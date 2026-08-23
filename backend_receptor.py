import os
import json
import time
import uuid
import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from typing import List, Dict, Any, Optional
import threading
import re
from collections import defaultdict
import paho.mqtt.client as mqtt

app = FastAPI(title="CANalyzer Pro Backend - Híbrido (Streaming & EDR)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = os.getenv("DATABASE_URL")

SYSTEM_STATE = {
    "last_heartbeat_time": 0.0,
    "user_is_monitoring": False,
    "timeout_seconds": 30.0,
    "monitoring_by_truck": {}
}

live_signals_db = {}
LIVE_DATA_TIMEOUT_SECONDS = 5.0
MAX_LIVE_FRAMES_PER_TRUCK = 2000
BLACKBOX_EVENTS_LIGHT_LIMIT = 100
PENDING_BLACKBOX_TTL_SECONDS = 900

# ============================================================================
# MQTT, TELEMETRIA LIVE E LEASE DO VISUALIZADOR
# ============================================================================
# MQTT live:
# - ESP32 publica telemetry e status.
# - Backend conserva somente o último snapshot confirmado.
# - Não há histórico MQTT, backlog ou replay.
#
# EDR:
# - Continua usando HTTP, chunks e PostgreSQL.
# - Não é alterada por este bloco.
# ============================================================================
MQTT_HOST = os.getenv("MQTT_HOST", "")
MQTT_PORT = int(
    os.getenv("MQTT_PORT", "8883")
)
MQTT_USERNAME = os.getenv(
    "MQTT_USERNAME",
    ""
)
MQTT_PASSWORD = os.getenv(
    "MQTT_PASSWORD",
    ""
)
MQTT_CLIENT_ID = os.getenv(
    "MQTT_CLIENT_ID",
    "backend-nic"
)
MQTT_TLS_ENABLED = (
    os.getenv(
        "MQTT_TLS_ENABLED",
        "true"
    )
    .strip()
    .lower()
    in {"1", "true", "yes", "on"}
)
MQTT_COMMAND_QOS = 1
MQTT_TELEMETRY_QOS = 0
LIVE_VIEWER_LEASE_SECONDS = 10.0

mqtt_client = None
mqtt_connected = False
mqtt_lock = threading.Lock()
live_state_lock = threading.Lock()

"""
viewer_leases:
{
    "viewer_<uuid>": {
        "truck_id": "Volvo FH540 (Sniffer 01)",
        "created_at": 0.0,
        "last_heartbeat_at": 0.0,
        "expires_at": 0.0
    }
}
"""
viewer_leases = {}


class HeartbeatTruckResponse(BaseModel):
    status: str
    user_is_monitoring: bool
    truck_id: str
    live_viewer_active: bool = False
    live_viewer_count: int = 0


class BlackboxMetadata(BaseModel):
    truck_id: str
    trigger_event: str
    lat: float
    lon: float
    timestamp: str


class BlackboxUpload(BaseModel):
    metadata: BlackboxMetadata
    log: List[Dict[str, Any]]
    log_format: Optional[str] = "raw_can"


class CanFrame(BaseModel):
    t: int
    id: int
    dlc: int
    d: List[int]
    extd: Optional[bool] = True

    @field_validator("dlc")
    @classmethod
    def validate_dlc(cls, v):
        if v < 0:
            return 0
        if v > 8:
            return 8
        return v

    @field_validator("d")
    @classmethod
    def validate_data(cls, v):
        if not isinstance(v, list):
            return []
        return [int(b) & 0xFF for b in v[:8]]


class LiveSignalsPayload(BaseModel):
    truck_id: str
    frames: List[CanFrame]
    lat: float | None = None
    lon: float | None = None
    snapshot_device_ms: Optional[int] = None
    snapshot_unix_ms: Optional[int] = None


class TruckRegisterPayload(BaseModel):
    truck_id: str
    lat: float | None = None
    lon: float | None = None
    mode: str | None = "sentinel"
    priority_mode: Optional[bool] = False
    pending_blackbox_upload: Optional[bool] = False
    blackbox_locked_until_upload: Optional[bool] = False
    last_error: Optional[str] = ""
    chunk_status: Optional[str] = "idle"


class TruckStatePayload(BaseModel):
    state: str

class LiveViewerOpenPayload(BaseModel):
    truck_id: str

class LiveViewerHeartbeatPayload(BaseModel):
    truck_id: str
    viewer_id: str


class BlackboxChunkUpload(BaseModel):
    upload_id: str
    chunk_index: int
    chunk_total: int
    metadata: BlackboxMetadata
    frames: List[CanFrame]
    log_format: Optional[str] = "raw_can"


DTC_DICT = {
    "140_2": {"caption": "Engine Oil Pressure", "ftb": "Data Erratic, Intermittent Or Incorrect"},
    "190_0": {"caption": "Engine Speed", "ftb": "Data Valid But Above Normal Operational Range"},
    "110_0": {"caption": "Engine Coolant Temperature", "ftb": "Data Valid But Above Normal Range"},
    "94_1": {"caption": "Engine Fuel Delivery Pressure", "ftb": "Data Valid But Below Normal Range"},
    "84_9": {"caption": "Wheel-Based Vehicle Speed", "ftb": "Abnormal Update Rate"},
    "108_3": {"caption": "Barometric Pressure", "ftb": "Voltage Above Normal"},
    "158_4": {"caption": "Battery Potential / Power Input 1", "ftb": "Voltage Below Normal"}
}

J1939_NODE_NAMES = {
    0x00: "Engine #1 (EMS)",
    0x01: "Engine #2",
    0x03: "Transmission (TECU)",
    0x05: "Shift Console",
    0x0B: "Brakes (EBS/ABS)",
    0x0F: "Retarder",
    0x11: "Cruise Control / Vehicle Management",
    0x17: "Instrument Cluster",
    0x19: "Climate Control",
    0x21: "Body Controller / VMCU",
    0x2B: "Brakes #2",
    0x31: "Cab Controller",
    0x33: "Driver Assistance (DACU)",
    0xE8: "FMS Standard",
    0xEE: "Tachograph",
    0xF9: "Body Builder",
    0xFF: "Global"
}


def get_db_connection():
    if not DATABASE_URL:
        raise HTTPException(status_code=500, detail="DATABASE_URL não configurada.")
    return psycopg2.connect(DATABASE_URL)


def ensure_support_tables():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blackbox_logs (
            id SERIAL PRIMARY KEY,
            payload JSONB NOT NULL,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pending_blackbox_chunks (
            upload_id TEXT PRIMARY KEY,
            payload JSONB NOT NULL,
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        )
    """)
    conn.commit()
    cursor.close()
    conn.close()

ensure_support_tables()

@app.on_event("startup")
def on_backend_startup():
    start_mqtt_client()
    watchdog_thread = threading.Thread(
        target=viewer_lease_watchdog,
        daemon=True,
        name="ViewerLeaseWatchdog"
    )
    watchdog_thread.start()

@app.on_event("shutdown")
def on_backend_shutdown():
    global mqtt_connected
    mqtt_connected = False
    if mqtt_client is not None:
        try:
            mqtt_client.loop_stop()
            mqtt_client.disconnect()
        except Exception:
            pass


def sanitize_frame_dict(frame: Dict[str, Any]) -> Dict[str, Any]:
    dlc = int(frame.get("dlc", 0) or 0)
    dlc = max(0, min(dlc, 8))

    data = frame.get("d", []) or []
    if not isinstance(data, list):
        data = []

    data = [int(x) & 0xFF for x in data[:8]]
    if len(data) > dlc:
        data = data[:dlc]

    return {
        "t": int(frame.get("t", 0) or 0),
        "id": int(frame.get("id", 0) or 0),
        "dlc": dlc,
        "d": data,
        "extd": bool(frame.get("extd", True))
    }


def ensure_truck_state(truck_id: str):
    if truck_id not in SYSTEM_STATE["monitoring_by_truck"]:
        SYSTEM_STATE["monitoring_by_truck"][truck_id] = {
            "last_heartbeat_time": 0.0,
            "user_is_monitoring": False,
            "timeout_seconds": 30.0,
            "desired_state": "sentinel"
        }
    elif "desired_state" not in SYSTEM_STATE["monitoring_by_truck"][truck_id]:
        SYSTEM_STATE["monitoring_by_truck"][truck_id]["desired_state"] = "sentinel"
    return SYSTEM_STATE["monitoring_by_truck"][truck_id]


def ensure_live_bucket(truck_id: str):
    if truck_id not in live_signals_db:
        live_signals_db[truck_id] = {
            "frames": [],
            "__meta__": {},
            "__stream__": {
                "snapshot_seq": 0,
                "last_server_time": 0.0,

                # Timestamp exclusivo para confirmar que o backend
                # recebeu um snapshot CAN em POST /signals.
                "last_snapshot_received_at": 0.0,

                "snapshot_device_ms": None,
                "snapshot_unix_ms": None
            }
        }
    else:
        if "__stream__" not in live_signals_db[truck_id]:
            live_signals_db[truck_id]["__stream__"] = {
                "snapshot_seq": 0,
                "last_server_time": 0.0,
                "last_snapshot_received_at": 0.0,
                "snapshot_device_ms": None,
                "snapshot_unix_ms": None
            }

        if "__meta__" not in live_signals_db[truck_id]:
            live_signals_db[truck_id]["__meta__"] = {}

        if "frames" not in live_signals_db[truck_id]:
            live_signals_db[truck_id]["frames"] = []

        # Compatibilidade com buckets criados antes deste patch.
        # Evita KeyError enquanto o backend estiver em execução.
        if (
            "last_snapshot_received_at"
            not in live_signals_db[truck_id]["__stream__"]
        ):
            live_signals_db[truck_id]["__stream__"][
                "last_snapshot_received_at"
            ] = 0.0

    return live_signals_db[truck_id]

def mqtt_safe_truck_id(truck_id: str) -> str:
    """
    Converte o identificador de exibição do caminhão para um segmento
    seguro de tópico MQTT.
    Exemplo:
    Volvo FH540 (Sniffer 01)
    ->
    volvo_fh540_sniffer_01
    """
    normalized = str(truck_id or "").strip().lower()
    normalized = re.sub(
        r"[^a-z0-9]+",
        "_",
        normalized
    )
    return normalized.strip("_") or "unknown_truck"

def mqtt_topic_for(
    truck_id: str,
    channel: str
) -> str:
    return (
        "canalyzer/v1/trucks/"
        f"{mqtt_safe_truck_id(truck_id)}"
        f"/{channel}"
    )

def get_active_viewer_count(
    truck_id: str
) -> int:
    now = time.time()
    return sum(
        1
        for lease in viewer_leases.values()
        if (
            lease.get("truck_id") == truck_id
            and float(
                lease.get("expires_at", 0.0)
            ) > now
        )
    )

def get_effective_mode_for_truck(
    truck_id: str
) -> str:
    """
    ONLINE exige simultaneamente:
    - intenção online do backend;
    - ao menos um navegador com lease válido.
    Sem visualizador ativo, o modo seguro é SENTINEL.
    """
    truck_state = ensure_truck_state(truck_id)
    desired_state = truck_state.get(
        "desired_state",
        "sentinel"
    )

    active_viewers = get_active_viewer_count(
        truck_id
    )

    if (
        desired_state == "online"
        and active_viewers > 0
    ):
        return "online"

    return "sentinel"

def publish_mqtt_mode_command(
    truck_id: str,
    mode: str,
    reason: str
) -> bool:
    """
    Publica comando para o sniffer.
    ONLINE:
    - QoS 1;
    - não retained;
    - lease de curta duração;
    - heartbeat do navegador renova a autorização.
    SENTINEL:
    - QoS 1;
    - retained;
    - estado seguro caso o sniffer reconecte ao broker.
    """
    global mqtt_connected

    if (
        mqtt_client is None
        or not mqtt_connected
    ):
        print(
            "[MQTT] Não conectado. "
            f"Comando não publicado: {mode}"
        )
        return False

    normalized_mode = (
        "online"
        if mode == "online"
        else "sentinel"
    )

    if normalized_mode == "online":
        lease_duration_ms = int(
            LIVE_VIEWER_LEASE_SECONDS * 1000
        )
        retain = False
    else:
        lease_duration_ms = 0
        retain = True

    payload = {
        "mode": normalized_mode,
        "lease_duration_ms": lease_duration_ms,
        "reason": reason,
        "issued_at_ms": int(time.time() * 1000)
    }

    topic = mqtt_topic_for(
        truck_id,
        "command/mode"
    )

    try:
        with mqtt_lock:
            publish_info = mqtt_client.publish(
                topic,
                json.dumps(payload),
                qos=MQTT_COMMAND_QOS,
                retain=retain
            )
        published = (
            publish_info.rc
            == mqtt.MQTT_ERR_SUCCESS
        )

        if published:
            print(
                "[MQTT] Comando publicado "
                f"| truck={truck_id} "
                f"| mode={normalized_mode} "
                f"| reason={reason}"
            )
        else:
            print(
                "[MQTT] Falha ao publicar comando "
                f"| rc={publish_info.rc}"
            )

        return published
    except Exception as error:
        print(
            f"[MQTT] Erro publish command: {error}"
        )
        return False

def publish_effective_mode_for_truck(
    truck_id: str,
    reason: str
) -> str:
    """
    Avalia lease e intenção online, depois envia o comando efetivo.
    """
    mode = get_effective_mode_for_truck(truck_id)

    publish_mqtt_mode_command(
        truck_id,
        mode,
        reason
    )

    return mode

def cleanup_expired_viewer_leases():
    """
    Remove leases expirados e manda SENTINEL para unidades que deixaram
    de ter visualizadores ativos.
    """
    now = time.time()
    expired_viewers = [
        viewer_id
        for viewer_id, lease in viewer_leases.items()
        if float(
            lease.get("expires_at", 0.0)
        ) <= now
    ]

    affected_trucks = set()
    for viewer_id in expired_viewers:
        lease = viewer_leases.pop(
            viewer_id,
            None
        )
        if lease:
            affected_trucks.add(
                lease.get("truck_id")
            )
    print(
    "[LEASE] Lease expirado "
    f"| truck={truck_id} "
    f"| viewer={viewer_id}"
    )
    for truck_id in affected_trucks:
        if truck_id:
            mode = get_effective_mode_for_truck(
                truck_id
            )
            if mode == "sentinel":
                publish_mqtt_mode_command(
                    truck_id,
                    "sentinel",
                    "viewer_lease_expired"
                )

def update_live_snapshot_from_mqtt(
    payload: dict
):
    """
    Atualiza o último snapshot completo da unidade.
    Não acumula snapshots.
    Não cria histórico.
    Não interfere com EDR.
    """
    if not isinstance(payload, dict):
        return

    truck_id = str(
        payload.get("truck_id") or ""
    ).strip()

    if not truck_id:
        print(
            "[MQTT] Telemetria ignorada: truck_id ausente."
        )
        return

    raw_frames = payload.get(
        "frames",
        []
    )

    if not isinstance(raw_frames, list):
        raw_frames = []

    sanitized_frames = [
        sanitize_frame_dict(frame)
        for frame in raw_frames
        if isinstance(frame, dict)
    ]

    with live_state_lock:
        truck_bucket = ensure_live_bucket(
            truck_id
        )

        now = time.time()

        """
        O novo snapshot MQTT substitui integralmente o anterior.
        Isso é intencional:
        telemetria live mostra estado atual, não replay histórico.
        """
        truck_bucket["frames"] = sanitized_frames

        truck_bucket["__stream__"][
            "snapshot_seq"
        ] += 1

        truck_bucket["__stream__"][
            "last_server_time"
        ] = now

        truck_bucket["__stream__"][
            "last_snapshot_received_at"
        ] = now

        truck_bucket["__stream__"][
            "snapshot_device_ms"
        ] = payload.get(
            "snapshot_device_ms"
        )

        truck_bucket["__stream__"][
            "snapshot_unix_ms"
        ] = payload.get(
            "snapshot_unix_ms"
        )

        current_meta = truck_bucket.get(
            "__meta__",
            {}
        )

        truck_bucket["__meta__"] = {
            "truck_id": truck_id,
            "lat": payload.get(
                "lat",
                current_meta.get(
                    "lat",
                    -25.4284
                )
            ),
            "lon": payload.get(
                "lon",
                current_meta.get(
                    "lon",
                    -49.2731
                )
            ),
            "updated_at": now,
            "mode": "online",
            "priority_mode": current_meta.get(
                "priority_mode",
                False
            ),
            "pending_blackbox_upload": current_meta.get(
                "pending_blackbox_upload",
                False
            ),
            "blackbox_locked_until_upload": current_meta.get(
                "blackbox_locked_until_upload",
                False
            ),
            "last_error": current_meta.get(
                "last_error",
                ""
            ),
            "chunk_status": current_meta.get(
                "chunk_status",
                "idle"
            )
        }

def update_truck_status_from_mqtt(
    payload: dict
):
    """
    Atualiza os metadados de status exibidos pela lista de unidades.
    """
    if not isinstance(payload, dict):
        return

    truck_id = str(
        payload.get("truck_id") or ""
    ).strip()

    if not truck_id:
        return

    with live_state_lock:
        truck_bucket = ensure_live_bucket(
            truck_id
        )

        current_meta = truck_bucket.get(
            "__meta__",
            {}
        )

        truck_bucket["__meta__"] = {
            "truck_id": truck_id,
            "lat": payload.get(
                "lat",
                current_meta.get(
                    "lat",
                    -25.4284
                )
            ),
            "lon": payload.get(
                "lon",
                current_meta.get(
                    "lon",
                    -49.2731
                )
            ),
            "updated_at": time.time(),
            "mode": payload.get(
                "mode",
                current_meta.get(
                    "mode",
                    "sentinel"
                )
            ),
            "priority_mode": bool(
                payload.get(
                    "priority_mode",
                    False
                )
            ),
            "pending_blackbox_upload": bool(
                payload.get(
                    "pending_blackbox_upload",
                    False
                )
            ),
            "blackbox_locked_until_upload": bool(
                payload.get(
                    "blackbox_locked_until_upload",
                    False
                )
            ),
            "last_error": str(
                payload.get(
                    "last_error",
                    ""
                )
            ),
            "chunk_status": str(
                payload.get(
                    "chunk_status",
                    "idle"
                )
            )
        }

def mqtt_on_connect(
    client,
    userdata,
    flags,
    reason_code,
    properties=None
):
    global mqtt_connected

    mqtt_connected = (
        reason_code == 0
    )

    if not mqtt_connected:
        print(
            "[MQTT] Conexão recusada "
            f"| reason={reason_code}"
        )
        return

    client.subscribe(
        "canalyzer/v1/trucks/+/telemetry",
        qos=MQTT_TELEMETRY_QOS
    )

    client.subscribe(
        "canalyzer/v1/trucks/+/status",
        qos=MQTT_COMMAND_QOS
    )

    print(
        "[MQTT] Backend conectado e inscrito "
        "em telemetry/status."
    )

def mqtt_on_disconnect(
    client,
    userdata,
    disconnect_flags,
    reason_code,
    properties=None
):
    global mqtt_connected
    mqtt_connected = False
    print(
        "[MQTT] Backend desconectado "
        f"| reason={reason_code}"
    )

def mqtt_on_message(
    client,
    userdata,
    message
):
    try:
        payload = json.loads(
            message.payload.decode("utf-8")
        )
    except Exception:
        print(
            "[MQTT] JSON inválido recebido."
        )
        return

    topic = str(message.topic or "")

    if topic.endswith("/telemetry"):
        update_live_snapshot_from_mqtt(
            payload
        )
        return

    if topic.endswith("/status"):
        update_truck_status_from_mqtt(
            payload
        )

def start_mqtt_client():
    """
    Inicializa cliente MQTT do backend.
    Necessita:
    MQTT_HOST
    MQTT_PORT
    MQTT_USERNAME
    MQTT_PASSWORD
    MQTT_CLIENT_ID
    MQTT_TLS_ENABLED
    """
    global mqtt_client
    global mqtt_connected

    if not MQTT_HOST:
        print(
            "[MQTT] MQTT_HOST não configurado. "
            "MQTT desabilitado."
        )
        return

    try:
        mqtt_client = mqtt.Client(
            callback_api_version=(
                mqtt.CallbackAPIVersion.VERSION2
            ),
            client_id=MQTT_CLIENT_ID,
            protocol=mqtt.MQTTv311
        )

        if MQTT_USERNAME:
            mqtt_client.username_pw_set(
                MQTT_USERNAME,
                MQTT_PASSWORD
            )

        if MQTT_TLS_ENABLED:
            mqtt_client.tls_set()

        mqtt_client.on_connect = mqtt_on_connect
        mqtt_client.on_disconnect = mqtt_on_disconnect
        mqtt_client.on_message = mqtt_on_message

        mqtt_client.reconnect_delay_set(
            min_delay=1,
            max_delay=15
        )

        mqtt_client.connect_async(
            MQTT_HOST,
            MQTT_PORT,
            keepalive=15
        )

        mqtt_client.loop_start()
        mqtt_connected = True

        print(
            "[MQTT] Cliente backend iniciado "
            f"| host={MQTT_HOST}"
            f"| port={MQTT_PORT}"
            f"| client_id={MQTT_CLIENT_ID}"
        )

    except Exception as error:
        mqtt_connected = False
        print(
            f"[MQTT] Falha ao iniciar: {error}"
        )

def viewer_lease_watchdog():
    while True:
        try:
            cleanup_expired_viewer_leases()
        except Exception as error:
            print(
                f"[LEASE] Erro watchdog: {error}"
            )
        time.sleep(1)


def cleanup_stale_pending_blackbox_chunks():
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT upload_id, payload, created_at
        FROM pending_blackbox_chunks
    """)
    rows = cursor.fetchall()

    now = time.time()
    removed = []

    for row in rows:
        created_at = row["created_at"].timestamp() if row["created_at"] else 0.0
        if (now - created_at) > PENDING_BLACKBOX_TTL_SECONDS:
            payload = row["payload"] or {}
            removed.append({
                "upload_id": row["upload_id"],
                "age_seconds": round(now - created_at, 2),
                "received_chunks": len((payload.get("received", {}) or {})),
                "chunk_total": payload.get("chunk_total", 0),
                "truck_id": ((payload.get("metadata", {}) or {}).get("truck_id", "unknown"))
            })
            cursor.execute("DELETE FROM pending_blackbox_chunks WHERE upload_id = %s", (row["upload_id"],))

    conn.commit()
    cursor.close()
    conn.close()
    return removed


def get_pending_blackbox_summary():
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("""
        SELECT upload_id, payload, created_at
        FROM pending_blackbox_chunks
        ORDER BY updated_at DESC
    """)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    now = time.time()
    summary = []

    for row in rows:
        payload = row["payload"] or {}
        created_at = row["created_at"].timestamp() if row["created_at"] else 0.0
        summary.append({
            "upload_id": row["upload_id"],
            "age_seconds": round(now - created_at, 2),
            "received_chunks": len((payload.get("received", {}) or {})),
            "chunk_total": payload.get("chunk_total", 0),
            "truck_id": ((payload.get("metadata", {}) or {}).get("truck_id", "unknown"))
        })

    summary.sort(key=lambda x: x["age_seconds"], reverse=True)
    return summary


def load_pending_chunk_bucket(upload_id: str):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute(
        "SELECT payload FROM pending_blackbox_chunks WHERE upload_id = %s LIMIT 1",
        (upload_id,)
    )
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    return row["payload"] if row else None


def save_pending_chunk_bucket(upload_id: str, bucket: dict):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO pending_blackbox_chunks (upload_id, payload, created_at, updated_at)
        VALUES (%s, %s, NOW(), NOW())
        ON CONFLICT (upload_id)
        DO UPDATE SET payload = EXCLUDED.payload, updated_at = NOW()
    """, (upload_id, json.dumps(bucket)))
    conn.commit()
    cursor.close()
    conn.close()


def delete_pending_chunk_bucket(upload_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM pending_blackbox_chunks WHERE upload_id = %s", (upload_id,))
    conn.commit()
    cursor.close()
    conn.close()


def get_dtc_text(spn, fmi):
    key = f"{spn}_{fmi}"
    return DTC_DICT.get(key, {
        "caption": f"SPN Não Catalogada ({spn})",
        "ftb": f"FMI Genérico ({fmi})"
    })

def extract_blackbox_fault_context(raw_log):
    """
    Extrai as falhas DM1 presentes no raw_log de uma caixa-preta.

    O resultado é usado pelo endpoint leve de eventos para que o
    frontend consiga filtrar por ECU/Source Address, SPN e FMI sem
    baixar o log completo do evento.

    Cada falha é identificada por:

        Source Address + SPN + FMI

    A ordem de retorno respeita a primeira ocorrência de cada DTC no
    log da caixa-preta.
    """
    if not isinstance(raw_log, list):
        return []

    faults = []
    seen_faults = set()

    source_address_groups = {
        0x00: {
            "group": "Motor (EMS)",
            "ecu": "EMS",
            "ecu_name": "Engine #1 (EMS)"
        },
        0x0B: {
            "group": "Freio (EBS)",
            "ecu": "EBS",
            "ecu_name": "Brakes (EBS/ABS)"
        },
        0x03: {
            "group": "Transmissão (TECU)",
            "ecu": "TECU",
            "ecu_name": "Transmission (TECU)"
        }
    }

    for raw_frame in raw_log:
        if not isinstance(raw_frame, dict):
            continue

        frame = sanitize_frame_dict(raw_frame)

        if not frame.get("extd", True):
            continue

        can_id = int(frame.get("id", 0) or 0)

        try:
            j1939_meta = decode_j1939_id(can_id)
        except Exception:
            continue

        if j1939_meta.get("pgn") != 65226:
            continue

        data = frame.get("d", []) or []

        if len(data) < 6:
            continue

        lamp_byte = data[0]
        flash_lamp_byte = data[1]

        source_address = int(
            j1939_meta.get("sa", 0)
        )

        source_info = source_address_groups.get(
            source_address,
            {
                "group": "Outros",
                "ecu": f"SA 0x{source_address:02X}",
                "ecu_name": J1939_NODE_NAMES.get(
                    source_address,
                    f"ECU desconhecida (SA 0x{source_address:02X})"
                )
            }
        )

        """
        Uma DTC DM1 começa no byte 2 e ocupa 4 bytes:

        byte 2: SPN bits 0..7
        byte 3: SPN bits 8..15
        byte 4: SPN bits 16..18 e FMI bits 0..4
        byte 5: OC bits 0..6 e CM bit 7

        CAN clássico possui normalmente uma DTC por frame. O loop
        também suporta payloads reagrupados com múltiplas DTCs.
        """
        for offset in range(2, len(data) - 3, 4):
            byte_0 = data[offset]
            byte_1 = data[offset + 1]
            byte_2 = data[offset + 2]
            byte_3 = data[offset + 3]

            if (
                byte_0 == 0xFF
                and byte_1 == 0xFF
                and byte_2 == 0xFF
                and byte_3 == 0xFF
            ):
                continue

            spn = (
                byte_0
                | (byte_1 << 8)
                | ((byte_2 & 0x07) << 16)
            )

            fmi = (byte_2 >> 3) & 0x1F
            occurrence_count = byte_3 & 0x7F
            conversion_method = (byte_3 >> 7) & 0x01

            if spn == 0:
                continue

            fault_key = (
                source_address,
                spn,
                fmi
            )

            if fault_key in seen_faults:
                continue

            seen_faults.add(fault_key)

            dtc_text = get_dtc_text(spn, fmi)

            faults.append({
                "sa": source_address,
                "sa_hex": f"0x{source_address:02X}",
                "ecu": source_info["ecu"],
                "ecu_name": source_info["ecu_name"],
                "group": source_info["group"],

                "spn": spn,
                "fmi": fmi,
                "oc": occurrence_count,
                "cm": conversion_method,

                "caption": dtc_text.get(
                    "caption",
                    f"SPN Não Catalogada ({spn})"
                ),
                "ftb": dtc_text.get(
                    "ftb",
                    f"FMI Genérico ({fmi})"
                ),

                "mil": lamp_byte & 0x03,
                "red_stop": (lamp_byte >> 2) & 0x03,
                "amber_warning": (lamp_byte >> 4) & 0x03,
                "protect": (lamp_byte >> 6) & 0x03,

                "flash_mil": flash_lamp_byte & 0x03,
                "flash_red_stop": (
                    flash_lamp_byte >> 2
                ) & 0x03,
                "flash_amber_warning": (
                    flash_lamp_byte >> 4
                ) & 0x03,
                "flash_protect": (
                    flash_lamp_byte >> 6
                ) & 0x03
            })

    return faults

def normalize_can_id(raw_id):
    if isinstance(raw_id, int):
        return f"0x{raw_id:X}"
    if isinstance(raw_id, str):
        s = raw_id.strip()
        if s.lower().startswith("0x"):
            return "0x" + s[2:].upper()
        try:
            return f"0x{int(s):X}"
        except Exception:
            return s
    return "0x0"


def payload_to_hex(data_bytes, dlc=None):
    if not isinstance(data_bytes, list):
        return ""
    payload = [int(b) & 0xFF for b in data_bytes[:8]]
    if dlc is not None:
        dlc = max(0, min(int(dlc), 8))
        payload = payload[:dlc]
    return " ".join(f"{b:02X}" for b in payload)


def to_time_label_from_seconds(seconds_float):
    total_ms = int(round(max(seconds_float, 0) * 1000))
    hh = total_ms // 3600000
    rem = total_ms % 3600000
    mm = rem // 60000
    rem = rem % 60000
    ss = rem // 1000
    ms = rem % 1000
    return f"{hh:02d}:{mm:02d}:{ss:02d}.{ms:03d}"


def decode_j1939_id(raw_id):
    id_int = int(raw_id)
    priority = (id_int >> 26) & 0x7
    dp = (id_int >> 24) & 0x1
    pf = (id_int >> 16) & 0xFF
    ps = (id_int >> 8) & 0xFF
    sa = id_int & 0xFF

    is_pdu1 = pf < 240
    is_pdu2 = pf >= 240

    if is_pdu1:
        da = ps
        pgn = (dp << 16) | (pf << 8)
    else:
        da = None
        pgn = (dp << 16) | (pf << 8) | ps

    return {
        "priority": priority,
        "dp": dp,
        "pf": pf,
        "ps": ps,
        "sa": sa,
        "da": da,
        "pgn": pgn,
        "is_pdu1": is_pdu1,
        "is_pdu2": is_pdu2
    }


def format_sender(sa):
    return J1939_NODE_NAMES.get(sa, f"SA 0x{sa:02X}")


def format_receiver(meta):
    if meta["is_pdu1"] and meta["da"] is not None:
        return J1939_NODE_NAMES.get(meta["da"], f"DA 0x{meta['da']:02X}")
    return "Broadcast"


def le_u16(data, start):
    if len(data) <= start + 1:
        return None
    return data[start] | (data[start + 1] << 8)


def decode_eec1(payload_bytes):
    sigs = {}
    parts = []

    eng_raw = le_u16(payload_bytes, 3)
    if eng_raw is not None and eng_raw != 0xFFFF:
        eng_speed = eng_raw * 0.125
        sigs["EngineSpeed"] = eng_speed
        parts.append(f"EngineSpeed={eng_speed:.2f} rpm")

    if len(payload_bytes) > 0 and payload_bytes[0] != 0xFF:
        driver_demand = payload_bytes[0] - 125
        sigs["DriverDemand"] = driver_demand
        parts.append(f"DriverDemand={driver_demand:.2f} %")

    if len(payload_bytes) > 1 and payload_bytes[1] != 0xFF:
        actual_torque = payload_bytes[1] - 125
        sigs["ActualTorque"] = actual_torque
        parts.append(f"ActualTorque={actual_torque:.2f} %")

    return {"message": "EEC1", "decoded": " | ".join(parts) if parts else "Raw Data", "sigs": sigs}


def decode_eec2(payload_bytes):
    sigs = {}
    parts = []

    if len(payload_bytes) > 1 and payload_bytes[1] != 0xFF:
        accel = payload_bytes[1] * 0.4
        sigs["AccelPedal1"] = accel
        parts.append(f"AccelPedal1={accel:.2f} %")

    return {"message": "EEC2", "decoded": " | ".join(parts) if parts else "Raw Data", "sigs": sigs}


def decode_ccvs1(payload_bytes):
    sigs = {}
    parts = []

    spd_raw = le_u16(payload_bytes, 1)
    if spd_raw is not None and spd_raw != 0xFFFF:
        spd = spd_raw / 256.0
        sigs["VehicleSpeed"] = spd
        parts.append(f"VehicleSpeed={spd:.2f} km/h")

    if len(payload_bytes) > 0 and payload_bytes[0] != 0xFF:
        parking_brake = 1 if (payload_bytes[0] & 0x10) else 0
        sigs["ParkingBrake"] = parking_brake
        parts.append(f"ParkingBrake={'On' if parking_brake else 'Off'}")

    return {"message": "CCVS1", "decoded": " | ".join(parts) if parts else "Raw Data", "sigs": sigs}


def decode_ic1(payload_bytes):
    sigs = {}
    parts = []

    if len(payload_bytes) > 1 and payload_bytes[1] != 0xFF:
        boost = payload_bytes[1] * 0.01
        sigs["BoostPressure"] = boost
        parts.append(f"BoostPressure={boost:.2f} bar")

    return {"message": "IC1", "decoded": " | ".join(parts) if parts else "Raw Data", "sigs": sigs}


def decode_et1(payload_bytes):
    sigs = {}
    parts = []

    if len(payload_bytes) > 0 and payload_bytes[0] != 0xFF:
        coolant = payload_bytes[0] - 40
        sigs["EngineCoolantTemp"] = coolant
        parts.append(f"EngineCoolantTemp={coolant:.2f} °C")

    return {"message": "ET1", "decoded": " | ".join(parts) if parts else "Raw Data", "sigs": sigs}


def decode_lfe1(payload_bytes):
    sigs = {}
    parts = []

    fuel_raw = le_u16(payload_bytes, 0)
    if fuel_raw is not None and fuel_raw != 0xFFFF:
        fuel_rate = fuel_raw * 0.05
        sigs["FuelRate"] = fuel_rate
        parts.append(f"FuelRate={fuel_rate:.2f} L/h")

    eco_raw = le_u16(payload_bytes, 2)
    if eco_raw is not None and eco_raw != 0xFFFF:
        fuel_eco = eco_raw * 0.001953125
        sigs["FuelEconomy"] = fuel_eco
        parts.append(f"FuelEconomy={fuel_eco:.2f} km/L")

    return {"message": "LFE1", "decoded": " | ".join(parts) if parts else "Raw Data", "sigs": sigs}


def decode_vdhr(payload_bytes):
    sigs = {}
    parts = []

    if len(payload_bytes) > 3 and not all(v == 0xFF for v in payload_bytes[:4]):
        raw = payload_bytes[0] + (payload_bytes[1] << 8) + (payload_bytes[2] << 16) + (payload_bytes[3] << 24)
        meters = raw * 5.0
        sigs["Odometer_m"] = meters
        parts.append(f"Odometer={meters:.0f} m")

    return {"message": "VDHR", "decoded": " | ".join(parts) if parts else "Raw Data", "sigs": sigs}


def decode_dm1(payload_bytes):
    if len(payload_bytes) < 6:
        return {
            "message": "DM1",
            "decoded": "Diagnostic Message 1, payload incompleto",
            "sigs": {},
            "dtc": None
        }

    lamp_byte = payload_bytes[0]
    flash_lamp_byte = payload_bytes[1]

    dtc_byte_0 = payload_bytes[2]
    dtc_byte_1 = payload_bytes[3]
    dtc_byte_2 = payload_bytes[4]
    dtc_byte_3 = payload_bytes[5]

    # FF FF FF FF representa ausência de DTC ativa.
    if (
        dtc_byte_0 == 0xFF
        and dtc_byte_1 == 0xFF
        and dtc_byte_2 == 0xFF
        and dtc_byte_3 == 0xFF
    ):
        return {
            "message": "DM1",
            "decoded": "No Active DTCs",
            "sigs": {
                "ActiveDTCCount": 0,
                "DM1_MIL": lamp_byte & 0x03,
                "DM1_RedStopLamp": (lamp_byte >> 2) & 0x03,
                "DM1_AmberWarningLamp": (
                    lamp_byte >> 4
                ) & 0x03,
                "DM1_ProtectLamp": (lamp_byte >> 6) & 0x03,
                "DM1_FlashMIL": flash_lamp_byte & 0x03,
                "DM1_FlashRedStopLamp": (
                    flash_lamp_byte >> 2
                ) & 0x03,
                "DM1_FlashAmberWarningLamp": (
                    flash_lamp_byte >> 4
                ) & 0x03,
                "DM1_FlashProtectLamp": (
                    flash_lamp_byte >> 6
                ) & 0x03
            },
            "dtc": None
        }

    spn = (
        dtc_byte_0
        | (dtc_byte_1 << 8)
        | ((dtc_byte_2 & 0x07) << 16)
    )

    fmi = (dtc_byte_2 >> 3) & 0x1F
    oc = dtc_byte_3 & 0x7F
    cm = (dtc_byte_3 >> 7) & 0x01

    if spn == 0:
        return {
            "message": "DM1",
            "decoded": "No Active DTCs",
            "sigs": {
                "ActiveDTCCount": 0
            },
            "dtc": None
        }

    info = get_dtc_text(spn, fmi)

    return {
        "message": "DM1",
        "decoded": (
            "Active Diagnostic Trouble Codes"
            f" | SPN={spn}"
            f" | FMI={fmi}"
            f" | OC={oc}"
            f" | CM={cm}"
        ),
        "sigs": {
            "ActiveDTCCount": 1,
            "DM1_SPN": spn,
            "DM1_FMI": fmi,
            "DM1_OC": oc,
            "DM1_CM": cm,
            "DM1_MIL": lamp_byte & 0x03,
            "DM1_RedStopLamp": (lamp_byte >> 2) & 0x03,
            "DM1_AmberWarningLamp": (
                lamp_byte >> 4
            ) & 0x03,
            "DM1_ProtectLamp": (lamp_byte >> 6) & 0x03,
            "DM1_FlashMIL": flash_lamp_byte & 0x03,
            "DM1_FlashRedStopLamp": (
                flash_lamp_byte >> 2
            ) & 0x03,
            "DM1_FlashAmberWarningLamp": (
                flash_lamp_byte >> 4
            ) & 0x03,
            "DM1_FlashProtectLamp": (
                flash_lamp_byte >> 6
            ) & 0x03
        },
        "dtc": {
            "spn": spn,
            "fmi": fmi,
            "oc": oc,
            "cm": cm,
            "caption": info["caption"],
            "ftb": info["ftb"]
        }
    }


def parse_known_j1939(frame):
    frame = sanitize_frame_dict(frame)

    is_extended = frame.get("extd", True)
    if not is_extended:
        return {
            "id": normalize_can_id(frame.get("id")),
            "message": "Standard CAN Frame",
            "sender": "N/A",
            "receiver": "N/A",
            "dlc": frame.get("dlc", 0),
            "payload": payload_to_hex(frame.get("d", []) or [], frame.get("dlc", 0)),
            "decoded": "Unsupported non-J1939 standard frame",
            "sigs": {},
            "dtc": None,
            "is_j1939": False,
            "pgn": None,
            "sa": None,
            "da": None
        }

    can_id = frame.get("id")
    can_id_hex = normalize_can_id(can_id)
    payload_bytes = frame.get("d", []) or []
    dlc = frame.get("dlc", len(payload_bytes))
    payload_hex = payload_to_hex(payload_bytes, dlc)

    meta = decode_j1939_id(can_id)
    pgn = meta["pgn"]
    decoded = None

    if pgn == 61444:
        decoded = decode_eec1(payload_bytes)
    elif pgn == 61443:
        decoded = decode_eec2(payload_bytes)
    elif pgn == 65265:
        decoded = decode_ccvs1(payload_bytes)
    elif pgn == 65270:
        decoded = decode_ic1(payload_bytes)
    elif pgn == 65262:
        decoded = decode_et1(payload_bytes)
    elif pgn == 65266:
        decoded = decode_lfe1(payload_bytes)
    elif pgn == 65217:
        decoded = decode_vdhr(payload_bytes)
    elif pgn == 65226:
        decoded = decode_dm1(payload_bytes)

    if decoded:
        return {
            "id": can_id_hex,
            "message": decoded["message"],
            "sender": format_sender(meta["sa"]),
            "receiver": format_receiver(meta),
            "dlc": dlc,
            "payload": payload_hex,
            "decoded": decoded["decoded"],
            "sigs": decoded.get("sigs", {}),
            "dtc": decoded.get("dtc"),
            "is_j1939": True,
            "pgn": pgn,
            "sa": meta["sa"],
            "da": meta["da"]
        }

    return {
        "id": can_id_hex,
        "message": f"Unknown PGN {pgn}",
        "sender": format_sender(meta["sa"]),
        "receiver": format_receiver(meta),
        "dlc": dlc,
        "payload": payload_hex,
        "decoded": "Raw Data",
        "sigs": {},
        "dtc": None,
        "is_j1939": True,
        "pgn": pgn,
        "sa": meta["sa"],
        "da": meta["da"]
    }


def build_workspace_log(raw_log):
    """
    Constrói o log temporal usado pelo workspace/frontend.

    Estratégia:

    - gera um pacote lógico por segundo, 1 Hz;
    - mantém o último frame CAN real de cada CAN ID;
    - preenche cada snapshot com todos os CAN IDs conhecidos;
    - identifica frames retidos com is_held=True;
    - não repete uma DM1 retida, pois uma DTC antiga não pode continuar
      aparecendo como ativa depois que a ECU deixou de retransmiti-la.

    Compatibilidade:

    - Novo sniffer:
      todos os frames de um snapshot chegam com o mesmo timestamp.
      O backend apenas preserva e organiza esse snapshot.

    - Logs antigos:
      frames podem chegar com timestamps diferentes. O backend cria
      snapshots de 1 Hz usando o último valor CAN realmente recebido.
    """
    if not isinstance(raw_log, list) or not raw_log:
        return []

    sanitized_frames = []

    for raw_frame in raw_log:
        if not isinstance(raw_frame, dict):
            continue

        frame = sanitize_frame_dict(raw_frame)

        # O workspace atual considera somente J1939 estendido.
        if not frame.get("extd", True):
            continue

        sanitized_frames.append(frame)

    if not sanitized_frames:
        return []

    # Ordem temporal estável, inclusive para frames com mesmo timestamp.
    sanitized_frames.sort(
        key=lambda frame: int(frame.get("t", 0) or 0)
    )

    first_timestamp_ms = int(
        sanitized_frames[0].get("t", 0) or 0
    )

    last_timestamp_ms = int(
        sanitized_frames[-1].get("t", 0) or 0
    )

    """
    O último snapshot é arredondado para cima para garantir que frames
    recebidos, por exemplo, em 850 ms, sejam incluídos no snapshot de
    1.000 ms em vez de serem descartados.

    Exemplo:
        primeiro frame: 0 ms
        último frame:   850 ms

        snapshots gerados:
        - 0 ms
        - 1000 ms
    """
    duration_ms = max(
        0,
        last_timestamp_ms - first_timestamp_ms
    )

    final_snapshot_offset_ms = (
        ((duration_ms + 999) // 1000) * 1000
    )

    final_snapshot_timestamp_ms = (
        first_timestamp_ms
        + final_snapshot_offset_ms
    )

    """
    Cache persistente por CAN ID.

    Cada posição contém:
    - frame: último frame CAN real recebido;
    - source_timestamp_ms: timestamp original desse frame.
    """
    latest_frame_by_can_id = {}

    workspace_log = []
    next_frame_index = 0
    frame_count = len(sanitized_frames)

    snapshot_timestamp_ms = first_timestamp_ms

    while (
        snapshot_timestamp_ms
        <= final_snapshot_timestamp_ms
    ):
        """
        Incorpora todos os frames reais recebidos até o instante do
        snapshot atual.

        Se dois frames do mesmo CAN ID chegarem dentro do mesmo segundo,
        o último recebido é preservado, exatamente como acontece no
        cache do firmware.
        """
        while (
            next_frame_index < frame_count
            and int(
                sanitized_frames[next_frame_index].get(
                    "t",
                    0
                ) or 0
            ) <= snapshot_timestamp_ms
        ):
            incoming_frame = sanitized_frames[
                next_frame_index
            ]

            can_id = int(
                incoming_frame.get("id", 0) or 0
            )

            source_timestamp_ms = int(
                incoming_frame.get("t", 0) or 0
            )

            latest_frame_by_can_id[can_id] = {
                "frame": incoming_frame,
                "source_timestamp_ms": source_timestamp_ms
            }

            next_frame_index += 1

        frames_out = []
        signals_out = {}

        """
        Ordena por CAN ID para gerar um workspace determinístico.
        Isso facilita comparação, exportação e análise offline.
        """
        for can_id in sorted(
            latest_frame_by_can_id.keys()
        ):
            cached_item = latest_frame_by_can_id[can_id]

            cached_frame = cached_item["frame"]

            source_timestamp_ms = int(
                cached_item["source_timestamp_ms"]
            )

            is_held = (
                source_timestamp_ms
                < snapshot_timestamp_ms
            )

            parsed = parse_known_j1939(
                cached_frame
            )

            if not parsed.get("is_j1939", False):
                continue

            """
            Regra especial para DM1:

            Uma DM1 retida não pode ser repetida indefinidamente, pois
            isso manteria uma falha antiga visível como se a ECU ainda
            estivesse confirmando-a.

            A DM1 aparece somente no instante em que foi realmente
            recebida. Mensagens telemétricas normais permanecem retidas
            para preencher as curvas em 1 Hz.
            """
            if (
                parsed.get("message") == "DM1"
                and is_held
            ):
                continue

            frames_out.append({
                "id": parsed["id"],
                "message": parsed["message"],
                "sender": parsed["sender"],
                "receiver": parsed["receiver"],
                "dlc": parsed["dlc"],
                "payload": parsed["payload"],
                "decoded": parsed["decoded"],
                "pgn": parsed.get("pgn"),
                "sa": parsed.get("sa"),
                "da": parsed.get("da"),

                # Metadados úteis para auditoria e futura visualização.
                "is_held": is_held,
                "source_timestamp_ms": source_timestamp_ms
            })

            """
            Para telemetria regular, parsed.sigs contém valores reais
            extraídos do último frame CAN recebido.

            Se is_held=True, o valor é o último valor real conhecido,
            e não um valor interpolado ou estimado.
            """
            if parsed.get("sigs"):
                signals_out.update(
                    parsed["sigs"]
                )

        """
        Adiciona a linha temporal mesmo se nenhum frame estiver disponível.

        Em condições normais, haverá ao menos um frame depois do primeiro
        timestamp. O comportamento também preserva a cadência de 1 Hz
        caso o log tenha uma janela temporária sem dados.
        """
        relative_seconds = (
            snapshot_timestamp_ms
            - first_timestamp_ms
        ) / 1000.0

        workspace_log.append({
            "time": to_time_label_from_seconds(
                relative_seconds
            ),
            "rel": relative_seconds,
            "sigs": signals_out,
            "frames": frames_out,

            # Metadados do snapshot lógico.
            "snapshot_timestamp_ms": (
                snapshot_timestamp_ms
            ),
            "is_gap": len(frames_out) == 0
        })

        snapshot_timestamp_ms += 1000

    return workspace_log

def build_markers_from_workspace_log(workspace_log):
    markers = []
    seen_active_dtcs = set()

    for entry in workspace_log:
        time_label = entry.get("time", "00:00:00.000")
        frames = entry.get("frames", [])

        for frame in frames:
            if frame.get("message") != "DM1":
                continue

            decoded = frame.get("decoded", "")
            if "Active Diagnostic Trouble Codes" not in decoded:
                continue

            spn = None
            fmi = None

            parts = [p.strip() for p in decoded.split("|")]
            for part in parts:
                if part.startswith("SPN="):
                    try:
                        spn = int(part.replace("SPN=", "").strip())
                    except Exception:
                        pass
                elif part.startswith("FMI="):
                    try:
                        fmi = int(part.replace("FMI=", "").strip())
                    except Exception:
                        pass

            if spn is None or fmi is None:
                continue

            key = f"{spn}_{fmi}"
            info = get_dtc_text(spn, fmi)

            if key not in seen_active_dtcs:
                markers.append({
                    "time": time_label,
                    "comment": f"⚠️ FALHA: {info['caption']}"
                })
                seen_active_dtcs.add(key)
            else:
                markers.append({
                    "time": time_label,
                    "comment": f"⚠️ REINCIDÊNCIA: {info['caption']}"
                })

    return markers


def build_dtc_history_from_workspace_log(workspace_log):
    dtc_history = {}

    for entry in workspace_log:
        time_label = entry.get("time", "00:00:00.000")
        frames = entry.get("frames", [])
        active_in_this_cycle = set()
        dm1_seen = False

        for frame in frames:
            if frame.get("message") != "DM1":
                continue

            dm1_seen = True
            decoded = frame.get("decoded", "")

            if "No Active DTCs" in decoded:
                continue

            if "Active Diagnostic Trouble Codes" not in decoded:
                continue

            spn = None
            fmi = None
            oc = 0

            parts = [p.strip() for p in decoded.split("|")]
            for part in parts:
                if part.startswith("SPN="):
                    try:
                        spn = int(part.replace("SPN=", "").strip())
                    except Exception:
                        pass
                elif part.startswith("FMI="):
                    try:
                        fmi = int(part.replace("FMI=", "").strip())
                    except Exception:
                        pass
                elif part.startswith("OC="):
                    try:
                        oc = int(part.replace("OC=", "").strip())
                    except Exception:
                        pass

            if spn is None or fmi is None:
                continue

            key = f"{spn}_{fmi}"
            active_in_this_cycle.add(key)
            info = get_dtc_text(spn, fmi)

            dtc_history[key] = {
                "spn": spn,
                "fmi": fmi,
                "caption": info["caption"],
                "ftb": info["ftb"],
                "status": "Ativa",
                "oc": oc,
                "lastTime": time_label
            }

        if dm1_seen:
            for key in list(dtc_history.keys()):
                if key not in active_in_this_cycle:
                    dtc_history[key]["status"] = "Inativa"

    return dtc_history


def build_offline_package(log_id, metadata, raw_log, workspace_log):
    markers = build_markers_from_workspace_log(workspace_log)
    dtc_history = build_dtc_history_from_workspace_log(workspace_log)

    return {
        "version": "3.0",
        "timestamp": metadata.get("timestamp"),
        "source": "blackbox_esp32",
        "log_id": log_id,
        "metadata": metadata,
        "uiState": {
            "activeSignals": [],
            "selectedSignal": None,
            "configs": {},
            "showCursors": True,
            "cursorCount": 2,
            "markers": markers,
            "layout": "overlay",
            "smooth": True
        },
        "colFilters": {
            "id": {"type": "contains", "val": ""},
            "msg": {"type": "contains", "val": ""},
            "sender": {"type": "contains", "val": ""},
            "receiver": {"type": "contains", "val": ""},
            "payload": {"type": "contains", "val": ""},
            "decoded": {"type": "contains", "val": ""}
        },
        "sortConfig": {
            "key": "id",
            "direction": "asc"
        },
        "dtcHistory": dtc_history,
        "globalSignalDict": {},
        "log": workspace_log,
        "raw_log": [sanitize_frame_dict(f) for f in raw_log]
    }


def persist_blackbox_record(metadata_dict, raw_log, log_format="raw_can"):
    log_id = f"log_caixa_preta_{str(uuid.uuid4())[:8]}"

    sanitized_raw_log = [sanitize_frame_dict(f) for f in raw_log]
    workspace_log = build_workspace_log(sanitized_raw_log)

    event_summary = {
        "name": f"{metadata_dict.get('truck_id')} ({metadata_dict.get('trigger_event')})",
        "value": [metadata_dict.get("lon"), metadata_dict.get("lat"), 1],
        "itemStyle": {"color": "#ef4444"},
        "isAlert": True,
        "logId": log_id,
        "timestamp": metadata_dict.get("timestamp")
    }

    offline_package = build_offline_package(
        log_id=log_id,
        metadata=metadata_dict,
        raw_log=sanitized_raw_log,
        workspace_log=workspace_log
    )

    record = {
        "log_id": log_id,
        "payload": {
            "metadata": metadata_dict,
            "raw_log": sanitized_raw_log,
            "workspace_log": workspace_log,
            "log_format": log_format,
            "offline_package": offline_package
        },
        "event_summary": event_summary
    }

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO blackbox_logs (payload) VALUES (%s)",
        (json.dumps(record),)
    )
    conn.commit()
    cursor.close()
    conn.close()

    return {
        "status": "success",
        "log_id": log_id,
        "workspace_frames": len(workspace_log),
        "raw_frames": len(sanitized_raw_log),
        "markers": len(offline_package["uiState"]["markers"]),
        "message": "Caixa preta armazenada no Supabase."
    }

@app.post("/api/live-viewers/open")
def open_live_viewer(
    payload: LiveViewerOpenPayload
):
    truck_id = payload.truck_id
    viewer_id = (
        f"viewer_{uuid.uuid4().hex}"
    )

    expires_at = (
        time.time()
        + LIVE_VIEWER_LEASE_SECONDS
    )

    viewer_leases[viewer_id] = {
        "truck_id": truck_id,
        "created_at": time.time(),
        "last_heartbeat_at": time.time(),
        "expires_at": expires_at
    }

    truck_state = ensure_truck_state(
        truck_id
    )

    truck_state["desired_state"] = "online"
    truck_state["user_is_monitoring"] = True
    truck_state["last_heartbeat_time"] = time.time()

    effective_mode = publish_effective_mode_for_truck(
        truck_id,
        "viewer_open"
    )

    return {
        "status": "opened",
        "truck_id": truck_id,
        "viewer_id": viewer_id,
        "effective_mode": effective_mode,
        "lease_expires_at_ms": int(
            expires_at * 1000
        )
    }

@app.post("/api/live-viewers/heartbeat")
def heartbeat_live_viewer(
    payload: LiveViewerHeartbeatPayload
):
    lease = viewer_leases.get(
        payload.viewer_id
    )

    if (
        not lease
        or lease.get("truck_id")
        != payload.truck_id
    ):
        return {
            "status": "expired",
            "viewer_active": False
        }

    expires_at = (
        time.time()
        + LIVE_VIEWER_LEASE_SECONDS
    )

    lease["last_heartbeat_at"] = time.time()
    lease["expires_at"] = expires_at
    print(
    "[LEASE] Heartbeat recebido "
    f"| truck={payload.truck_id} "
    f"| viewer={payload.viewer_id[:16]}... "
    f"| expires_at={int(expires_at)}"
    )

    """
    O comando ONLINE é republicado a cada heartbeat.
    Isso renova o lease local no sniffer.
    """
    publish_mqtt_mode_command(
        payload.truck_id,
        "online",
        "viewer_heartbeat"
    )

    return {
        "status": "ok",
        "viewer_active": True,
        "lease_expires_at_ms": int(
            expires_at * 1000
        )
    }

@app.post("/api/live-viewers/close")
def close_live_viewer(
    payload: LiveViewerHeartbeatPayload
):
    lease = viewer_leases.pop(
        payload.viewer_id,
        None
    )

    truck_id = (
        lease.get("truck_id")
        if lease
        else payload.truck_id
    )

    effective_mode = publish_effective_mode_for_truck(
        truck_id,
        "viewer_closed"
    )

    return {
        "status": "closed",
        "truck_id": truck_id,
        "effective_mode": effective_mode
    }

@app.post("/api/truck-state/{truck_id}")
def set_truck_state_endpoint(
    truck_id: str,
    payload: TruckStatePayload
):
    truck_state = ensure_truck_state(
        truck_id
    )

    desired_state = (
        payload.state or ""
    ).strip().lower()

    if desired_state not in {
        "online",
        "sentinel"
    }:
        raise HTTPException(
            status_code=400,
            detail=(
                "Estado inválido. "
                "Use 'online' ou 'sentinel'."
            )
        )

    truck_state["desired_state"] = desired_state
    truck_state["user_is_monitoring"] = (
        desired_state == "online"
    )

    if desired_state == "online":
        truck_state["last_heartbeat_time"] = time.time()
    else:
        truck_state["last_heartbeat_time"] = 0.0

        viewer_ids_to_remove = [
            viewer_id
            for viewer_id, lease in viewer_leases.items()
            if lease.get("truck_id") == truck_id
        ]

        for viewer_id in viewer_ids_to_remove:
            viewer_leases.pop(
                viewer_id,
                None
            )

    effective_mode = publish_effective_mode_for_truck(
        truck_id,
        "manual_truck_state"
    )

    return {
        "status": "success",
        "truck_id": truck_id,
        "desired_state": desired_state,
        "effective_mode": effective_mode,
        "user_is_monitoring": (
            truck_state["user_is_monitoring"]
        )
    }

@app.get("/api/status/{truck_id}")
async def check_system_status_for_truck(
    truck_id: str
) -> HeartbeatTruckResponse:
    cleanup_expired_viewer_leases()

    truck_state = ensure_truck_state(
        truck_id
    )

    viewer_count = get_active_viewer_count(
        truck_id
    )

    effective_mode = get_effective_mode_for_truck(
        truck_id
    )

    truck_state["user_is_monitoring"] = (
        effective_mode == "online"
    )

    return HeartbeatTruckResponse(
        status="ok",
        truck_id=truck_id,
        user_is_monitoring=(
            effective_mode == "online"
        ),
        live_viewer_active=(
            viewer_count > 0
        ),
        live_viewer_count=viewer_count
    )

@app.post("/api/trucks/register")
def register_truck(payload: TruckRegisterPayload):
    truck_bucket = ensure_live_bucket(payload.truck_id)

    current_stream = truck_bucket.get("__stream__", {
        "snapshot_seq": 0,
        "last_server_time": 0.0,
        "snapshot_device_ms": None,
        "snapshot_unix_ms": None
    })

    truck_bucket["__meta__"] = {
        "truck_id": payload.truck_id,
        "lat": payload.lat,
        "lon": payload.lon,
        "updated_at": time.time(),
        "mode": payload.mode or "sentinel",
        "priority_mode": payload.priority_mode or False,
        "pending_blackbox_upload": payload.pending_blackbox_upload or False,
        "blackbox_locked_until_upload": payload.blackbox_locked_until_upload or False,
        "last_error": payload.last_error or "",
        "chunk_status": payload.chunk_status or "idle"
    }

    truck_bucket["__stream__"] = current_stream

    return {
        "status": "registered",
        "truck_id": payload.truck_id
    }


@app.get("/api/trucks/online")
def get_online_trucks():
    now = time.time()
    trucks = []

    for truck_id, truck_payload in live_signals_db.items():
        meta = truck_payload.get("__meta__", {})
        stream = truck_payload.get("__stream__", {})

        updated_at = float(meta.get("updated_at", 0.0) or 0.0)

        last_snapshot_received_at = float(
            stream.get("last_snapshot_received_at", 0.0) or 0.0
        )

        snapshot_seq = int(
            stream.get("snapshot_seq", 0) or 0
        )

        if last_snapshot_received_at > 0:
            snapshot_age_seconds = round(
                max(0.0, now - last_snapshot_received_at),
                2
            )
        else:
            snapshot_age_seconds = None

        # Regra oficial solicitada:
        # conectado somente se recebeu snapshot nos últimos 5 segundos.
        can_stream_connected = (
            last_snapshot_received_at > 0
            and snapshot_age_seconds is not None
            and snapshot_age_seconds <= 5.0
        )

        trucks.append({
            "truck_id": truck_id,
            "lat": meta.get("lat", -25.4284),
            "lon": meta.get("lon", -49.2731),

            # Mantém o campo existente para não quebrar o frontend.
            "updated_at": updated_at,

            # Mantém o comportamento atual de presença recente.
            "is_recent": (now - updated_at) <= 30.0,

            "mode": meta.get("mode", "unknown"),
            "priority_mode": meta.get(
                "priority_mode",
                False
            ),
            "pending_blackbox_upload": meta.get(
                "pending_blackbox_upload",
                False
            ),
            "blackbox_locked_until_upload": meta.get(
                "blackbox_locked_until_upload",
                False
            ),
            "last_error": meta.get("last_error", ""),
            "chunk_status": meta.get("chunk_status", "idle"),

            # Novos campos para status real de conectividade CAN.
            "snapshot_seq": snapshot_seq,
            "last_snapshot_received_at": (
                last_snapshot_received_at
                if last_snapshot_received_at > 0
                else None
            ),
            "snapshot_age_seconds": snapshot_age_seconds,
            "can_stream_connected": can_stream_connected
        })

    trucks.sort(
        key=lambda truck: truck.get("updated_at", 0),
        reverse=True
    )

    return {
        "trucks": trucks
    }

@app.post("/signals")
async def upload_live_signals(payload: LiveSignalsPayload):
    truck = payload.truck_id
    truck_bucket = ensure_live_bucket(truck)

    for frame in payload.frames:
        truck_bucket["frames"].append(
            sanitize_frame_dict(frame.dict())
        )

    if len(truck_bucket["frames"]) > MAX_LIVE_FRAMES_PER_TRUCK:
        truck_bucket["frames"] = truck_bucket["frames"][
            -MAX_LIVE_FRAMES_PER_TRUCK:
        ]

    now = time.time()

    truck_bucket["__stream__"]["snapshot_seq"] += 1
    truck_bucket["__stream__"]["last_server_time"] = now

    # Este timestamp é a fonte oficial para o status de conexão CAN.
    # Ele só é atualizado quando o backend recebe POST /signals.
    truck_bucket["__stream__"]["last_snapshot_received_at"] = now

    truck_bucket["__stream__"]["snapshot_device_ms"] = (
        payload.snapshot_device_ms
    )

    truck_bucket["__stream__"]["snapshot_unix_ms"] = (
        payload.snapshot_unix_ms
    )

    current_meta = truck_bucket.get("__meta__", {})

    truck_bucket["__meta__"] = {
        "truck_id": payload.truck_id,
        "lat": payload.lat,
        "lon": payload.lon,
        "updated_at": now,
        "mode": current_meta.get("mode", "online"),
        "priority_mode": current_meta.get(
            "priority_mode",
            False
        ),
        "pending_blackbox_upload": current_meta.get(
            "pending_blackbox_upload",
            False
        ),
        "blackbox_locked_until_upload": current_meta.get(
            "blackbox_locked_until_upload",
            False
        ),
        "last_error": current_meta.get("last_error", ""),
        "chunk_status": current_meta.get("chunk_status", "idle")
    }

    return {
        "status": "success",
        "processed_frames": len(payload.frames),
        "snapshot_seq": truck_bucket["__stream__"]["snapshot_seq"],

        # Útil para diagnóstico do sniffer e do backend.
        "last_snapshot_received_at": now
    }

@app.get("/signals")
async def get_live_signals(
    truck_id: str = "Volvo FH540 (Sniffer 01)"
):
    """
    Retorna o último snapshot completo recebido por MQTT.
    Não limpa frames após o GET.
    O frontend identifica novidade usando snapshot_seq.
    """
    if truck_id not in live_signals_db:
        return {
            "status": "empty",
            "frames": [],
            "truck_id": truck_id,
            "snapshot_seq": 0,
            "server_time": time.time(),
            "snapshot_device_ms": None,
            "snapshot_unix_ms": None
        }

    with live_state_lock:
        truck_data = ensure_live_bucket(
            truck_id
        )

        meta = truck_data.get(
            "__meta__",
            {}
        )

        stream = truck_data.get(
            "__stream__",
            {}
        )

        updated_at = float(
            meta.get(
                "updated_at",
                0.0
            ) or 0.0
        )

        if (
            time.time() - updated_at
            > LIVE_DATA_TIMEOUT_SECONDS
        ):
            return {
                "status": "stale",
                "frames": [],
                "truck_id": truck_id,
                "lat": meta.get(
                    "lat",
                    -25.4284
                ),
                "lon": meta.get(
                    "lon",
                    -49.2731
                ),
                "snapshot_seq": stream.get(
                    "snapshot_seq",
                    0
                ),
                "server_time": time.time(),
                "snapshot_device_ms": stream.get(
                    "snapshot_device_ms"
                ),
                "snapshot_unix_ms": stream.get(
                    "snapshot_unix_ms"
                )
            }

        frames_to_deliver = [
            sanitize_frame_dict(frame)
            for frame in truck_data.get(
                "frames",
                []
            )
        ]

        return {
            "status": "success",
            "frames": frames_to_deliver,
            "truck_id": meta.get(
                "truck_id",
                truck_id
            ),
            "lat": meta.get(
                "lat",
                -25.4284
            ),
            "lon": meta.get(
                "lon",
                -49.2731
            ),
            "snapshot_seq": stream.get(
                "snapshot_seq",
                0
            ),
            "server_time": stream.get(
                "last_server_time",
                time.time()
            ),
            "snapshot_device_ms": stream.get(
                "snapshot_device_ms"
            ),
            "snapshot_unix_ms": stream.get(
                "snapshot_unix_ms"
            )
        }

@app.post("/api/blackbox/upload")
def upload_blackbox_log(payload: BlackboxUpload):
    try:
        return persist_blackbox_record(
            metadata_dict=payload.metadata.dict(),
            raw_log=[sanitize_frame_dict(f) for f in payload.log],
            log_format=payload.log_format or "raw_can"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao salvar no Supabase: {str(e)}")


@app.post("/api/blackbox/upload_chunk")
def upload_blackbox_chunk(payload: BlackboxChunkUpload):
    try:
        removed = cleanup_stale_pending_blackbox_chunks()
        upload_id = payload.upload_id

        bucket = load_pending_chunk_bucket(upload_id)
        if not bucket:
            bucket = {
                "metadata": payload.metadata.dict(),
                "chunk_total": payload.chunk_total,
                "received": {},
                "created_at_epoch": time.time(),
                "log_format": payload.log_format or "raw_can"
            }

        bucket["metadata"] = payload.metadata.dict()
        bucket["chunk_total"] = payload.chunk_total
        bucket["received"][str(payload.chunk_index)] = [sanitize_frame_dict(frame.dict()) for frame in payload.frames]
        bucket["log_format"] = payload.log_format or bucket.get("log_format", "raw_can")

        save_pending_chunk_bucket(upload_id, bucket)

        received_count = len(bucket["received"])
        expected_total = bucket["chunk_total"]

        if received_count < expected_total:
            return {
                "status": "partial",
                "upload_id": upload_id,
                "received_chunks": received_count,
                "chunk_total": expected_total,
                "cleanup_removed": removed
            }

        missing_chunks = [idx for idx in range(expected_total) if str(idx) not in bucket["received"]]
        if missing_chunks:
            return {
                "status": "partial_missing",
                "upload_id": upload_id,
                "received_chunks": received_count,
                "chunk_total": expected_total,
                "missing_chunks": missing_chunks,
                "cleanup_removed": removed
            }

        full_log = []
        for idx in range(expected_total):
            full_log.extend(bucket["received"][str(idx)])

        result = persist_blackbox_record(
            metadata_dict=bucket["metadata"],
            raw_log=full_log,
            log_format=bucket["log_format"]
        )

        delete_pending_chunk_bucket(upload_id)

        return {
            "status": "success",
            "upload_id": upload_id,
            "cleanup_removed": removed,
            **result
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao montar upload em chunks: {str(e)}")


@app.post("/api/blackbox/cleanup_pending")
def cleanup_pending_blackbox():
    removed = cleanup_stale_pending_blackbox_chunks()
    return {
        "status": "success",
        "removed_count": len(removed),
        "removed": removed,
        "pending_after_cleanup": len(get_pending_blackbox_summary())
    }


@app.get("/api/blackbox/pending_status")
def get_pending_blackbox_status():
    removed = cleanup_stale_pending_blackbox_chunks()
    summary = get_pending_blackbox_summary()
    return {
        "status": "success",
        "ttl_seconds": PENDING_BLACKBOX_TTL_SECONDS,
        "cleanup_removed_now": len(removed),
        "pending_count": len(summary),
        "pending_uploads": summary
    }


@app.get("/api/blackbox/events")
def get_blackbox_events():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT payload FROM blackbox_logs ORDER BY created_at DESC")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        events = []
        for row in rows:
            record = row[0] or {}
            payload = record.get("payload", {}) or {}
            metadata = payload.get("metadata", {}) or {}
            event_summary = record.get("event_summary", {}) or {}

            events.append({
                "log_id": record.get("log_id") or event_summary.get("logId"),
                "event_summary": event_summary,
                "metadata": metadata,
                "workspace_log": payload.get("workspace_log", []),
                "raw_log": payload.get("raw_log", []),
                "offline_package": payload.get("offline_package")
            })

        return {"events": events}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao buscar eventos: {str(e)}")


@app.get("/api/blackbox/events/light")
def get_blackbox_events_light(response: Response):
    """
    Retorna metadados leves dos eventos EDR.

    Além dos dados de identificação, o endpoint inclui as DTCs DM1
    encontradas no raw_log. Isso permite filtrar corretamente por
    ECU, Source Address, SPN e FMI no frontend, sem transferir todo
    o conteúdo da caixa-preta.
    """
    try:
        response.headers["Cache-Control"] = (
            "no-store, no-cache, must-revalidate, max-age=0"
        )

        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT payload
            FROM blackbox_logs
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (BLACKBOX_EVENTS_LIGHT_LIMIT,)
        )

        rows = cursor.fetchall()

        cursor.close()
        conn.close()

        events = []

        for row in rows:
            record = row[0] or {}

            if not isinstance(record, dict):
                continue

            payload = record.get("payload", {}) or {}
            metadata = payload.get("metadata", {}) or {}
            event_summary = record.get("event_summary", {}) or {}

            raw_log = payload.get("raw_log", []) or []

            faults = extract_blackbox_fault_context(
                raw_log
            )

            fault_groups = []

            for fault in faults:
                fault_group = fault.get("group")

                if (
                    fault_group
                    and fault_group not in fault_groups
                ):
                    fault_groups.append(fault_group)

            truck_id = (
                metadata.get("truck_id")
                or event_summary.get("name")
                or "Volvo FH540 (Recuperado)"
            )

            timestamp = (
                metadata.get("timestamp")
                or event_summary.get("timestamp")
                or "N/A"
            )

            trigger_event = (
                metadata.get("trigger_event")
                or "Falha DM1 Detectada"
            )

            lat = metadata.get("lat", -25.4284)
            lon = metadata.get("lon", -49.2731)

            if faults:
                preview_fault = faults[0]

                fault_preview = (
                    f"{preview_fault.get('ecu_name')} "
                    f"({preview_fault.get('sa_hex')}) | "
                    f"SPN {preview_fault.get('spn')} | "
                    f"FMI {preview_fault.get('fmi')} | "
                    f"{preview_fault.get('caption')}"
                )
            else:
                fault_preview = (
                    "Nenhuma DTC DM1 válida foi identificada "
                    "no log da caixa-preta."
                )

            events.append({
                "log_id": (
                    record.get("log_id")
                    or event_summary.get("logId")
                ),

                "event_summary": event_summary,

                "metadata": {
                    "truck_id": truck_id,
                    "timestamp": timestamp,
                    "trigger_event": trigger_event,
                    "lat": lat,
                    "lon": lon
                },

                "fault_groups": fault_groups,
                "faults": faults,
                "fault_preview": fault_preview
            })

        return {
            "events": events,
            "count": len(events),
            "generated_at": time.time()
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=(
                "Erro ao buscar eventos leves: "
                f"{str(error)}"
            )
        )


@app.get("/api/blackbox/download/{log_id}")
def download_blackbox_log(log_id: str):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT payload FROM blackbox_logs WHERE payload->>'log_id' = %s ORDER BY created_at DESC LIMIT 1",
            (log_id,)
        )
        row = cursor.fetchone()
        cursor.close()
        conn.close()

        if not row:
            raise HTTPException(status_code=404, detail="Log não encontrado no servidor.")

        return row[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao baixar log: {str(e)}")


@app.get("/api/blackbox/offline/{log_id}")
def download_blackbox_offline(log_id: str):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT payload FROM blackbox_logs WHERE payload->>'log_id' = %s ORDER BY created_at DESC LIMIT 1",
            (log_id,)
        )
        row = cursor.fetchone()
        cursor.close()
        conn.close()

        if not row:
            raise HTTPException(status_code=404, detail="Log não encontrado no servidor.")

        record = row[0] or {}
        payload = record.get("payload", {}) or {}
        offline_package = payload.get("offline_package")

        if offline_package:
            return offline_package

        metadata = payload.get("metadata", {})
        raw_log = [sanitize_frame_dict(f) for f in payload.get("raw_log", [])]
        workspace_log = payload.get("workspace_log", build_workspace_log(raw_log))

        return build_offline_package(
            log_id=record.get("log_id", log_id),
            metadata=metadata,
            raw_log=raw_log,
            workspace_log=workspace_log
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao montar pacote offline: {str(e)}")


@app.get("/api/blackbox/direct/{log_id}")
def get_blackbox_direct(log_id: str):
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT
                    payload->>'log_id' AS log_id,
                    payload->'payload'->'metadata' AS metadata,
                    payload->'payload'->'raw_log' AS raw_log,
                    payload->'payload'->'workspace_log' AS workspace_log,
                    payload->'payload'->'offline_package' AS offline_package,
                    payload->'event_summary' AS event_summary,
                    created_at
                FROM blackbox_logs
                WHERE payload->>'log_id' = %s
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (log_id,)
            )
            row = cursor.fetchone()
        conn.close()

        if not row:
            raise HTTPException(status_code=404, detail="Log não encontrado.")

        return row
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro na consulta direta: {str(e)}")
