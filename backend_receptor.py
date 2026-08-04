import os
import json
import time
import uuid
import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional

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
    "timeout_seconds": 10.0
}

live_signals_db = {}

class HeartbeatResponse(BaseModel):
    status: str
    user_is_monitoring: bool

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

class LiveSignalsPayload(BaseModel):
    truck_id: str
    frames: List[CanFrame]
    lat: float | None = None
    lon: float | None = None

def get_db_connection():
    if not DATABASE_URL:
        raise HTTPException(status_code=500, detail="DATABASE_URL não configurada.")
    return psycopg2.connect(DATABASE_URL)

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

def payload_to_hex(data_bytes):
    if not isinstance(data_bytes, list):
        return ""
    return " ".join(f"{int(b) & 0xFF:02X}" for b in data_bytes)

def is_dm1_frame(can_id_hex):
    return "FECA" in can_id_hex.upper()

def parse_dm1(decoded_payload_hex):
    try:
        parts = decoded_payload_hex.split()
        if len(parts) < 4:
            return None
        spn = (int(parts[2], 16) << 8) | int(parts[1], 16)
        fmi = int(parts[3], 16) & 0x1F
        oc = int(parts[3], 16) >> 7
        if spn == 0:
            return {
                "message": "DM1",
                "decoded": "No Active DTCs",
                "sigs": {}
            }
        return {
            "message": "DM1",
            "decoded": f"Active Diagnostic Trouble Codes | SPN={spn} | FMI={fmi} | OC={oc}",
            "sigs": {}
        }
    except Exception:
        return {
            "message": "DM1",
            "decoded": "Diagnostic Message 1",
            "sigs": {}
        }

def parse_j1939_fallback(frame):
    can_id_hex = normalize_can_id(frame.get("id"))
    payload_hex = payload_to_hex(frame.get("d", []))
    if is_dm1_frame(can_id_hex):
        dm1 = parse_dm1(payload_hex)
        if dm1:
            return {
                "id": can_id_hex,
                "message": dm1["message"],
                "sender": "ECU Desconhecida",
                "receiver": "Broadcast",
                "dlc": frame.get("dlc", 8),
                "payload": payload_hex,
                "decoded": dm1["decoded"],
                "sigs": dm1["sigs"]
            }

    return {
        "id": can_id_hex,
        "message": f"Unknown PGN {((int(can_id_hex, 16) >> 8) & 0x3FFFF)}" if can_id_hex.startswith("0x") else "Unknown",
        "sender": "ECU Desconhecida",
        "receiver": "Broadcast",
        "dlc": frame.get("dlc", 8),
        "payload": payload_hex,
        "decoded": "Raw Data",
        "sigs": {}
    }

def to_time_label_from_seconds(seconds_float):
    total_ms = int(round(max(seconds_float, 0) * 1000))
    hh = total_ms // 3600000
    rem = total_ms % 3600000
    mm = rem // 60000
    rem = rem % 60000
    ss = rem // 1000
    ms = rem % 1000
    return f"{hh:02d}:{mm:02d}:{ss:02d}.{ms:03d}"

def build_workspace_log(raw_log):
    if not isinstance(raw_log, list) or not raw_log:
        return []

    grouped = {}
    ordered_ts = []

    for frame in raw_log:
        t = int(frame.get("t", 0))
        if t not in grouped:
            grouped[t] = []
            ordered_ts.append(t)
        grouped[t].append(frame)

    ordered_ts.sort()
    base_t = ordered_ts[0] if ordered_ts else 0

    workspace_log = []
    for t in ordered_ts:
        frames_out = []
        sigs = {}

        for frame in grouped[t]:
            parsed = parse_j1939_fallback(frame)
            frames_out.append({
                "id": parsed["id"],
                "message": parsed["message"],
                "sender": parsed["sender"],
                "receiver": parsed["receiver"],
                "dlc": parsed["dlc"],
                "payload": parsed["payload"],
                "decoded": parsed["decoded"]
            })
            if parsed["sigs"]:
                sigs.update(parsed["sigs"])

        rel = (t - base_t) / 1000.0
        workspace_log.append({
            "time": to_time_label_from_seconds(rel),
            "rel": rel,
            "sigs": sigs,
            "frames": frames_out
        })

    return workspace_log

def build_offline_package(log_id, metadata, raw_log, workspace_log):
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
            "markers": [],
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
        "dtcHistory": {},
        "globalSignalDict": {},
        "log": workspace_log,
        "raw_log": raw_log
    }

@app.post("/api/heartbeat", summary="Recebe o pulso do Frontend (Dashboard)")
async def receive_heartbeat():
    SYSTEM_STATE["last_heartbeat_time"] = time.time()
    SYSTEM_STATE["user_is_monitoring"] = True
    return {"status": "alive", "timestamp": SYSTEM_STATE["last_heartbeat_time"]}

@app.get("/api/status", summary="ESP32 Consulta o Status da Operação")
async def check_system_status() -> HeartbeatResponse:
    current_time = time.time()
    time_since_last_pulse = current_time - SYSTEM_STATE["last_heartbeat_time"]

    if time_since_last_pulse > SYSTEM_STATE["timeout_seconds"]:
        SYSTEM_STATE["user_is_monitoring"] = False

    return HeartbeatResponse(
        status="ok",
        user_is_monitoring=SYSTEM_STATE["user_is_monitoring"]
    )

@app.post("/signals", summary="ESP32 envia frames CAN em tempo real (Streaming)")
async def upload_live_signals(payload: LiveSignalsPayload):
    truck = payload.truck_id
    if truck not in live_signals_db:
        live_signals_db[truck] = {}

    for frame in payload.frames:
        live_signals_db[truck][frame.id] = frame.dict()

    live_signals_db[truck]["__meta__"] = {
        "truck_id": payload.truck_id,
        "lat": payload.lat,
        "lon": payload.lon,
        "updated_at": time.time()
    }

    return {"status": "success", "processed_frames": len(payload.frames)}

@app.get("/signals", summary="Frontend consome frames em tempo real")
async def get_live_signals(truck_id: str = "Volvo FH540 (Sniffer 01)"):
    if truck_id in live_signals_db:
        truck_data = live_signals_db[truck_id].copy()
        meta = truck_data.pop("__meta__", {})
        return {
            "status": "success",
            "data": truck_data,
            "truck_id": meta.get("truck_id", truck_id),
            "lat": meta.get("lat", -25.4284),
            "lon": meta.get("lon", -49.2731)
        }
    return {"status": "empty", "data": {}}

@app.post("/api/blackbox/upload", summary="ESP32 Envia o Log Pós-Falha (Bulk Upload)")
def upload_blackbox_log(payload: BlackboxUpload):
    log_id = f"log_caixa_preta_{str(uuid.uuid4())[:8]}"

    raw_log = payload.log
    workspace_log = build_workspace_log(raw_log)

    event_summary = {
        "name": f"{payload.metadata.truck_id} ({payload.metadata.trigger_event})",
        "value": [payload.metadata.lon, payload.metadata.lat, 1],
        "itemStyle": {"color": "#ef4444"},
        "isAlert": True,
        "logId": log_id,
        "timestamp": payload.metadata.timestamp
    }

    offline_package = build_offline_package(
        log_id=log_id,
        metadata=payload.metadata.dict(),
        raw_log=raw_log,
        workspace_log=workspace_log
    )

    record = {
        "log_id": log_id,
        "payload": {
            "metadata": payload.metadata.dict(),
            "raw_log": raw_log,
            "workspace_log": workspace_log,
            "log_format": payload.log_format or "raw_can",
            "offline_package": offline_package
        },
        "event_summary": event_summary
    }

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO blackbox_logs (payload) VALUES (%s)",
            (json.dumps(record),)
        )
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao salvar no Supabase: {str(e)}")

    return {
        "status": "success",
        "log_id": log_id,
        "workspace_frames": len(workspace_log),
        "raw_frames": len(raw_log),
        "message": "Caixa preta armazenada no Supabase."
    }

@app.get("/api/blackbox/events", summary="Frontend Solicita Pontos do Mapa")
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
                "raw_log": payload.get("raw_log", [])
            })

        return {"events": events}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao buscar eventos: {str(e)}")

@app.get("/api/blackbox/download/{log_id}", summary="Frontend Baixa o Arquivo Completo")
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

@app.get("/api/blackbox/offline/{log_id}", summary="Baixa pacote compatível com modo offline")
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
        raw_log = payload.get("raw_log", payload.get("log", []))
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

@app.get("/api/blackbox/direct/{log_id}", summary="Consulta resumida do log completo")
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
