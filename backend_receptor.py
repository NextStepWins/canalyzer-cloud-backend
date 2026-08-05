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
    "timeout_seconds": 10.0,
    "monitoring_by_truck": {}
}

live_signals_db = {}

class HeartbeatResponse(BaseModel):
    status: str
    user_is_monitoring: bool

class HeartbeatTruckResponse(BaseModel):
    status: str
    user_is_monitoring: bool
    truck_id: str

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

DTC_DICT = {
    "140_2": {"caption": "Engine Oil Pressure", "ftb": "Data Erratic, Intermittent Or Incorrect"},
    "190_0": {"caption": "Engine Speed", "ftb": "Data Valid But Above Normal Operational Range"},
    "110_0": {"caption": "Engine Coolant Temperature", "ftb": "Data Valid But Above Normal Range"},
    "94_1": {"caption": "Engine Fuel Delivery Pressure", "ftb": "Data Valid But Below Normal Range"},
    "84_9": {"caption": "Wheel-Based Vehicle Speed", "ftb": "Abnormal Update Rate"},
    "108_3": {"caption": "Barometric Pressure", "ftb": "Voltage Above Normal"},
    "158_4": {"caption": "Battery Potential / Power Input 1", "ftb": "Voltage Below Normal"}
}

J1939_SENDERS = {
    0x00: "Engine #1 (EMS)",
    0x03: "Transmission (TECU)",
    0x0B: "Brakes (EBS/ABS)",
    0x11: "Vehicle Management",
    0x17: "Instrument Cluster",
    0x21: "Body Controller",
    0x33: "Cab Controller",
    0xEE: "Tachograph",
    0xFF: "Broadcast"
}

def get_db_connection():
    if not DATABASE_URL:
        raise HTTPException(status_code=500, detail="DATABASE_URL não configurada.")
    return psycopg2.connect(DATABASE_URL)

def ensure_truck_state(truck_id: str):
    if truck_id not in SYSTEM_STATE["monitoring_by_truck"]:
        SYSTEM_STATE["monitoring_by_truck"][truck_id] = {
            "last_heartbeat_time": 0.0,
            "user_is_monitoring": False,
            "timeout_seconds": 10.0
        }
    return SYSTEM_STATE["monitoring_by_truck"][truck_id]

def get_dtc_text(spn, fmi):
    key = f"{spn}_{fmi}"
    return DTC_DICT.get(key, {
        "caption": f"SPN Não Catalogada ({spn})",
        "ftb": f"FMI Genérico ({fmi})"
    })

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
    return J1939_SENDERS.get(sa, f"SA 0x{sa:02X}")

def format_receiver(meta):
    if meta["is_pdu1"] and meta["da"] is not None:
        return f"DA 0x{meta['da']:02X}"
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

def decode_dm1(payload_bytes):
    if len(payload_bytes) < 4:
        return {
            "message": "DM1",
            "decoded": "Diagnostic Message 1",
            "sigs": {},
            "dtc": None
        }

    spn = (payload_bytes[2] << 8) | payload_bytes[1]
    fmi = payload_bytes[3] & 0x1F
    oc = payload_bytes[4] if len(payload_bytes) > 4 else 0

    if spn == 0:
        return {
            "message": "DM1",
            "decoded": "No Active DTCs",
            "sigs": {"ActiveDTCCount": 0},
            "dtc": None
        }

    info = get_dtc_text(spn, fmi)
    return {
        "message": "DM1",
        "decoded": f"Active Diagnostic Trouble Codes | SPN={spn} | FMI={fmi} | OC={oc}",
        "sigs": {
            "ActiveDTCCount": 1,
            "DM1_SPN": spn,
            "DM1_FMI": fmi,
            "DM1_OC": oc
        },
        "dtc": {
            "spn": spn,
            "fmi": fmi,
            "oc": oc,
            "caption": info["caption"],
            "ftb": info["ftb"]
        }
    }

def parse_known_j1939(frame):
    can_id = frame.get("id")
    can_id_hex = normalize_can_id(can_id)
    payload_bytes = frame.get("d", []) or []
    payload_hex = payload_to_hex(payload_bytes)

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
    elif pgn == 65226:
        decoded = decode_dm1(payload_bytes)

    if decoded:
        return {
            "id": can_id_hex,
            "message": decoded["message"],
            "sender": format_sender(meta["sa"]),
            "receiver": format_receiver(meta),
            "dlc": frame.get("dlc", 8),
            "payload": payload_hex,
            "decoded": decoded["decoded"],
            "sigs": decoded.get("sigs", {}),
            "dtc": decoded.get("dtc")
        }

    return {
        "id": can_id_hex,
        "message": f"Unknown PGN {pgn}",
        "sender": format_sender(meta["sa"]),
        "receiver": format_receiver(meta),
        "dlc": frame.get("dlc", 8),
        "payload": payload_hex,
        "decoded": "Raw Data",
        "sigs": {},
        "dtc": None
    }

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
            parsed = parse_known_j1939(frame)

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
        "raw_log": raw_log
    }

@app.post("/api/heartbeat")
async def receive_heartbeat():
    SYSTEM_STATE["last_heartbeat_time"] = time.time()
    SYSTEM_STATE["user_is_monitoring"] = True
    return {"status": "alive", "timestamp": SYSTEM_STATE["last_heartbeat_time"]}

@app.get("/api/status")
async def check_system_status() -> HeartbeatResponse:
    current_time = time.time()
    time_since_last_pulse = current_time - SYSTEM_STATE["last_heartbeat_time"]

    if time_since_last_pulse > SYSTEM_STATE["timeout_seconds"]:
        SYSTEM_STATE["user_is_monitoring"] = False

    return HeartbeatResponse(
        status="ok",
        user_is_monitoring=SYSTEM_STATE["user_is_monitoring"]
    )

@app.post("/api/heartbeat/{truck_id}")
async def receive_heartbeat_for_truck(truck_id: str):
    truck_state = ensure_truck_state(truck_id)
    truck_state["last_heartbeat_time"] = time.time()
    truck_state["user_is_monitoring"] = True
    return {
        "status": "alive",
        "truck_id": truck_id,
        "timestamp": truck_state["last_heartbeat_time"]
    }

@app.get("/api/status/{truck_id}")
async def check_system_status_for_truck(truck_id: str) -> HeartbeatTruckResponse:
    truck_state = ensure_truck_state(truck_id)

    current_time = time.time()
    time_since_last_pulse = current_time - truck_state["last_heartbeat_time"]

    if time_since_last_pulse > truck_state["timeout_seconds"]:
        truck_state["user_is_monitoring"] = False

    return HeartbeatTruckResponse(
        status="ok",
        user_is_monitoring=truck_state["user_is_monitoring"],
        truck_id=truck_id
    )

@app.get("/api/trucks/online")
def get_online_trucks():
    now = time.time()
    trucks = []

    for truck_id, truck_payload in live_signals_db.items():
        meta = truck_payload.get("__meta__", {})
        updated_at = meta.get("updated_at", 0.0)

        trucks.append({
            "truck_id": truck_id,
            "lat": meta.get("lat", -25.4284),
            "lon": meta.get("lon", -49.2731),
            "updated_at": updated_at,
            "is_recent": (now - updated_at) <= 30.0
        })

    trucks.sort(key=lambda x: x.get("updated_at", 0), reverse=True)
    return {"trucks": trucks}

@app.post("/signals")
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

@app.get("/signals")
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
    return {"status": "empty", "data": {}, "truck_id": truck_id}

@app.post("/api/blackbox/upload")
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
        "markers": len(offline_package["uiState"]["markers"]),
        "message": "Caixa preta armazenada no Supabase."
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
                "raw_log": payload.get("raw_log", [])
            })

        return {"events": events}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao buscar eventos: {str(e)}")

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
        raw_log = payload.get("raw_log", [])
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
