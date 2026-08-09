import os
import json
import time
import uuid
import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
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
    "timeout_seconds": 30.0,
    "monitoring_by_truck": {}
}

live_signals_db = {}
LIVE_DATA_TIMEOUT_SECONDS = 5.0
MAX_LIVE_FRAMES_PER_TRUCK = 2000
BLACKBOX_EVENTS_LIGHT_LIMIT = 100
PENDING_BLACKBOX_TTL_SECONDS = 900


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
        clean = []
        for b in v[:8]:
            clean.append(int(b) & 0xFF)
        return clean


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


def sanitize_frame_dict(frame: Dict[str, Any]) -> Dict[str, Any]:
    dlc = int(frame.get("dlc", 0) or 0)
    if dlc < 0:
        dlc = 0
    if dlc > 8:
        dlc = 8

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
                "snapshot_device_ms": None,
                "snapshot_unix_ms": None
            }
        }
    else:
        if "__stream__" not in live_signals_db[truck_id]:
            live_signals_db[truck_id]["__stream__"] = {
                "snapshot_seq": 0,
                "last_server_time": 0.0,
                "snapshot_device_ms": None,
                "snapshot_unix_ms": None
            }
        if "__meta__" not in live_signals_db[truck_id]:
            live_signals_db[truck_id]["__meta__"] = {}
        if "frames" not in live_signals_db[truck_id]:
            live_signals_db[truck_id]["frames"] = []

    return live_signals_db[truck_id]


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
    return (row["payload"] if row else None)


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
    if not isinstance(raw_log, list) or not raw_log:
        return []

    grouped = {}
    ordered_ts = []

    for raw_frame in raw_log:
        frame = sanitize_frame_dict(raw_frame)
        if not frame.get("extd", True):
            continue

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

            if not parsed.get("is_j1939", False):
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
                "da": parsed.get("da")
            })

            if parsed["sigs"]:
                sigs.update(parsed["sigs"])

        if frames_out:
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


@app.post("/api/truck-state/{truck_id}")
def set_truck_state_endpoint(truck_id: str, payload: TruckStatePayload):
    truck_state = ensure_truck_state(truck_id)
    desired_state = (payload.state or "").strip().lower()

    if desired_state not in {"online", "sentinel"}:
        raise HTTPException(status_code=400, detail="Estado inválido. Use 'online' ou 'sentinel'.")

    truck_state["desired_state"] = desired_state
    truck_state["user_is_monitoring"] = (desired_state == "online")
    if desired_state == "online":
        truck_state["last_heartbeat_time"] = time.time()
    else:
        truck_state["last_heartbeat_time"] = 0.0

    return {
        "status": "success",
        "truck_id": truck_id,
        "desired_state": desired_state,
        "user_is_monitoring": truck_state["user_is_monitoring"]
    }


@app.get("/api/status/{truck_id}")
async def check_system_status_for_truck(truck_id: str) -> HeartbeatTruckResponse:
    truck_state = ensure_truck_state(truck_id)
    desired_state = truck_state.get("desired_state", "sentinel")
    truck_state["user_is_monitoring"] = (desired_state == "online")

    return HeartbeatTruckResponse(
        status="ok",
        user_is_monitoring=truck_state["user_is_monitoring"],
        truck_id=truck_id
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
        updated_at = meta.get("updated_at", 0.0)

        trucks.append({
            "truck_id": truck_id,
            "lat": meta.get("lat", -25.4284),
            "lon": meta.get("lon", -49.2731),
            "updated_at": updated_at,
            "is_recent": (now - updated_at) <= 30.0,
            "mode": meta.get("mode", "unknown"),
            "priority_mode": meta.get("priority_mode", False),
            "pending_blackbox_upload": meta.get("pending_blackbox_upload", False),
            "blackbox_locked_until_upload": meta.get("blackbox_locked_until_upload", False),
            "last_error": meta.get("last_error", ""),
            "chunk_status": meta.get("chunk_status", "idle")
        })

    trucks.sort(key=lambda x: x.get("updated_at", 0), reverse=True)
    return {"trucks": trucks}


@app.post("/signals")
async def upload_live_signals(payload: LiveSignalsPayload):
    truck = payload.truck_id
    truck_bucket = ensure_live_bucket(truck)

    for frame in payload.frames:
        truck_bucket["frames"].append(sanitize_frame_dict(frame.dict()))

    if len(truck_bucket["frames"]) > MAX_LIVE_FRAMES_PER_TRUCK:
        truck_bucket["frames"] = truck_bucket["frames"][-MAX_LIVE_FRAMES_PER_TRUCK:]

    truck_bucket["__stream__"]["snapshot_seq"] += 1
    truck_bucket["__stream__"]["last_server_time"] = time.time()
    truck_bucket["__stream__"]["snapshot_device_ms"] = payload.snapshot_device_ms
    truck_bucket["__stream__"]["snapshot_unix_ms"] = payload.snapshot_unix_ms

    current_meta = truck_bucket.get("__meta__", {})
    truck_bucket["__meta__"] = {
        "truck_id": payload.truck_id,
        "lat": payload.lat,
        "lon": payload.lon,
        "updated_at": time.time(),
        "mode": current_meta.get("mode", "online"),
        "priority_mode": current_meta.get("priority_mode", False),
        "pending_blackbox_upload": current_meta.get("pending_blackbox_upload", False),
        "blackbox_locked_until_upload": current_meta.get("blackbox_locked_until_upload", False),
        "last_error": current_meta.get("last_error", ""),
        "chunk_status": current_meta.get("chunk_status", "idle")
    }

    return {
        "status": "success",
        "processed_frames": len(payload.frames),
        "snapshot_seq": truck_bucket["__stream__"]["snapshot_seq"]
    }


@app.get("/signals")
async def get_live_signals(truck_id: str = "Volvo FH540 (Sniffer 01)"):
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

    truck_data = ensure_live_bucket(truck_id)
    meta = truck_data.get("__meta__", {})
    updated_at = meta.get("updated_at", 0.0)
    stream = truck_data.get("__stream__", {
        "snapshot_seq": 0,
        "last_server_time": 0.0,
        "snapshot_device_ms": None,
        "snapshot_unix_ms": None
    })

    if (time.time() - updated_at) > LIVE_DATA_TIMEOUT_SECONDS:
        return {
            "status": "stale",
            "frames": [],
            "truck_id": truck_id,
            "lat": meta.get("lat", -25.4284),
            "lon": meta.get("lon", -49.2731),
            "snapshot_seq": stream.get("snapshot_seq", 0),
            "server_time": time.time(),
            "snapshot_device_ms": stream.get("snapshot_device_ms"),
            "snapshot_unix_ms": stream.get("snapshot_unix_ms")
        }

    frames_to_deliver = [sanitize_frame_dict(f) for f in truck_data.get("frames", [])[:]]
    truck_data["frames"] = []

    return {
        "status": "success",
        "frames": frames_to_deliver,
        "truck_id": meta.get("truck_id", truck_id),
        "lat": meta.get("lat", -25.4284),
        "lon": meta.get("lon", -49.2731),
        "snapshot_seq": stream.get("snapshot_seq", 0),
        "server_time": stream.get("last_server_time", time.time()),
        "snapshot_device_ms": stream.get("snapshot_device_ms"),
        "snapshot_unix_ms": stream.get("snapshot_unix_ms")
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
def get_blackbox_events_light():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT payload FROM blackbox_logs ORDER BY created_at DESC LIMIT %s",
            (BLACKBOX_EVENTS_LIGHT_LIMIT,)
        )
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        events = []
        for row in rows:
            record = row[0] or {}
            payload = record.get("payload", {}) or {}
            metadata = payload.get("metadata", {}) or {}
            event_summary = record.get("event_summary", {}) or {}

            truck_id = metadata.get("truck_id") or event_summary.get("name") or "Volvo FH540 (Recuperado)"
            timestamp = metadata.get("timestamp") or event_summary.get("timestamp") or "N/A"
            trigger_event = metadata.get("trigger_event") or "Falha DM1 Detectada"
            lat = metadata.get("lat", -25.4284)
            lon = metadata.get("lon", -49.2731)

            events.append({
                "log_id": record.get("log_id") or event_summary.get("logId"),
                "event_summary": event_summary,
                "metadata": {
                    "truck_id": truck_id,
                    "timestamp": timestamp,
                    "trigger_event": trigger_event,
                    "lat": lat,
                    "lon": lon
                }
            })

        return {"events": events}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao buscar eventos leves: {str(e)}")


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
