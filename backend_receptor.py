import os
import json
import time
import uuid
import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any

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

    event_summary = {
        "name": f"{payload.metadata.truck_id} ({payload.metadata.trigger_event})",
        "value": [payload.metadata.lon, payload.metadata.lat, 1],
        "itemStyle": {"color": "#ef4444"},
        "isAlert": True,
        "logId": log_id,
        "timestamp": payload.metadata.timestamp
    }

    record = {
        "log_id": log_id,
        "payload": payload.dict(),
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
                "metadata": metadata
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
                    payload->'payload'->'log' AS log,
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
