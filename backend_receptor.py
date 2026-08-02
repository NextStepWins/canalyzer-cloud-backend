import os
import json
import time
import uuid
import psycopg2
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any

app = FastAPI(title="CANalyzer Pro Backend - Híbrido (Streaming & EDR)")

# Configuração de CORS para permitir que o Frontend converse com o Render
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Lê a URL do banco de dados que você configurou nas Environment Variables do Render
DATABASE_URL = os.getenv("DATABASE_URL")

# ==========================================
# VARIÁVEIS DE ESTADO (MEMÓRIA TEMPORÁRIA)
# ==========================================
SYSTEM_STATE = {
    "last_heartbeat_time": 0.0,
    "user_is_monitoring": False,
    "timeout_seconds": 10.0  # Timeout para voltar ao modo Sentinela
}

# --- Banco de Dados em Memória (Free Tier Render) ---
# Banco do Live Sniffing (Guarda o último estado de cada ID CAN)
live_signals_db = {} 

# ==========================================
# MODELOS DE DADOS (Pydantic)
# ==========================================
class HeartbeatResponse(BaseModel):
    status: str
    user_is_monitoring: bool

# --- Modelos da Caixa Preta (EDR) ---
class BlackboxMetadata(BaseModel):
    truck_id: str
    trigger_event: str
    lat: float
    lon: float
    timestamp: str

class BlackboxUpload(BaseModel):
    metadata: BlackboxMetadata
    log: List[Dict[str, Any]]  # Buffer circular gigante

# --- Modelos do Live Sniffing (Tempo Real) ---
class CanFrame(BaseModel):
    t: int       # Timestamp
    id: int      # CAN ID (ex: PGN)
    dlc: int     # Tamanho dos dados
    d: List[int] # Array com os 8 bytes

class LiveSignalsPayload(BaseModel):
    truck_id: str
    frames: List[CanFrame]

# ==========================================
# MÓDULO 1: HEARTBEAT E MÁQUINA DE ESTADOS
# ==========================================
@app.post("/api/heartbeat", summary="Recebe o pulso do Frontend (Dashboard)")
async def receive_heartbeat():
    SYSTEM_STATE["last_heartbeat_time"] = time.time()
    SYSTEM_STATE["user_is_monitoring"] = True
    return {"status": "alive", "timestamp": SYSTEM_STATE["last_heartbeat_time"]}

@app.get("/api/status", summary="ESP32 Consulta o Status da Operação")
async def check_system_status() -> HeartbeatResponse:
    current_time = time.time()
    time_since_last_pulse = current_time - SYSTEM_STATE["last_heartbeat_time"]
    
    # Se passou do timeout, o usuário fechou a aba (Desativa o Streaming)
    if time_since_last_pulse > SYSTEM_STATE["timeout_seconds"]:
        SYSTEM_STATE["user_is_monitoring"] = False
        
    return HeartbeatResponse(
        status="ok",
        user_is_monitoring=SYSTEM_STATE["user_is_monitoring"]
    )

# ==========================================
# MÓDULO 2: SNIFFING EM TEMPO REAL
# ==========================================
@app.post("/signals", summary="ESP32 envia frames CAN em tempo real (Streaming)")
async def upload_live_signals(payload: LiveSignalsPayload):
    truck = payload.truck_id
    if truck not in live_signals_db:
        live_signals_db[truck] = {}

    for frame in payload.frames:
        live_signals_db[truck][frame.id] = frame.dict()

    return {"status": "success", "processed_frames": len(payload.frames)}

@app.get("/signals", summary="Frontend consome frames em tempo real")
async def get_live_signals(truck_id: str = "Volvo FH540 (Sniffer 01)"):
    if truck_id in live_signals_db:
        return {"status": "success", "data": live_signals_db[truck_id]}
    return {"status": "empty", "data": {}}

# ==========================================
# MÓDULO 3: EDR / CAIXA PRETA (SUPABASE)
# ==========================================
@app.post("/api/blackbox/upload", summary="ESP32 Envia o Log Pós-Falha (Bulk Upload)")
def upload_blackbox_log(payload: BlackboxUpload):
    log_id = f"log_caixa_preta_{str(uuid.uuid4())[:8]}"
    
    # Prepara o resumo que vai aparecer no mapa/dashboard
    event_summary = {
        "name": f"{payload.metadata.truck_id} ({payload.metadata.trigger_event})",
        "value": [payload.metadata.lon, payload.metadata.lat, 1], 
        "itemStyle": {"color": "#ef4444"},
        "isAlert": True,
        "logId": log_id,
        "timestamp": payload.metadata.timestamp
    }
    
    # Estrutura o registro completo
    record = {
        "log_id": log_id,
        "event_summary": event_summary,
        "payload": payload.dict()
    }
    
    try:
        # Conecta e insere no PostgreSQL
        conn = psycopg2.connect(DATABASE_URL)
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
    
    return {"status": "success", "log_id": log_id, "message": "Caixa preta armazenada no Supabase."}

@app.get("/api/blackbox/events", summary="Frontend Solicita Pontos do Mapa")
def get_blackbox_events():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        cursor.execute("SELECT payload FROM blackbox_logs ORDER BY created_at DESC")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        
        events = [row[0]["event_summary"] for row in rows]
        return {"events": events}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao buscar eventos: {str(e)}")

@app.get("/api/blackbox/download/{log_id}", summary="Frontend Baixa o Arquivo Completo")
def download_blackbox_log(log_id: str):
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        cursor.execute("SELECT payload FROM blackbox_logs WHERE payload->>'log_id' = %s", (log_id,))
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not row:
            raise HTTPException(status_code=404, detail="Log não encontrado no servidor.")
        
        return row[0]["payload"]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao baixar log: {str(e)}")
