from fastapi import FastAPI, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any
import time
import uuid

app = FastAPI(title="CANalyzer Pro Backend - EDR / Sentinel Mode")

# Configuração de CORS para permitir que seu Streamlit (Frontend) converse com o Render
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# VARIÁVEIS DE ESTADO (MEMÓRIA TEMPORÁRIA)
# ==========================================
# NOTA: O Render gratuito tem armazenamento efêmero. Se o servidor reiniciar, essas variáveis zeram.
# No futuro, integraremos isso a um MongoDB (Atlas) ou AWS S3 / Firebase Storage.

SYSTEM_STATE = {
    "last_heartbeat_time": 0.0,
    "user_is_monitoring": False,
    "timeout_seconds": 10.0 # Se o dashboard não der 'oi' em 10s, o ESP32 entra em modo sentinela
}

# Armazena os eventos de caixa preta recebidos
blackbox_events_db = []
# Armazena os arquivos JSON pesados associados a cada evento
blackbox_logs_db = {} 

# ==========================================
# MODELOS DE DADOS (Pydantic)
# ==========================================
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
    log: List[Dict[str, Any]] # O buffer circular gigante de sinais

# ==========================================
# ROTAS 1: HEARTBEAT & CONTROLE DE ESTADO
# ==========================================
@app.post("/api/heartbeat", summary="Recebe o pulso do Frontend (Dashboard)")
async def receive_heartbeat():
    """
    O Frontend em Streamlit deve chamar essa rota a cada 5 segundos
    enquanto a aba 'ONLINE' estiver aberta.
    """
    SYSTEM_STATE["last_heartbeat_time"] = time.time()
    SYSTEM_STATE["user_is_monitoring"] = True
    return {"status": "alive", "timestamp": SYSTEM_STATE["last_heartbeat_time"]}

@app.get("/api/status", summary="ESP32 Consulta o Status da Operação")
async def check_system_status() -> HeartbeatResponse:
    """
    O ESP32-S3 chama essa rota. Se retornar user_is_monitoring=False,
    ele para de enviar via 4G e ativa o Modo Sentinela (Buffer Circular em PSRAM).
    """
    current_time = time.time()
    time_since_last_pulse = current_time - SYSTEM_STATE["last_heartbeat_time"]
    
    # Se passou do timeout, o usuário fechou a aba ou perdeu conexão
    if time_since_last_pulse > SYSTEM_STATE["timeout_seconds"]:
        SYSTEM_STATE["user_is_monitoring"] = False
        
    return HeartbeatResponse(
        status="ok",
        user_is_monitoring=SYSTEM_STATE["user_is_monitoring"]
    )

# ==========================================
# ROTAS 2: EDR / CAIXA PRETA
# ==========================================
@app.post("/api/blackbox/upload", summary="ESP32 Envia o Log Pós-Falha (Bulk Upload)")
async def upload_blackbox_log(payload: BlackboxUpload):
    """
    Recebe o arquivo JSON denso contendo X minutos antes e depois da falha.
    """
    log_id = f"log_caixa_preta_{str(uuid.uuid4())[:8]}"
    
    # Monta o resumo que vai para o Mapa no frontend
    event_summary = {
        "name": f"{payload.metadata.truck_id} ({payload.metadata.trigger_event})",
        "value": [payload.metadata.lon, payload.metadata.lat, 1], # ECharts usa [Lon, Lat]
        "itemStyle": {"color": "#ef4444"},
        "isAlert": True,
        "logId": log_id,
        "timestamp": payload.metadata.timestamp
    }
    
    # Salva na memória do servidor
    blackbox_events_db.append(event_summary)
    blackbox_logs_db[log_id] = payload.dict()
    
    return {"status": "success", "log_id": log_id, "message": "Caixa preta armazenada com sucesso."}

@app.get("/api/blackbox/events", summary="Frontend Solicita Pontos do Mapa")
async def get_blackbox_events():
    """
    Retorna a lista de caminhões e falhas para renderizar no GeoJSON.
    """
    return {"events": blackbox_events_db}

@app.get("/api/blackbox/download/{log_id}", summary="Frontend Baixa o Arquivo Completo")
async def download_blackbox_log(log_id: str):
    """
    Retorna o JSON completo da caixa preta para o usuário analisar no Dashboard.
    """
    if log_id not in blackbox_logs_db:
        raise HTTPException(status_code=404, detail="Log não encontrado no servidor.")
    
    return blackbox_logs_db[log_id]
