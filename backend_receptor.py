import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import uvicorn

app = FastAPI(title="CANalyzer Pro Cloud Receiver")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# MODELOS DE DADOS (SCHEMA J1939 SNAPSHOT)
# Valida a estrutura recebida para evitar que dados parciais quebrem o frontend
# =============================================================================
class CANFrame(BaseModel):
    timestamp_ms: Optional[int] = None
    can_id: str                 # Chave atualizada para refletir o ESP32 Sniffer
    priority: Optional[int] = None
    pgn: Optional[int] = None
    sender: str
    receiver: Optional[str] = None
    dlc: Optional[int] = None
    payload: str

class Payload(BaseModel):
    frames: List[CANFrame]

# Buffer na memória para armazenar a última foto do barramento CAN
latest_truck_data = {"frames": []}

@app.post("/signals_upload")
async def upload_signals(payload: Payload):
    global latest_truck_data
    try:
        # Pydantic V2 usa model_dump(), se usar V1 substitua por payload.dict()
        latest_truck_data = payload.model_dump() if hasattr(payload, 'model_dump') else payload.dict()
        
        print(f"📦 Pacote J1939 recebido: {len(latest_truck_data.get('frames', []))} frames únicos.")
        return {"status": "success", "msg": "Dados gravados no buffer"}
    except Exception as e:
        print(f"❌ Erro no processamento do payload: {e}")
        return {"status": "error", "msg": str(e)}

@app.get("/signals/")
def get_can_bus_data():
    return latest_truck_data

if __name__ == "__main__":
    # Lê a porta dinâmica da nuvem ou usa a 8055 como fallback local
    port = int(os.environ.get("PORT", 8055))
    uvicorn.run(app, host="0.0.0.0", port=port)
