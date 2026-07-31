import os
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import json

app = FastAPI(title="CANalyzer Pro Cloud Receiver")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Buffer na memória
latest_truck_data = {"frames": []}

@app.post("/signals_upload")
async def upload_signals(request: Request):
    global latest_truck_data
    try:
        # 1. Tenta ler o JSON. Se o ESP32 mandar quebrado, cai no except sem dar Erro 400.
        data = await request.json()
        
        # 2. Extrai os frames de forma segura
        frames = data.get("frames", [])
        valid_frames = []
        
        for f in frames:
            # 3. NORMALIZAÇÃO: Aceita a chave nova ('can_id') ou a velha ('id') do ESP32
            current_id = f.get("can_id") or f.get("id") or "0x00000000"
            
            valid_frames.append({
                "timestamp_ms": f.get("timestamp_ms"),
                "can_id": current_id,
                "priority": f.get("priority"),
                "pgn": f.get("pgn"),
                "sender": f.get("sender", "ESP32_WIFI"),
                "receiver": f.get("receiver", "undefined"),
                "dlc": f.get("dlc", "undefined"),
                "payload": f.get("payload", "")
            })
            
        latest_truck_data = {"frames": valid_frames}
        print(f"✅ Pacote salvo: {len(valid_frames)} frames J1939.")
        return {"status": "success", "msg": "Dados normalizados e gravados"}
        
    except json.JSONDecodeError:
        print("⚠️ Aviso: O ESP32 enviou um pacote JSON cortado/corrompido. Ignorando lote.")
        # Retorna 200 OK para o ESP32 não travar, mas não grava o lixo na memória
        return {"status": "warning", "msg": "JSON malformado"}
    except Exception as e:
        print(f"❌ Erro interno: {e}")
        return {"status": "error", "msg": str(e)}

@app.get("/signals/")
def get_can_bus_data():
    return latest_truck_data

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8055))
    uvicorn.run(app, host="0.0.0.0", port=port)
