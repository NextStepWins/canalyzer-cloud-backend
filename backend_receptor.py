import os
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI(title="CANalyzer Pro Cloud Receiver")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Buffer na memória para armazenar a última foto do barramento CAN
latest_truck_data = {"frames": []}

@app.post("/signals_upload")
async def upload_signals(request: Request):
    global latest_truck_data
    try:
        data = await request.json()
        latest_truck_data = data
        print(f"📦 Pacote recebido: {len(data.get('frames', []))} frames únicos.")
        return {"status": "success", "msg": "Dados gravados no buffer"}
    except Exception as e:
        print(f"❌ Erro no payload: {e}")
        return {"status": "error", "msg": str(e)}

@app.get("/signals/")
def get_can_bus_data():
    return latest_truck_data

if __name__ == "__main__":
    # Lê a porta dinâmica da nuvem ou usa a 8055 como fallback local
    port = int(os.environ.get("PORT", 8055))
    uvicorn.run(app, host="0.0.0.0", port=port)