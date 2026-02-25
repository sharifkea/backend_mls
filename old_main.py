# main.py
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Response
from fastapi.responses import PlainTextResponse
from fastapi import FastAPI, WebSocket, Body
from typing import Dict

app = FastAPI(title="MLS Chat Backend")
# In-memory storage (replace with SQLite/DB later)
key_packages: Dict[str, bytes] = {}  # user_id → serialized KeyPackage

@app.get("/")
async def root():
    return PlainTextResponse("MLS chat backend starting... (step 0)")

@app.websocket("/ws/test")
async def websocket_test(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            print(f"Received: {data}")
            await websocket.send_text(f"Echo: {data}")
    except WebSocketDisconnect:
        print("Client disconnected")

@app.post("/key_packages/{user_id}")
async def upload_keypackage(user_id: str, data: bytes = Body(...)):
    key_packages[user_id] = data
    print(f"Received KeyPackage for {user_id} ({len(data)} bytes)")
    return {"status": "uploaded", "size": len(data)}

@app.get("/key_packages/{user_id}")
async def get_keypackage(user_id: str):
    if user_id not in key_packages:
        return {"error": "Not found"}
    return Response(
        content=key_packages[user_id],
        media_type="application/octet-stream"
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

