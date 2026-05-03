import asyncio
import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from chat_core import ChatClientCore

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s")
logger = logging.getLogger("WebGateway")

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"


class ConnectRequest(BaseModel):
    nickname: str = Field(min_length=1)
    host: str = "127.0.0.1"
    port: int = 8888


class SendRequest(BaseModel):
    to: str = Field(min_length=1)
    text: str = Field(min_length=1)


class ExportRequest(BaseModel):
    password: str = Field(min_length=1)


class ImportRequest(BaseModel):
    nickname: str = Field(min_length=1)
    password: str = Field(min_length=1)


class GatewayState:
    def __init__(self):
        self.lock = threading.Lock()
        self.client: ChatClientCore | None = None
        self.events: List[Dict[str, Any]] = []
        self.last_id = 0

    def push_event(self, event_type: str, payload: Dict[str, Any]):
        with self.lock:
            self.last_id += 1
            self.events.append(
                {
                    "id": self.last_id,
                    "type": event_type,
                    "payload": payload,
                }
            )

    def events_after(self, since_id: int) -> tuple[List[Dict[str, Any]], int]:
        with self.lock:
            items = [event for event in self.events if event["id"] > since_id]
            return items, self.last_id

    def clear(self):
        with self.lock:
            self.events.clear()
            self.last_id = 0


state = GatewayState()
app = FastAPI(title="SUN Web GW")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def _on_client_event(name: str, payload: Dict[str, Any]):
    state.push_event(name, payload)


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.post("/api/connect")
def connect(data: ConnectRequest):
    with state.lock:
        old_client = state.client
        state.client = None
    if old_client:
        old_client.disconnect()

    state.clear()

    client = ChatClientCore(host=data.host, port=data.port, on_event=_on_client_event)

    # Пробуем загрузить identity из файлов (мог быть импорт через /api/import_crt)
    cert_path = os.path.join(client.identities_dir, f"{data.nickname}.crt")
    key_path = os.path.join(client.identities_dir, f"{data.nickname}.key")
    if os.path.exists(cert_path) and os.path.exists(key_path):
        try:
            client._load_identity_for_nickname(data.nickname)
        except Exception:
            client = ChatClientCore(host=data.host, port=data.port, on_event=_on_client_event)

    if not client.connect():
        raise HTTPException(status_code=400, detail="Не удалось подключиться к TCP-серверу")
    if not client.authenticate(data.nickname):
        client.disconnect()
        raise HTTPException(status_code=400, detail=client.auth_error or "Ошибка авторизации")

    with state.lock:
        state.client = client
    state.push_event("status", {"text": f"Вход выполнен как {data.nickname}"})
    return {"ok": True, "nickname": data.nickname}


@app.post("/api/send")
def send(data: SendRequest):
    with state.lock:
        client = state.client
    if not client or not client.connected or not client.authenticated:
        raise HTTPException(status_code=400, detail="Клиент не подключен/не авторизован")
    ok = client.send_private_message(data.to, data.text)
    if not ok:
        raise HTTPException(status_code=400, detail="Не удалось отправить сообщение")
    state.push_event("outgoing", {"to": data.to, "text": data.text})
    return {"ok": True}


@app.post("/api/disconnect")
def disconnect():
    with state.lock:
        client = state.client
        state.client = None
    if client:
        client.disconnect()
    state.push_event("status", {"text": "Отключено"})
    return {"ok": True}


@app.post("/api/export_crt")
def export_crt(data: ExportRequest):
    with state.lock:
        client = state.client
    if not client or not client.authenticated:
        raise HTTPException(status_code=400, detail="Клиент не авторизован")
    client._export_crt(client.nickname, data.password)
    return {"ok": True}


@app.post("/api/import_crt")
def import_crt(data: ImportRequest):
    client = ChatClientCore(host="127.0.0.1", port=8888, on_event=_on_client_event)
    ok = client._import_crt(data.password, data.nickname)
    if not ok:
        raise HTTPException(status_code=400, detail="Ошибка импорта сертификата")
    return {"ok": True}


@app.get("/api/events")
def get_events(since: int = Query(default=0, ge=0)):
    events, last_id = state.events_after(since)
    return {"events": events, "last_id": last_id}


@app.get("/api/state")
def get_state():
    with state.lock:
        client = state.client
    return {
        "connected": bool(client and client.connected),
        "authenticated": bool(client and client.authenticated),
        "nickname": client.nickname if client else None,
    }


@app.websocket("/ws")
async def ws_events(websocket: WebSocket):
    await websocket.accept()
    since = 0
    try:
        while True:
            events, last_id = state.events_after(since)
            if events:
                await websocket.send_json({"events": events, "last_id": last_id})
                since = last_id
            await asyncio.sleep(0.6)
    except WebSocketDisconnect:
        return
