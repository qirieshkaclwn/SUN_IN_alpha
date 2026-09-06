"""
Точка входа сервера SUN_IN на WebSocket и Protobuf.
"""
import argparse
import asyncio
import logging
import os
import sys
import websockets

# Гарантируем видимость proto и server при прямом запуске
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from server.protocol import (
        PacketType,
        create_pong,
        create_auth_challenge,
        create_auth_success,
        create_auth_fail,
        create_user_list_resp,
        create_msg_direct,
        create_error,
        deserialize_packet,
        serialize_packet,
    )
    from server.auth import AuthManager
except ImportError:
    from protocol import (
        PacketType,
        create_pong,
        create_auth_challenge,
        create_auth_success,
        create_auth_fail,
        create_user_list_resp,
        create_msg_direct,
        create_error,
        deserialize_packet,
        serialize_packet,
    )
    from auth import AuthManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("SUN_IN.Server")

# Менеджер аутентификации и сессий
AUTH_MANAGER = AuthManager()

# Пользователи онлайн: nickname -> websocket
ONLINE_USERS = {}

# Сессии: websocket -> {"nickname": str, "user_id": str, "session_token": str}
ACTIVE_SESSIONS = {}


async def broadcast_user_list():
    """Рассылает всем клиентам актуальный список пользователей в сети (контактов)."""
    users = list(ONLINE_USERS.keys())
    pkt = create_user_list_resp(users)
    data = serialize_packet(pkt)
    dead = []
    for nick, ws in list(ONLINE_USERS.items()):
        try:
            await ws.send(data)
        except Exception:
            dead.append(nick)
    for d in dead:
        ONLINE_USERS.pop(d, None)


async def handle_websocket(websocket):
    peer = websocket.remote_address
    logger.info(f"Новое подключение: {peer}")
    session = {"nickname": "", "user_id": "", "session_token": ""}
    ACTIVE_SESSIONS[websocket] = session
    pending_nonce = None

    try:
        async for message in websocket:
            if not isinstance(message, bytes):
                logger.warning(f"Получено небинарное сообщение от {peer}")
                continue

            packet = deserialize_packet(message)
            packet_type_name = PacketType.Name(packet.type)
            sender_nick = session["nickname"] or "unauthorized"
            logger.info(f"Пакет от {sender_nick}: {packet_type_name} (seq={packet.seq_id})")

            # 1. PING
            if packet.type == PacketType.PING:
                pong = create_pong(sender="server", seq_id=packet.seq_id)
                await websocket.send(serialize_packet(pong))

            # 2. АВТОРИЗАЦИЯ И РЕГИСТРАЦИЯ
            elif packet.type == PacketType.AUTH_INIT:
                nick = packet.auth_init.nickname.strip()
                token = packet.auth_init.token.strip()

                # Режим Challenge-Response по запросу клиента
                if token == "__challenge__":
                    nonce, err_msg = AUTH_MANAGER.create_challenge(nick)
                    if not nonce:
                        resp = create_auth_fail(reason=err_msg, seq_id=packet.seq_id)
                        await websocket.send(serialize_packet(resp))
                        continue
                    pending_nonce = nonce
                    resp = create_auth_challenge(nonce=nonce, seq_id=packet.seq_id)
                    await websocket.send(serialize_packet(resp))
                    continue

                res = AUTH_MANAGER.register_or_login(nick, token)
                if not res.success:
                    logger.warning(f"Отказ в авторизации для '{nick}': {res.message}")
                    resp = create_auth_fail(reason=res.message, seq_id=packet.seq_id)
                    await websocket.send(serialize_packet(resp))
                    continue

                # Если этот же пользователь уже подключен с другого сокета — уведомляем и заменяем сессию
                old_ws = ONLINE_USERS.get(res.nickname)
                if old_ws and old_ws != websocket:
                    try:
                        err_pkt = create_error(code=409, message="Выполнен вход с другого устройства", seq_id=0)
                        await old_ws.send(serialize_packet(err_pkt))
                        await old_ws.close()
                    except Exception:
                        pass

                session["nickname"] = res.nickname
                session["user_id"] = res.user_id
                session["session_token"] = res.session_token
                ONLINE_USERS[res.nickname] = websocket

                logger.info(f"Успешная авторизация: @{res.nickname} (id={res.user_id})")
                resp = create_auth_success(
                    user_id=res.user_id,
                    nickname=res.nickname,
                    message=res.message,
                    seq_id=packet.seq_id,
                )
                await websocket.send(serialize_packet(resp))
                await broadcast_user_list()

            # 2.1 КРИПТОГРАФИЧЕСКИЙ ОТВЕТ НА CHALLENGE
            elif packet.type == PacketType.AUTH_PROOF:
                if not pending_nonce:
                    resp = create_auth_fail(reason="Challenge не был запрошен", seq_id=packet.seq_id)
                    await websocket.send(serialize_packet(resp))
                    continue

                proof = packet.auth_proof.proof
                res = AUTH_MANAGER.verify_proof(pending_nonce, proof)
                pending_nonce = None

                if not res.success:
                    logger.warning(f"Ошибка проверки proof: {res.message}")
                    resp = create_auth_fail(reason=res.message, seq_id=packet.seq_id)
                    await websocket.send(serialize_packet(resp))
                    continue

                old_ws = ONLINE_USERS.get(res.nickname)
                if old_ws and old_ws != websocket:
                    try:
                        await old_ws.close()
                    except Exception:
                        pass

                session["nickname"] = res.nickname
                session["user_id"] = res.user_id
                session["session_token"] = res.session_token
                ONLINE_USERS[res.nickname] = websocket

                logger.info(f"Успешная Challenge-Response авторизация: @{res.nickname} (id={res.user_id})")
                resp = create_auth_success(
                    user_id=res.user_id,
                    nickname=res.nickname,
                    message=res.message,
                    seq_id=packet.seq_id,
                )
                await websocket.send(serialize_packet(resp))
                await broadcast_user_list()

            # 3. ЗАПРОС СПИСКА ПОЛЬЗОВАТЕЛЕЙ (ДИАЛОГОВ)
            elif packet.type == PacketType.USER_LIST_REQ:
                if not session["nickname"]:
                    err = create_error(code=401, message="Требуется авторизация", seq_id=packet.seq_id)
                    await websocket.send(serialize_packet(err))
                    continue

                users = list(ONLINE_USERS.keys())
                resp = create_user_list_resp(users, seq_id=packet.seq_id)
                await websocket.send(serialize_packet(resp))

            # 4. ЛИЧНОЕ СООБЩЕНИЕ 1-НА-1 (DIRECT MESSAGE)
            elif packet.type == PacketType.MSG_DIRECT:
                if not session["nickname"]:
                    err = create_error(code=401, message="Требуется авторизация", seq_id=packet.seq_id)
                    await websocket.send(serialize_packet(err))
                    continue

                to_user = packet.msg_direct.to_user.strip()
                text = packet.msg_direct.text.strip()
                from_user = session["nickname"]

                if not text:
                    continue

                # Формируем пакет прямого сообщения
                dm_pkt = create_msg_direct(from_user=from_user, to_user=to_user, text=text, seq_id=packet.seq_id)
                data = serialize_packet(dm_pkt)

                # Доставляем получателю, если он онлайн
                target_ws = ONLINE_USERS.get(to_user)
                if target_ws:
                    try:
                        await target_ws.send(data)
                    except Exception:
                        ONLINE_USERS.pop(to_user, None)

                # Эхо отправителю (подтверждение доставки / отображение в диалоге)
                await websocket.send(data)

    except websockets.exceptions.ConnectionClosed:
        logger.info(f"Соединение закрыто: {session['nickname'] or 'неавторизован'} ({peer})")
    except Exception as e:
        logger.error(f"Ошибка при обработке {peer}: {e}")
    finally:
        nick = session.get("nickname")
        if nick and nick in ONLINE_USERS and ONLINE_USERS[nick] == websocket:
            del ONLINE_USERS[nick]
            asyncio.create_task(broadcast_user_list())
        ACTIVE_SESSIONS.pop(websocket, None)



async def main():
    parser = argparse.ArgumentParser(description="SUN_IN Server (WebSocket/Protobuf)")
    parser.add_argument("--host", default="0.0.0.0", help="Хост для прослушивания (по умолчанию 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8765, help="Порт (по умолчанию 8765)")
    args = parser.parse_args()

    async with websockets.serve(handle_websocket, args.host, args.port):
        logger.info(f"Сервер SUN_IN (WebSocket) запущен на ws://{args.host}:{args.port}")
        await asyncio.Future()  # бесконечный цикл


if __name__ == "__main__":
    asyncio.run(main())

