"""
Интеграционный тест взаимодействия клиента и сервера через WebSocket и Protobuf.
"""
import asyncio
import os
import sys
import unittest
import websockets

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from server.protocol import (
    PacketType,
    create_ping,
    create_auth_init,
    create_msg_direct,
    deserialize_packet,
    serialize_packet,
)
from server.main import handle_websocket


class TestClientServerWebSocket(unittest.IsolatedAsyncioTestCase):
    async def test_ping_pong_exchange(self):
        # Запускаем локальный WebSocket сервер
        async with websockets.serve(handle_websocket, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]

            # Подключаемся клиентом по ws://
            uri = f"ws://127.0.0.1:{port}"
            async with websockets.connect(uri) as websocket:
                # Отправляем PING
                ping = create_ping(sender="test_user", seq_id=123)
                await websocket.send(serialize_packet(ping))

                # Принимаем PONG
                data = await websocket.recv()
                response = deserialize_packet(data)

                # Проверяем ответ
                self.assertEqual(response.type, PacketType.PONG)
                self.assertEqual(response.seq_id, 123)
                self.assertEqual(response.pong.sender, "server")
    async def test_auth_registration_and_login(self):
        """Тест регистрации и повторного входа через WebSocket."""
        async with websockets.serve(handle_websocket, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            uri = f"ws://127.0.0.1:{port}"

            async with websockets.connect(uri) as websocket:
                # 1. Регистрация нового пользователя 'alice_test'
                auth_req = create_auth_init(nickname="alice_test", token="alice_pass_999", seq_id=1)
                await websocket.send(serialize_packet(auth_req))

                resp_raw = await websocket.recv()
                resp = deserialize_packet(resp_raw)
                self.assertEqual(resp.type, PacketType.AUTH_SUCCESS)
                self.assertEqual(resp.auth_success.nickname, "alice_test")
                self.assertTrue(resp.auth_success.user_id.startswith("usr_"))

            # 2. Повторное подключение с неверным паролем
            async with websockets.connect(uri) as websocket:
                bad_auth = create_auth_init(nickname="alice_test", token="wrong_pass", seq_id=2)
                await websocket.send(serialize_packet(bad_auth))

                resp_raw = await websocket.recv()
                resp = deserialize_packet(resp_raw)
                self.assertEqual(resp.type, PacketType.AUTH_FAIL)
                self.assertIn("Неверный токен или пароль", resp.auth_fail.reason)

            # 3. Повторное подключение с верным паролем
            async with websockets.connect(uri) as websocket:
                good_auth = create_auth_init(nickname="alice_test", token="alice_pass_999", seq_id=3)
                await websocket.send(serialize_packet(good_auth))

                resp_raw = await websocket.recv()
                resp = deserialize_packet(resp_raw)
                self.assertEqual(resp.type, PacketType.AUTH_SUCCESS)
                self.assertEqual(resp.auth_success.nickname, "alice_test")

    async def test_unauthorized_rejection(self):
        """Тест отклонения запросов от неавторизованного клиента."""
        async with websockets.serve(handle_websocket, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            uri = f"ws://127.0.0.1:{port}"

            async with websockets.connect(uri) as websocket:
                # Попытка отправить сообщение без авторизации
                dm = create_msg_direct(from_user="intruder", to_user="bob", text="Hi", seq_id=5)
                await websocket.send(serialize_packet(dm))

                resp_raw = await websocket.recv()
                resp = deserialize_packet(resp_raw)
                self.assertEqual(resp.type, PacketType.ERROR)
                self.assertEqual(resp.error.code, 401)


if __name__ == "__main__":
    unittest.main()

