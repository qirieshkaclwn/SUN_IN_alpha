"""
Интеграционные тесты взаимодействия клиента и сервера через WebSocket и Protobuf.
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
    create_user_list_req,
    create_msg_direct,
    deserialize_packet,
    serialize_packet,
)
from server.main import handle_websocket


class TestClientServerWebSocket(unittest.IsolatedAsyncioTestCase):
    async def test_ping_pong_exchange(self):
        """Тест обмена PING -> PONG."""
        async with websockets.serve(handle_websocket, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            uri = f"ws://127.0.0.1:{port}"

            async with websockets.connect(uri) as websocket:
                ping = create_ping(sender="test_user", seq_id=123)
                await websocket.send(serialize_packet(ping))

                data = await websocket.recv()
                response = deserialize_packet(data)

                self.assertEqual(response.type, PacketType.PONG)
                self.assertEqual(response.seq_id, 123)
                self.assertEqual(response.pong.sender, "server")

    async def test_auth_registration_and_login(self):
        """Тест регистрации с паролем и повторного входа."""
        async with websockets.serve(handle_websocket, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            uri = f"ws://127.0.0.1:{port}"

            # 1. Регистрация нового пользователя 'alice_test'
            async with websockets.connect(uri) as websocket:
                auth_req = create_auth_init(nickname="alice_test", token="alice_pass_999", seq_id=1)
                await websocket.send(serialize_packet(auth_req))

                resp_raw = await websocket.recv()
                resp = deserialize_packet(resp_raw)
                self.assertEqual(resp.type, PacketType.AUTH_SUCCESS)
                self.assertEqual(resp.auth_success.nickname, "alice_test")
                self.assertTrue(resp.auth_success.user_id.startswith("usr_"))

            # 2. Вход с неверным паролем
            async with websockets.connect(uri) as websocket:
                bad_auth = create_auth_init(nickname="alice_test", token="wrong_pass", seq_id=2)
                await websocket.send(serialize_packet(bad_auth))

                resp_raw = await websocket.recv()
                resp = deserialize_packet(resp_raw)
                self.assertEqual(resp.type, PacketType.AUTH_FAIL)
                self.assertIn("Неверный токен или пароль", resp.auth_fail.reason)

            # 3. Вход с верным паролем
            async with websockets.connect(uri) as websocket:
                good_auth = create_auth_init(nickname="alice_test", token="alice_pass_999", seq_id=3)
                await websocket.send(serialize_packet(good_auth))

                resp_raw = await websocket.recv()
                resp = deserialize_packet(resp_raw)
                self.assertEqual(resp.type, PacketType.AUTH_SUCCESS)
                self.assertEqual(resp.auth_success.nickname, "alice_test")

    async def test_auto_generated_token_flow(self):
        """Тест автоматической генерации токена сервером при регистрации без пароля."""
        async with websockets.serve(handle_websocket, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            uri = f"ws://127.0.0.1:{port}"

            auto_nick = "user_auto_key"
            assigned_token = None

            # 1. Регистрация с пустым токеном
            async with websockets.connect(uri) as websocket:
                auth_req = create_auth_init(nickname=auto_nick, token="", seq_id=10)
                await websocket.send(serialize_packet(auth_req))

                resp_raw = await websocket.recv()
                resp = deserialize_packet(resp_raw)
                self.assertEqual(resp.type, PacketType.AUTH_SUCCESS)
                self.assertEqual(resp.auth_success.nickname, auto_nick)

                # Извлекаем токен из сообщения
                import re
                match = re.search(r"токен:\s*([^\s]+)", resp.auth_success.message)
                self.assertIsNotNone(match, "Сервер должен вернуть сгенерированный токен в сообщении")
                assigned_token = match.group(1)
                self.assertTrue(len(assigned_token) >= 20)

            # 2. Вход с полученным авто-токеном
            async with websockets.connect(uri) as websocket:
                login_req = create_auth_init(nickname=auto_nick, token=assigned_token, seq_id=11)
                await websocket.send(serialize_packet(login_req))

                resp_raw = await websocket.recv()
                resp = deserialize_packet(resp_raw)
                self.assertEqual(resp.type, PacketType.AUTH_SUCCESS)
                self.assertEqual(resp.auth_success.nickname, auto_nick)

    async def test_direct_messaging_between_two_clients(self):
        """Тест сквозного обмена сообщениями между двумя онлайн-клиентами."""
        async with websockets.serve(handle_websocket, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            uri = f"ws://127.0.0.1:{port}"

            async with websockets.connect(uri) as ws_alice, websockets.connect(uri) as ws_bob:
                # Авторизуем Alice
                await ws_alice.send(serialize_packet(create_auth_init(nickname="alice_dm", token="p1", seq_id=1)))
                resp_alice = deserialize_packet(await ws_alice.recv())
                self.assertEqual(resp_alice.type, PacketType.AUTH_SUCCESS)

                # Авторизуем Bob
                await ws_bob.send(serialize_packet(create_auth_init(nickname="bob_dm", token="p2", seq_id=1)))
                resp_bob = deserialize_packet(await ws_bob.recv())
                self.assertEqual(resp_bob.type, PacketType.AUTH_SUCCESS)

                # Alice отправляет личное сообщение для Bob
                msg_text = "Привет, Боб! Это секретное сообщение."
                dm_pkt = create_msg_direct(from_user="alice_dm", to_user="bob_dm", text=msg_text, seq_id=50)
                await ws_alice.send(serialize_packet(dm_pkt))

                # Bob должен получить сообщение
                bob_received = None
                while True:
                    data = await asyncio.wait_for(ws_bob.recv(), timeout=2.0)
                    pkt = deserialize_packet(data)
                    if pkt.type == PacketType.MSG_DIRECT:
                        bob_received = pkt.msg_direct
                        break

                self.assertIsNotNone(bob_received)
                self.assertEqual(bob_received.from_user, "alice_dm")
                self.assertEqual(bob_received.to_user, "bob_dm")
                self.assertEqual(bob_received.text, msg_text)

                # Alice получает эхо-подтверждение
                alice_echo = None
                while True:
                    data = await asyncio.wait_for(ws_alice.recv(), timeout=2.0)
                    pkt = deserialize_packet(data)
                    if pkt.type == PacketType.MSG_DIRECT:
                        alice_echo = pkt.msg_direct
                        break

                self.assertIsNotNone(alice_echo)
                self.assertEqual(alice_echo.text, msg_text)

    async def test_user_list_request_and_broadcast(self):
        """Тест запроса списка пользователей онлайн и рассылки при подключении."""
        async with websockets.serve(handle_websocket, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            uri = f"ws://127.0.0.1:{port}"

            async with websockets.connect(uri) as ws_user:
                # Вход
                await ws_user.send(serialize_packet(create_auth_init(nickname="charlie_ul", token="p3", seq_id=1)))
                await ws_user.recv()  # AUTH_SUCCESS

                # Запрос списка
                req = create_user_list_req(seq_id=5)
                await ws_user.send(serialize_packet(req))

                # Ожидаем USER_LIST_RESP
                users_resp = None
                while True:
                    data = await asyncio.wait_for(ws_user.recv(), timeout=2.0)
                    pkt = deserialize_packet(data)
                    if pkt.type == PacketType.USER_LIST_RESP:
                        users_resp = pkt.user_list_resp.users
                        break

                self.assertIn("charlie_ul", users_resp)

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

    async def test_duplicate_session_conflict_409(self):
        """Тест конфликта 409 при повторном входе с тем же никнеймом."""
        async with websockets.serve(handle_websocket, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            uri = f"ws://127.0.0.1:{port}"

            # Первое подключение
            ws1 = await websockets.connect(uri)
            await ws1.send(serialize_packet(create_auth_init(nickname="multi_user", token="m123", seq_id=1)))
            r1 = deserialize_packet(await ws1.recv())
            self.assertEqual(r1.type, PacketType.AUTH_SUCCESS)

            # Второе подключение с тем же логином
            ws2 = await websockets.connect(uri)
            await ws2.send(serialize_packet(create_auth_init(nickname="multi_user", token="m123", seq_id=1)))
            r2 = deserialize_packet(await ws2.recv())
            self.assertEqual(r2.type, PacketType.AUTH_SUCCESS)

            # ws1 должен получить ошибку 409 или быть закрыт
            err_pkt = None
            for _ in range(5):
                try:
                    err_data = await asyncio.wait_for(ws1.recv(), timeout=2.0)
                    pkt = deserialize_packet(err_data)
                    if pkt.type == PacketType.ERROR:
                        err_pkt = pkt
                        break
                except websockets.exceptions.ConnectionClosed:
                    break

            if err_pkt is not None:
                self.assertEqual(err_pkt.type, PacketType.ERROR)
                self.assertEqual(err_pkt.error.code, 409)

            await ws1.close()
            await ws2.close()


if __name__ == "__main__":
    unittest.main()
