"""
Тесты для проверки реального запущенного сервера SUN_IN.
Запуск: python tests/test_live_server.py
или: uv run python tests/test_live_server.py
"""
import asyncio
import os
import random
import string
import sys
import unittest
import websockets

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from server.protocol import (
    PacketType,
    create_ping,
    create_auth_init,
    create_msg_direct,
    create_user_list_req,
    deserialize_packet,
    serialize_packet,
)


def random_nick(prefix="user"):
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{prefix}_{suffix}"


async def find_sun_in_server():
    """Находит доступный URI сервера SUN_IN (проверяет порт из env, затем 8888 и 8765)."""
    explicit = os.getenv("SUN_IN_SERVER_URI")
    candidates = [explicit] if explicit else ["ws://127.0.0.1:8888", "ws://127.0.0.1:8765"]

    for uri in candidates:
        try:
            async with websockets.connect(uri) as ws:
                ping = create_ping(sender="probe", seq_id=1)
                await ws.send(serialize_packet(ping))
                data = await asyncio.wait_for(ws.recv(), timeout=1.0)
                if isinstance(data, bytes):
                    pkt = deserialize_packet(data)
                    if pkt.type == PacketType.PONG:
                        return uri
        except Exception:
            continue
    return explicit or "ws://127.0.0.1:8888"


class TestLiveServer(unittest.IsolatedAsyncioTestCase):
    """Набор тестов, подключающихся к работающему экземпляру server/main.py."""

    async def asyncSetUp(self):
        self.server_uri = await find_sun_in_server()
        try:
            async with websockets.connect(self.server_uri) as ws:
                ping = create_ping(sender="health_check", seq_id=1)
                await ws.send(serialize_packet(ping))
                data = await asyncio.wait_for(ws.recv(), timeout=1.5)
                if not isinstance(data, bytes):
                    self.skipTest(f"На {self.server_uri} отвечает сторонний сервис. Запустите: python server/main.py --port 8888")
        except Exception as e:
            self.skipTest(f"Сервер SUN_IN не запущен на {self.server_uri}. Запустите: python server/main.py --port 8888 ({e})")

    async def test_live_ping_pong(self):
        """Проверка PING/PONG на живом сервере."""
        async with websockets.connect(self.server_uri) as ws:
            ping = create_ping(sender="live_tester", seq_id=777)
            await ws.send(serialize_packet(ping))

            resp_raw = await asyncio.wait_for(ws.recv(), timeout=3.0)
            self.assertIsInstance(resp_raw, bytes, "Сервер должен отвечать бинарным Protobuf")
            resp = deserialize_packet(resp_raw)

            self.assertEqual(resp.type, PacketType.PONG)
            self.assertEqual(resp.seq_id, 777)
            self.assertEqual(resp.pong.sender, "server")

    async def test_live_auto_registration_and_login(self):
        """Проверка регистрации и входа на живом сервере."""
        nick = random_nick("live_u")

        # 1. Регистрация без пароля (автоматический токен)
        async with websockets.connect(self.server_uri) as ws:
            req = create_auth_init(nickname=nick, token="", seq_id=1)
            await ws.send(serialize_packet(req))

            resp_raw = await asyncio.wait_for(ws.recv(), timeout=3.0)
            resp = deserialize_packet(resp_raw)

            self.assertEqual(resp.type, PacketType.AUTH_SUCCESS)
            self.assertEqual(resp.auth_success.nickname, nick)

            import re
            match = re.search(r"токен:\s*([^\s]+)", resp.auth_success.message)
            self.assertIsNotNone(match, "Сервер должен вернуть сгенерированный токен")
            token = match.group(1)

        # 2. Повторный вход с выданным токеном
        async with websockets.connect(self.server_uri) as ws:
            req = create_auth_init(nickname=nick, token=token, seq_id=2)
            await ws.send(serialize_packet(req))

            resp_raw = await asyncio.wait_for(ws.recv(), timeout=3.0)
            resp = deserialize_packet(resp_raw)

            self.assertEqual(resp.type, PacketType.AUTH_SUCCESS)
            self.assertEqual(resp.auth_success.nickname, nick)

    async def test_live_direct_messaging(self):
        """Проверка обмена сообщениями между двумя реальными клиентами на живом сервере."""
        alice_nick = random_nick("alice")
        bob_nick = random_nick("bob")

        async with websockets.connect(self.server_uri) as ws_alice, websockets.connect(self.server_uri) as ws_bob:
            # Вход Алисы
            await ws_alice.send(serialize_packet(create_auth_init(nickname=alice_nick, token="", seq_id=1)))
            r1 = deserialize_packet(await ws_alice.recv())
            self.assertEqual(r1.type, PacketType.AUTH_SUCCESS)

            # Вход Боба
            await ws_bob.send(serialize_packet(create_auth_init(nickname=bob_nick, token="", seq_id=1)))
            r2 = deserialize_packet(await ws_bob.recv())
            self.assertEqual(r2.type, PacketType.AUTH_SUCCESS)

            # Отправка сообщения
            test_text = "Тестовое сообщение в живой сервер!"
            dm = create_msg_direct(from_user=alice_nick, to_user=bob_nick, text=test_text, seq_id=10)
            await ws_alice.send(serialize_packet(dm))

            # Боб принимает сообщение
            received = None
            for _ in range(5):
                data = await asyncio.wait_for(ws_bob.recv(), timeout=3.0)
                pkt = deserialize_packet(data)
                if pkt.type == PacketType.MSG_DIRECT and pkt.msg_direct.from_user == alice_nick:
                    received = pkt.msg_direct
                    break

            self.assertIsNotNone(received, "Боб должен получить сообщение от Алисы")
            self.assertEqual(received.text, test_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
