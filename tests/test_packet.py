"""
Unit-тесты для Protobuf пакетов SUN_IN.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from server.protocol import (
    PacketType,
    create_error,
    create_msg_ack,
    create_msg_direct,
    create_ping,
    create_pong,
    deserialize_packet,
    serialize_packet,
)


class TestProtobufPacket(unittest.TestCase):
    def test_ping_pong_serialization(self):
        """Тест сериализации и десериализации PING и PONG."""
        ping = create_ping(sender="alice", seq_id=42)
        raw = serialize_packet(ping)
        self.assertIsInstance(raw, bytes)

        unpacked = deserialize_packet(raw)
        self.assertEqual(unpacked.type, PacketType.PING)
        self.assertEqual(unpacked.seq_id, 42)
        self.assertEqual(unpacked.ping.sender, "alice")

        pong = create_pong(sender="server", seq_id=42)
        raw_pong = serialize_packet(pong)
        unpacked_pong = deserialize_packet(raw_pong)
        self.assertEqual(unpacked_pong.type, PacketType.PONG)
        self.assertEqual(unpacked_pong.pong.sender, "server")

    def test_direct_message(self):
        """Тест сериализации сообщения между пользователями."""
        msg = create_msg_direct(from_user="alice", to_user="bob", text="Hello protobuf!", seq_id=10)
        raw = serialize_packet(msg)

        unpacked = deserialize_packet(raw)
        self.assertEqual(unpacked.type, PacketType.MSG_DIRECT)
        self.assertEqual(unpacked.msg_direct.from_user, "alice")
        self.assertEqual(unpacked.msg_direct.to_user, "bob")
        self.assertEqual(unpacked.msg_direct.text, "Hello protobuf!")

    def test_auth_packets_serialization(self):
        """Тест создания и десериализации пакетов авторизации."""
        from server.protocol import create_auth_init, create_auth_challenge, create_auth_proof, create_auth_success, create_auth_fail

        # AuthInit
        auth_init = create_auth_init(nickname="alice", token="my_token_123", seq_id=1)
        unpacked_init = deserialize_packet(serialize_packet(auth_init))
        self.assertEqual(unpacked_init.type, PacketType.AUTH_INIT)
        self.assertEqual(unpacked_init.auth_init.nickname, "alice")
        self.assertEqual(unpacked_init.auth_init.token, "my_token_123")

        # AuthChallenge
        challenge = create_auth_challenge(nonce=b"12345678901234567890123456789012", seq_id=2)
        unpacked_challenge = deserialize_packet(serialize_packet(challenge))
        self.assertEqual(unpacked_challenge.type, PacketType.AUTH_CHALLENGE)
        self.assertEqual(unpacked_challenge.auth_challenge.nonce, b"12345678901234567890123456789012")

        # AuthProof
        proof = create_auth_proof(proof=b"proof_signature_bytes", seq_id=3)
        unpacked_proof = deserialize_packet(serialize_packet(proof))
        self.assertEqual(unpacked_proof.type, PacketType.AUTH_PROOF)
        self.assertEqual(unpacked_proof.auth_proof.proof, b"proof_signature_bytes")

        # AuthSuccess
        success = create_auth_success(user_id="usr_123", nickname="alice", message="Welcome!", seq_id=4)
        unpacked_success = deserialize_packet(serialize_packet(success))
        self.assertEqual(unpacked_success.type, PacketType.AUTH_SUCCESS)
        self.assertEqual(unpacked_success.auth_success.user_id, "usr_123")
        self.assertEqual(unpacked_success.auth_success.nickname, "alice")

        # AuthFail
        fail = create_auth_fail(reason="Invalid password", seq_id=5)
        unpacked_fail = deserialize_packet(serialize_packet(fail))
        self.assertEqual(unpacked_fail.type, PacketType.AUTH_FAIL)
        self.assertEqual(unpacked_fail.auth_fail.reason, "Invalid password")


if __name__ == "__main__":
    unittest.main()

