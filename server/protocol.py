"""
Протокол SUN_IN на базе Protocol Buffers.
Серверные вспомогательные методы для создания и распаковки пакетов.
"""
import time
from typing import Optional

from proto import protocol_pb2 as pb
from proto.protocol_pb2 import Packet, PacketType

PROTOCOL_VERSION = 1


def create_packet(packet_type: PacketType, seq_id: int = 0, timestamp: Optional[int] = None) -> Packet:
    """Создает базовый Protobuf Packet."""
    return Packet(
        version=PROTOCOL_VERSION,
        seq_id=seq_id,
        timestamp=timestamp if timestamp is not None else int(time.time() * 1000),
        type=packet_type,
    )


def create_ping(sender: str, seq_id: int = 0) -> Packet:
    """Создает пакет PING."""
    pkt = create_packet(PacketType.PING, seq_id=seq_id)
    pkt.ping.sender = sender
    return pkt


def create_pong(sender: str, seq_id: int = 0) -> Packet:
    """Создает пакет PONG."""
    pkt = create_packet(PacketType.PONG, seq_id=seq_id)
    pkt.pong.sender = sender
    return pkt


def create_error(code: int, message: str, seq_id: int = 0) -> Packet:
    """Создает пакет с ошибкой."""
    pkt = create_packet(PacketType.ERROR, seq_id=seq_id)
    pkt.error.code = code
    pkt.error.message = message
    return pkt


def create_msg_direct(from_user: str, to_user: str, text: str, seq_id: int = 0) -> Packet:
    """Создает пакет прямого сообщения."""
    pkt = create_packet(PacketType.MSG_DIRECT, seq_id=seq_id)
    pkt.msg_direct.from_user = from_user
    pkt.msg_direct.to_user = to_user
    pkt.msg_direct.text = text
    return pkt
def create_msg_ack(msg_seq_id: int, delivered: bool = True, seq_id: int = 0) -> Packet:
    """Создает подтверждение доставки сообщения."""
    pkt = create_packet(PacketType.MSG_ACK, seq_id=seq_id)
    pkt.msg_ack.msg_seq_id = msg_seq_id
    pkt.msg_ack.delivered = delivered
    return pkt

def create_auth_init(nickname: str, token: str = "", seq_id: int = 0) -> Packet:
    """Создает запрос на авторизацию / регистрацию."""
    pkt = create_packet(PacketType.AUTH_INIT, seq_id=seq_id)
    pkt.auth_init.nickname = nickname
    pkt.auth_init.token = token
    return pkt


def create_auth_challenge(nonce: bytes, seq_id: int = 0) -> Packet:
    """Создает вызов авторизации (challenge)."""
    pkt = create_packet(PacketType.AUTH_CHALLENGE, seq_id=seq_id)
    pkt.auth_challenge.nonce = nonce
    return pkt


def create_auth_proof(proof: bytes, seq_id: int = 0) -> Packet:
    """Создает криптографическое подтверждение (proof) вызова."""
    pkt = create_packet(PacketType.AUTH_PROOF, seq_id=seq_id)
    pkt.auth_proof.proof = proof
    return pkt


def create_auth_success(user_id: str, nickname: str, message: str = "Auth successful", seq_id: int = 0) -> Packet:
    """Создает успешный ответ авторизации."""
    pkt = create_packet(PacketType.AUTH_SUCCESS, seq_id=seq_id)
    pkt.auth_success.user_id = user_id
    pkt.auth_success.nickname = nickname
    pkt.auth_success.message = message
    return pkt


def create_auth_fail(reason: str, seq_id: int = 0) -> Packet:
    """Создает ответ о неудачной авторизации."""
    pkt = create_packet(PacketType.AUTH_FAIL, seq_id=seq_id)
    pkt.auth_fail.reason = reason
    return pkt


def create_user_list_resp(users: list, seq_id: int = 0) -> Packet:
    """Создает ответ со списком пользователей."""
    pkt = create_packet(PacketType.USER_LIST_RESP, seq_id=seq_id)
    pkt.user_list_resp.users.extend(users)
    return pkt


def create_chat_list_resp(chats: list, seq_id: int = 0) -> Packet:
    """Создает ответ со списком чатов."""
    pkt = create_packet(PacketType.CHAT_LIST_RESP, seq_id=seq_id)
    for c in chats:
        chat_item = pkt.chat_list_resp.chats.add()
        chat_item.chat_id = c["chat_id"]
        chat_item.name = c["name"]
        chat_item.member_count = c.get("member_count", 0)
    return pkt


def create_chat_join_resp(chat_id: str, success: bool = True, message: str = "Joined", seq_id: int = 0) -> Packet:
    """Создает ответ на вход в чат."""
    pkt = create_packet(PacketType.CHAT_JOIN_RESP, seq_id=seq_id)
    pkt.chat_join_resp.chat_id = chat_id
    pkt.chat_join_resp.success = success
    pkt.chat_join_resp.message = message
    return pkt


def create_chat_msg(chat_id: str, from_user: str, text: str, seq_id: int = 0) -> Packet:
    """Создает сообщение в групповой чат."""
    pkt = create_packet(PacketType.CHAT_MSG, seq_id=seq_id)
    pkt.chat_msg.chat_id = chat_id
    pkt.chat_msg.from_user = from_user
    pkt.chat_msg.text = text
    return pkt



def serialize_packet(packet: Packet) -> bytes:
    """Сериализует пакет в бинарный protobuf."""
    return packet.SerializeToString()


def deserialize_packet(data: bytes) -> Packet:
    """Десериализует protobuf байты в Packet."""
    packet = Packet()
    packet.ParseFromString(data)
    return packet

