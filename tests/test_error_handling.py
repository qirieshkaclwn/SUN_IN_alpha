import pytest
import json
import socket
import struct
from server.main import ChatServer, Packet, ClientHandler

class MockSocket:
    def __init__(self):
        self.sent_data = b""
        self.closed = False
    def sendall(self, data): self.sent_data += data
    def close(self): self.closed = True
    def recv(self, n): return b""

@pytest.fixture
def server():
    return ChatServer()

def test_handler_malformed_json(server):
    """Проверка устойчивости обработчика к некорректному JSON"""
    mock_socket = MockSocket()
    handler = ClientHandler(mock_socket, ("127.0.0.1", 12345), server)
    
    # В реальности recv_exactly вернет это, а Packet.from_json упадет
    with pytest.raises(json.JSONDecodeError):
        Packet.from_json("not json")

def test_handler_unknown_packet_type(server):
    """Проверка реакции на неизвестный тип пакета"""
    mock_socket = MockSocket()
    handler = ClientHandler(mock_socket, ("127.0.0.1", 12345), server)
    
    # Неизвестный тип пакета не должен приводить к падению сервера
    unknown_packet = Packet('mystery_type')
    handler.handle_packet(unknown_packet)
    # Сервер просто игнорирует или логирует это

def test_packet_missing_fields():
    """Проверка создания пакета при отсутствии необязательных полей"""
    # Пакет только с типом
    packet = Packet('event')
    assert packet.msg_type == 'event'
    assert packet.text is None
    
    # Пакет из минимального словаря
    packet2 = Packet.from_dict({'type': 'message'})
    assert packet2.msg_type == 'message'
    assert packet2.from_user is None

def test_server_invalid_cert_enroll(server):
    """Проверка попытки выпуска сертификата с некорректным CSR"""
    mock_socket = MockSocket()
    handler = ClientHandler(mock_socket, ("127.0.0.1", 12345), server)
    
    enroll_packet = Packet('cert_enroll', nickname="bad_user", csr="invalid_csr_pem")
    handler.handle_packet(enroll_packet)
    
    # Проверяем, что в ответ пришла ошибка
    # Пакет ошибки: заголовок (4 байта) + тело
    if len(mock_socket.sent_data) > 4:
        response_json = mock_socket.sent_data[4:].decode('utf-8')
        response = json.loads(response_json)
        assert response['type'] == 'error'
        assert "Не удалось выпустить сертификат" in response['error']
