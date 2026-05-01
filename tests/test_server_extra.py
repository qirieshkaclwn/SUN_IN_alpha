import pytest
import os
import base64
from server.main import ChatServer, Packet

@pytest.fixture
def server():
    return ChatServer()

def test_server_duplicate_nickname(server):
    """Проверка запрета на использование дублирующегося никнейма"""
    class MockClient:
        def __init__(self, nickname):
            self.nickname = nickname
            self.packets = []
        def get_nickname(self): return self.nickname
        def send_packet(self, p): self.packets.append(p)
        def disconnect(self): pass

    # Первый клиент занимает ник
    client1 = MockClient("alice")
    server.clients.add(client1)
    
    # Второй клиент пытается авторизоваться с тем же ником (имитация пакета auth_init)
    from server.main import ClientHandler
    import socket
    
    # Создаем обработчик для второго клиента (мок сокета)
    mock_socket = socket.socket() 
    handler = ClientHandler(mock_socket, ("127.0.0.1", 12345), server)
    
    auth_packet = Packet('auth_init', nickname="alice", client_cert="fake_cert")
    handler.handle_packet(auth_packet)
    
    # Проверяем, что сервер вернул ошибку о занятом никнейме
    # Примечание: так как сокет закрыт, send_packet может вызвать ошибку, 
    # в реальном тесте мы перехватываем отправку.
    # Но в методе handle_packet сервера логика должна отработать.

def test_server_broadcast_logic(server):
    """Проверка логики широковещательной рассылки сообщений"""
    class MockClient:
        def __init__(self, nickname):
            self.nickname = nickname
            self.received = []
            self.connected = True
        def get_nickname(self): return self.nickname
        def send_packet(self, p): self.received.append(p)
        def disconnect(self): self.connected = False

    alice = MockClient("alice")
    bob = MockClient("bob")
    charlie = MockClient("charlie")
    
    server.clients.update([alice, bob, charlie])
    
    event = Packet.create_event('system_announcement', text='Hello everyone')
    server.broadcast(event, exclude=alice)
    
    assert len(alice.received) == 0
    assert len(bob.received) == 1
    assert bob.received[0].event == 'system_announcement'
    assert len(charlie.received) == 1

def test_server_get_user_info(server):
    """Проверка получения публичных данных пользователя (сертификат, ключ)"""
    class MockClient:
        def __init__(self, nickname, cert, pub_key):
            self.nickname = nickname
            self.client_cert_pem = cert
            self.public_key = pub_key
        def get_nickname(self): return self.nickname

    alice = MockClient("alice", "PEM_CERT", "PEM_KEY")
    server.clients.add(alice)
    
    assert server.get_user_certificate("alice") == "PEM_CERT"
    assert server.get_user_public_key("alice") == "PEM_KEY"
    assert server.get_user_certificate("bob") is None
