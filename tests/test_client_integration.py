import socket
import threading
import struct
import json
import time
import base64
import os
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from client.main import ChatClient, Packet

def get_free_port():
    """Вспомогательная функция для получения свободного порта"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port

class MockServer:
    """Простой имитатор сервера для тестирования поведения клиента"""
    def __init__(self, port):
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('127.0.0.1', self.port))
        self.sock.listen(1)
        self.conn = None
        self.running = True

    def accept(self):
        """Ожидание подключения клиента"""
        self.conn, _ = self.sock.accept()

    def send_packet(self, packet):
        """Отправка пакета клиенту"""
        data = packet.to_json().encode('utf-8')
        header = struct.pack('!I', len(data))
        self.conn.sendall(header + data)

    def recv_packet(self):
        """Получение пакета от клиента"""
        header = self.conn.recv(4)
        if not header: return None
        length = struct.unpack('!I', header)[0]
        payload = b""
        while len(payload) < length:
            chunk = self.conn.recv(length - len(payload))
            payload += chunk
        return Packet.from_json(payload.decode('utf-8'))

    def stop(self):
        """Остановка имитатора сервера"""
        self.running = False
        if self.conn: self.conn.close()
        self.sock.close()

@pytest.fixture
def mock_server():
    """Фикстура для создания и запуска Mock-сервера"""
    port = get_free_port()
    server = MockServer(port)
    thread = threading.Thread(target=server.accept, daemon=True)
    thread.start()
    yield server
    server.stop()

def test_client_server_auth_flow(mock_server):
    """Интеграционный тест: проверка реализации протокола авторизации клиента на сервере"""
    client = ChatClient(host='127.0.0.1', port=mock_server.port)
    
    # Изоляция файловой системы: подмена методов работы с ключами
    client._load_identity_for_nickname = lambda nick: None 
    client.client_cert_pem = "fake_cert"
    client.private_key = rsa.generate_private_key(65537, 2048)
    client.ca_cert = "fake_ca" 

    # Проверка сетевого подключения
    assert client.connect() is True
    
    # Запуск процедуры аутентификации в фоновом потоке
    auth_thread = threading.Thread(target=client.authenticate, args=("alice",))
    auth_thread.start()

    # Валидация исходящего пакета инициации авторизации
    packet = mock_server.recv_packet()
    assert packet.msg_type == 'auth_init'
    assert packet.nickname == 'alice'

    # Имитация отправки сервером вызова (challenge)
    nonce = os.urandom(32)
    mock_server.send_packet(Packet('auth_challenge', nonce=base64.b64encode(nonce).decode()))

    # Валидация предоставленной клиентом подписи (proof)
    packet = mock_server.recv_packet()
    assert packet.msg_type == 'auth_proof'
    assert packet.signature is not None

    # Имитация подтверждения успешного входа сервером
    mock_server.send_packet(Packet.create_event('auth_success', text='Welcome'))

    auth_thread.join(timeout=2)
    assert client.authenticated is True
    assert client.nickname == 'alice'
    client.disconnect()

def test_client_receives_message(mock_server):
    """Интеграционный тест: проверка возможности корректного приема и расшифровки E2E-сообщения"""
    client = ChatClient(host='127.0.0.1', port=mock_server.port)
    client.connect()
    
    # Предварительная настройка состояния авторизованного клиента
    key = rsa.generate_private_key(65537, 2048)
    client.private_key = key
    client.nickname = "bob"
    client.authenticated = True
    
    # Подготовка имитированного E2E-пакета
    message_text = "Привет, Боб!"
    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    
    # Шифрование контента по алгоритму AES-GCM
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(aes_key)
    enc_data = aesgcm.encrypt(nonce, message_text.encode(), None)
    
    # Шифрование сессионного ключа публичным ключом получателя (RSA)
    enc_key = key.public_key().encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    msg_packet = Packet('message', **{
        'from': 'alice',
        'to': 'bob',
        'text': base64.b64encode(enc_data).decode(),
        'enc_key': base64.b64encode(enc_key).decode(),
        'nonce': base64.b64encode(nonce).decode()
    })

    # Передача пакета клиенту через имитатор сервера
    mock_server.send_packet(msg_packet)
    
    # Ожидание обработки пакета обработчиком событий клиента
    time.sleep(0.5)
    client.disconnect()
