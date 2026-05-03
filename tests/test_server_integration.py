import socket
import threading
import time
import struct
import json
import base64
import os
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from server.main import ChatServer, Packet

def get_free_port():
    """Вспомогательная функция для поиска свободного порта"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port

@pytest.fixture
def running_server():
    """Фикстура для запуска сервера в отдельном потоке для интеграционных тестов"""
    port = get_free_port()
    server = ChatServer(host='127.0.0.1', port=port)
    thread = threading.Thread(target=server.start, daemon=True)
    thread.start()
    time.sleep(0.2)  # Даем серверу время на запуск
    yield server, port
    try:
        server.server_socket.close()
    except:
        pass

def send_packet(sock, packet):
    """Вспомогательная функция для отправки пакета через сокет"""
    data = packet.to_json().encode('utf-8')
    header = struct.pack('!I', len(data))
    sock.sendall(header + data)

def recv_packet(sock, timeout=3.0):
    """Вспомогательная функция для получения пакета из сокета."""
    import socket as sock_mod
    sock.settimeout(timeout)
    try:
        header = sock.recv(4)
        if not header or len(header) < 4:
            return None
        length = struct.unpack('!I', header)[0]
        payload = b""
        while len(payload) < length:
            chunk = sock.recv(length - len(payload))
            if not chunk:
                break
            payload += chunk
        return Packet.from_json(payload.decode('utf-8'))
    except sock_mod.timeout:
        return None
    finally:
        sock.settimeout(None)

def test_server_connection(running_server):
    """Сценарный тест: проверка возможности установления сетевого соединения с сервером"""
    server, port = running_server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', port))
    client_socket.close()
    time.sleep(0.1)

def test_unauthorized_message(running_server):
    """Сценарный тест: проверка запрета на отправку сообщений неавторизованным пользователем"""
    server, port = running_server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', port))
    
    send_packet(client_socket, Packet('message', text='hi', to='bob'))
    resp = recv_packet(client_socket)
    assert resp.msg_type == 'error'
    assert "авторизацию" in resp.error
    client_socket.close()

def test_full_auth_and_enroll_flow(running_server):
    """Сценарный тест: проверка полного цикла регистрации (Enroll) и авторизации клиента"""
    from unittest.mock import patch
    server, port = running_server

    # Мокаем БД — сертификат не найден (новый пользователь), сохранение проходит
    def mock_get(nickname):
        return None
    def mock_save(nickname, cert_pem):
        pass
    server._get_cert_from_db = mock_get
    server._save_cert_to_db = mock_save
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', port))
    
    nickname = "charlie"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, nickname),
    ])).sign(key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    # Этап 1: Регистрация и получение сертификата
    send_packet(client_socket, Packet('cert_enroll', nickname=nickname, csr=csr_pem))
    resp = recv_packet(client_socket)
    if resp.msg_type == 'error':
        pytest.fail(f"cert_enroll returned error: {resp.error}")
    assert resp.msg_type == 'cert_enroll_response'
    client_cert_pem = resp.client_cert
    
    # Этап 2: Инициация авторизации
    send_packet(client_socket, Packet('auth_init', nickname=nickname, client_cert=client_cert_pem))
    resp = recv_packet(client_socket)
    assert resp.msg_type == 'auth_challenge'
    nonce = base64.b64decode(resp.nonce)
    
    # Этап 3: Предоставление доказательства владения ключом (подпись)
    signature = key.sign(nonce, padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = base64.b64encode(signature).decode('utf-8')
    send_packet(client_socket, Packet('auth_proof', signature=sig_b64))
    
    resp = recv_packet(client_socket)
    assert resp.msg_type == 'event'
    assert resp.event == 'auth_success'
    
    # Проверка получения списка активных пользователей после входа
    resp = recv_packet(client_socket)
    assert resp.msg_type == 'event'
    assert resp.event == 'users_list'
    
    client_socket.close()
