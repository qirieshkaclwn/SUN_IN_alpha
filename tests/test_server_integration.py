import socket
import threading
import time
import struct
import json
import base64
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

def recv_packet(sock):
    """Вспомогательная функция для получения пакета из сокета"""
    header = sock.recv(4)
    if not header or len(header) < 4: return None
    length = struct.unpack('!I', header)[0]
    payload = b""
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk: break
        payload += chunk
    return Packet.from_json(payload.decode('utf-8'))

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
    server, port = running_server
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

def test_message_relay(running_server):
    """Сценарный тест: проверка ретрансляции E2E-сообщения между двумя авторизованными пользователями"""
    server, port = running_server
    
    # Настройка и вход пользователя Alice
    alice_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    alice_sock.connect(('127.0.0.1', port))
    alice_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    alice_csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "alice"),
    ])).sign(alice_key, hashes.SHA256())
    alice_csr_pem = alice_csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    send_packet(alice_sock, Packet('cert_enroll', nickname="alice", csr=alice_csr_pem))
    alice_cert = recv_packet(alice_sock).client_cert
    
    send_packet(alice_sock, Packet('auth_init', nickname="alice", client_cert=alice_cert))
    nonce = base64.b64decode(recv_packet(alice_sock).nonce)
    sig = base64.b64encode(alice_key.sign(nonce, padding.PKCS1v15(), hashes.SHA256())).decode('utf-8')
    send_packet(alice_sock, Packet('auth_proof', signature=sig))
    assert recv_packet(alice_sock).event == 'auth_success'
    recv_packet(alice_sock) # Пропуск списка пользователей
    
    # Настройка и вход пользователя Bob
    bob_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob_sock.connect(('127.0.0.1', port))
    bob_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bob_csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "bob"),
    ])).sign(bob_key, hashes.SHA256())
    bob_csr_pem = bob_csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    send_packet(bob_sock, Packet('cert_enroll', nickname="bob", csr=bob_csr_pem))
    bob_cert = recv_packet(bob_sock).client_cert
    
    send_packet(bob_sock, Packet('auth_init', nickname="bob", client_cert=bob_cert))
    nonce = base64.b64decode(recv_packet(bob_sock).nonce)
    sig = base64.b64encode(bob_key.sign(nonce, padding.PKCS1v15(), hashes.SHA256())).decode('utf-8')
    send_packet(bob_sock, Packet('auth_proof', signature=sig))
    assert recv_packet(bob_sock).event == 'auth_success'
    recv_packet(bob_sock) # Пропуск списка пользователей
    
    # Alice должна получить уведомление о подключении Bob
    joined = recv_packet(alice_sock)
    assert joined.event == 'user_joined'
    assert joined.nickname == 'bob'
    
    # Alice отправляет E2E-пакет для Bob
    msg_packet = Packet('message', text='secret', to='bob', enc_key='key', nonce='nonce')
    send_packet(alice_sock, msg_packet)
    
    # Bob должен получить это сообщение
    received = recv_packet(bob_sock)
    assert received.msg_type == 'message'
    assert received.from_user == 'alice'
    assert received.text == 'secret'
    
    alice_sock.close()
    bob_sock.close()
