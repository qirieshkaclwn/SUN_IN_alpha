import threading
import time
import base64
import os
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from websockets.sync.client import connect
from server.main import ChatServer, Packet

@pytest.fixture
def running_server():
    """Фикстура для запуска сервера в отдельном потоке для интеграционных тестов"""
    server = ChatServer(host='127.0.0.1', port=0)

    def _cleanup_db():
        conn = server._get_db_connection()
        if conn:
            try:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM certificates WHERE nickname IN ('alice', 'bob')")
                conn.commit()
            except Exception:
                pass
            finally:
                conn.close()

    _cleanup_db()
    thread = threading.Thread(target=server.start, daemon=True)
    thread.start()
    for _ in range(50):
        if server.server_socket is not None:
            break
        time.sleep(0.05)
    port = server.port
    yield server, port
    server.stop()
    _cleanup_db()

def send_packet(ws, packet):
    """Вспомогательная функция для отправки пакета через WebSocket"""
    ws.send(packet.to_json())

def recv_packet(ws, timeout=3.0):
    """Вспомогательная функция для получения пакета из WebSocket"""
    try:
        msg = ws.recv(timeout=timeout)
        return Packet.from_json(msg)
    except Exception:
        return None

def test_server_connection(running_server):
    """Сценарный тест: проверка возможности установления сетевого соединения с сервером"""
    server, port = running_server
    ws = connect(f'ws://127.0.0.1:{port}', legacy=True)
    ws.close()

def test_unauthorized_message(running_server):
    """Сценарный тест: проверка запрета на отправку сообщений неавторизованным пользователем"""
    server, port = running_server
    ws = connect(f'ws://127.0.0.1:{port}', legacy=True)
    
    send_packet(ws, Packet('message', text='hi', to='bob'))
    resp = recv_packet(ws)
    assert resp is not None
    assert resp.msg_type == 'error'
    assert "авторизацию" in resp.error
    ws.close()

def test_full_auth_and_enroll_flow(running_server):
    """Сценарный тест: проверка полного цикла регистрации (Enroll) и авторизации клиента"""
    server, port = running_server

    # Мокаем БД — сертификат не найден (новый пользователь), сохранение проходит
    server._get_cert_from_db = lambda nickname: None
    server._save_cert_to_db = lambda nickname, cert_pem: None
    ws = connect(f'ws://127.0.0.1:{port}', legacy=True)
    
    nickname = "charlie"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, nickname),
    ])).sign(key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    # Этап 1: Регистрация и получение сертификата
    send_packet(ws, Packet('cert_enroll', nickname=nickname, csr=csr_pem))
    resp = recv_packet(ws)
    assert resp is not None
    if resp.msg_type == 'error':
        pytest.fail(f"cert_enroll returned error: {resp.error}")
    assert resp.msg_type == 'cert_enroll_response'
    client_cert_pem = resp.client_cert
    
    # Этап 2: Инициация авторизации
    send_packet(ws, Packet('auth_init', nickname=nickname, client_cert=client_cert_pem))
    resp = recv_packet(ws)
    assert resp is not None
    assert resp.msg_type == 'auth_challenge'
    nonce = base64.b64decode(resp.nonce)
    
    # Этап 3: Предоставление доказательства владения ключом (подпись)
    signature = key.sign(nonce, padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = base64.b64encode(signature).decode('utf-8')
    send_packet(ws, Packet('auth_proof', signature=sig_b64))
    
    resp = recv_packet(ws)
    assert resp is not None
    assert resp.msg_type == 'event'
    assert resp.event == 'auth_success'
    
    # Проверка получения списка активных пользователей после входа
    resp = recv_packet(ws)
    assert resp is not None
    assert resp.msg_type == 'event'
    assert resp.event == 'users_list'
    
    ws.close()

def test_message_relay(running_server):
    """Сценарный тест: проверка ретрансляции E2E-сообщения между двумя авторизованными пользователями"""
    server, port = running_server
    
    # Настройка и вход пользователя Alice
    alice_ws = connect(f'ws://127.0.0.1:{port}', legacy=True)
    alice_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    alice_csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "alice"),
    ])).sign(alice_key, hashes.SHA256())
    alice_csr_pem = alice_csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    send_packet(alice_ws, Packet('cert_enroll', nickname="alice", csr=alice_csr_pem))
    alice_cert = recv_packet(alice_ws).client_cert
    
    send_packet(alice_ws, Packet('auth_init', nickname="alice", client_cert=alice_cert))
    nonce = base64.b64decode(recv_packet(alice_ws).nonce)
    sig = base64.b64encode(alice_key.sign(nonce, padding.PKCS1v15(), hashes.SHA256())).decode('utf-8')
    send_packet(alice_ws, Packet('auth_proof', signature=sig))
    assert recv_packet(alice_ws).event == 'auth_success'
    recv_packet(alice_ws) # Пропуск списка пользователей
    
    # Настройка и вход пользователя Bob
    bob_ws = connect(f'ws://127.0.0.1:{port}', legacy=True)
    bob_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bob_csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "bob"),
    ])).sign(bob_key, hashes.SHA256())
    bob_csr_pem = bob_csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    send_packet(bob_ws, Packet('cert_enroll', nickname="bob", csr=bob_csr_pem))
    bob_cert = recv_packet(bob_ws).client_cert
    
    send_packet(bob_ws, Packet('auth_init', nickname="bob", client_cert=bob_cert))
    nonce = base64.b64decode(recv_packet(bob_ws).nonce)
    sig = base64.b64encode(bob_key.sign(nonce, padding.PKCS1v15(), hashes.SHA256())).decode('utf-8')
    send_packet(bob_ws, Packet('auth_proof', signature=sig))
    assert recv_packet(bob_ws).event == 'auth_success'
    recv_packet(bob_ws) # Пропуск списка пользователей
    
    # Alice должна получить уведомление о подключении Bob
    joined = recv_packet(alice_ws)
    assert joined.event == 'user_joined'
    assert joined.nickname == 'bob'
    
    # Alice отправляет E2E-пакет для Bob
    msg_packet = Packet('message', text='secret', to='bob', enc_key='key', nonce='nonce')
    send_packet(alice_ws, msg_packet)
    
    # Bob должен получить это сообщение
    received = recv_packet(bob_ws)
    assert received.msg_type == 'message'
    assert received.from_user == 'alice'
    assert received.text == 'secret'
    
    alice_ws.close()
    bob_ws.close()
