import pytest
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from unittest.mock import MagicMock
from server.main import ChatServer, Packet

@pytest.fixture
def server():
    # ChatServer ожидает наличие private_ca.crt и private_ca.key в своей директории
    s = ChatServer()
    # Мокаем методы работы с БД для тестов
    s._init_db = MagicMock()
    s._get_cert_from_db = MagicMock(return_value=None)
    s._save_cert_to_db = MagicMock()
    return s

def generate_key_and_csr(nickname):
    """Вспомогательная функция для генерации приватного ключа и CSR"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, nickname),
    ])).sign(key, hashes.SHA256())
    
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    return key, csr_pem

def test_server_issue_and_validate_cert(server):
    """Проверка выпуска и последующей валидации клиентского сертификата сервером"""
    nickname = "alice"
    key, csr_pem = generate_key_and_csr(nickname)
    
    # Выпуск сертификата
    cert_pem = server.issue_client_certificate(nickname, csr_pem)
    assert cert_pem.startswith("-----BEGIN CERTIFICATE-----")
    
    # Валидация сертификата
    cert = server.validate_client_certificate(cert_pem, nickname)
    assert isinstance(cert, x509.Certificate)
    
    # Проверка обработки ошибки при несовпадении никнейма в сертификате
    with pytest.raises(ValueError, match="не совпадает с nickname"):
        server.validate_client_certificate(cert_pem, "bob")

def test_server_verify_signature(server):
    """Проверка корректности верификации цифровой подписи клиента сервером"""
    nickname = "alice"
    key, csr_pem = generate_key_and_csr(nickname)
    cert_pem = server.issue_client_certificate(nickname, csr_pem)
    cert = server.validate_client_certificate(cert_pem, nickname)
    
    nonce = os.urandom(32)
    signature = key.sign(
        nonce,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    # Проверка валидной подписи
    server.verify_client_signature(cert.public_key(), nonce, signature)
    
    # Проверка реакции на некорректную подпись
    with pytest.raises(Exception):
        server.verify_client_signature(cert.public_key(), nonce, b"wrong signature")

def test_server_client_management(server):
    """Проверка механизмов управления списком подключенных клиентов"""
    assert len(server.clients) == 0
    
    # Использование Mock-объекта для имитации ClientHandler
    class MockClient:
        def __init__(self, nickname):
            self.nickname = nickname
        def get_nickname(self):
            return self.nickname
            
    client_alice = MockClient("alice")
    server.clients.add(client_alice)
    
    # Поиск клиента по никнейму
    assert server.find_client_by_nickname("alice") == client_alice
    assert server.find_client_by_nickname("bob") is None
    
    # Получение списка всех онлайн-пользователей
    online = server.get_online_users()
    assert "alice" in online
    
    # Удаление клиента из списка
    server.remove_client(client_alice)
    assert len(server.clients) == 0

def test_server_prevent_duplicate_cert(server):
    """Проверка запрета на повторный выпуск сертификата для того же никнейма"""
    nickname = "alice"
    key, csr_pem = generate_key_and_csr(nickname)
    
    # Имитируем, что сертификат уже есть в БД
    server._get_cert_from_db = MagicMock(return_value="EXISTING_CERT_PEM")
    
    with pytest.raises(ValueError, match="уже был выдан ранее"):
        server.issue_client_certificate(nickname, csr_pem)
