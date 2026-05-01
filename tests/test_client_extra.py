import pytest
import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from client.main import ChatClient, Packet

@pytest.fixture
def client():
    c = ChatClient()
    c.private_key = rsa.generate_private_key(65537, 2048)
    c.nickname = "test_user"
    c.authenticated = True
    return c

def test_client_message_queuing(client):
    """Проверка постановки сообщений в очередь при отсутствии ключа собеседника"""
    recipient = "bob"
    message = "Secret message"
    
    # Пытаемся отправить сообщение Бобу, ключа которого нет
    client.send_message(message, to_user=recipient)
    
    # Проверяем, что сообщение попало в очередь
    assert recipient in client.pending_messages
    assert client.pending_messages[recipient] == [message]
    
    # Имитируем получение ключа Боба
    bob_key = rsa.generate_private_key(65537, 2048)
    bob_cert_pem = "fake_cert" # В реальности нужно валидное PEM, но мы мокаем загрузку ключа
    
    # Подменяем метод отправки, чтобы проверить вызов
    sent_packets = []
    client.send_packet = lambda p: sent_packets.append(p)
    
    # Мокаем _encrypt_for_recipient, так как нам нужна настоящая криптография для теста очереди
    # или просто загрузим ключ в peer_public_keys
    client.peer_public_keys[recipient] = bob_key.public_key()
    
    # Вызываем отправку из очереди
    client._send_pending_messages(recipient)
    
    assert len(sent_packets) == 1
    assert sent_packets[0].msg_type == 'message'
    assert recipient not in client.pending_messages

def test_client_peer_cert_validation(client):
    """Проверка валидации сертификата другого пользователя"""
    # Этот тест сложен тем, что требует CA для подписи. 
    # Но мы можем проверить, что некорректный сертификат вызывает ошибку.
    
    with pytest.raises(Exception):
        # Передаем случайную строку вместо сертификата
        client._load_peer_public_key("alice", "not a certificate")

from cryptography.hazmat.primitives.asymmetric import padding

def test_client_sign_payload_algorithms(client):
    """Проверка поддержки алгоритмов подписи (RSA)"""
    payload = b"test payload"
    signature_b64 = client._sign_payload(payload)
    
    signature = base64.b64decode(signature_b64)
    # Проверяем подпись с правильными параметрами padding и hashes
    client.private_key.public_key().verify(
        signature,
        payload,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    # Если не упало — значит RSA подпись работает
