import pytest
import os
import socket
import threading
import time
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from client.main import ChatClient, Packet

@pytest.fixture
def client():
    # Создаем клиента. Он попробует загрузить private_ca.crt из своей папки.
    return ChatClient()

def test_client_parse_message(client):
    """Проверка корректности парсинга интерактивных команд и адресатов сообщений"""
    # Формат @nickname сообщение
    text, recipient = client.parse_message("@bob hello there")
    assert recipient == "bob"
    assert text == "hello there"
    
    # Формат @nickname без тела сообщения
    text, recipient = client.parse_message("@alice")
    assert recipient == "alice"
    assert text == ""
    
    # Формат сообщения без указания адресата
    text, recipient = client.parse_message("hello")
    assert recipient is None
    assert text == "hello"

def test_client_crypto_setup(client):
    """Проверка процесса генерации CSR и корректности атрибутов в запросе на сертификат"""
    nickname = "test_user"
    client.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    csr_pem = client._build_csr_for_nickname(nickname)
    assert "-----BEGIN CERTIFICATE REQUEST-----" in csr_pem
    
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert cn == nickname

def test_client_e2e_encryption_decryption(client):
    """Проверка механизмов сквозного (E2E) шифрования и расшифровки данных"""
    # Настройка локальных ключей (имитация получателя)
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client.private_key = client_key
    
    # Регистрация публичного ключа собеседника
    recipient_name = "bob"
    client.peer_public_keys[recipient_name] = client_key.public_key()
    
    message = "Секретное сообщение"
    
    # Выполнение шифрования
    enc_key, nonce, encrypted_text = client._encrypt_for_recipient(recipient_name, message)
    
    # Создание пакета с зашифрованными данными
    packet = Packet('message', from_user='alice', to_user='bob', 
                    text=encrypted_text, enc_key=enc_key, nonce=nonce)
    
    # Выполнение расшифровки
    decrypted = client._decrypt_message(packet)
    assert decrypted == message

def test_client_identity_paths(client):
    """Проверка алгоритма формирования путей к файлам закрытых ключей и сертификатов"""
    cert_path, key_path = client._identity_paths("alice")
    assert "alice.crt" in cert_path
    assert "alice.key" in key_path
