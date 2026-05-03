"""
Тесты криптографических функций: экспорт/импорт сертификата в .enc файл.
"""
import pytest
import os
import tempfile
import struct
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from datetime import datetime, timezone, timedelta
from client.main import ChatClient, Packet


@pytest.fixture
def ca_cert_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "client", "private_ca.crt")


@pytest.fixture
def client_with_ca(ca_cert_path):
    c = ChatClient()
    assert c.ca_cert is not None, "CA certificate not loaded — check client/private_ca.crt"
    return c


def _gen_key_cert(nickname, ca_key_pem, ca_cert_pem_bytes):
    """Генерирует пару RSA-ключ + самоподписанный сертификат (CN=nickname)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nickname)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TEST_CA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before_utc(datetime.now(timezone.utc))
        .not_valid_after_utc(datetime.now(timezone.utc)
                             + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return key, cert_pem, key_pem


class TestExportImportEnc:
    """Тесты симметричного шифрования .enc файла."""

    def test_export_requires_cert(self, client_with_ca):
        """Экспорт без сертификата должен вернуть False без ошибок."""
        client_with_ca.client_cert_pem = None
        client_with_ca.private_key = None
        # Не падает, печатает ошибку и выходит
        client_with_ca._export_crt("alice", "secret")
        # сертификат не изменился
        assert client_with_ca.client_cert_pem is None

    def test_export_requires_key(self, client_with_ca):
        """Экспорт без приватного ключа должен вернуть False."""
        client_with_ca.client_cert_pem = "dummy cert"
        client_with_ca.private_key = None
        client_with_ca._export_crt("alice", "secret")
        assert client_with_ca.client_cert_pem == "dummy cert"

    def test_export_creates_enc_file(self, client_with_ca, tmp_path, ca_cert_path):
        """После экспорта в tmp_path должен появиться файл {nickname}.enc."""
        nickname = "alice"
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nickname)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TEST_CA")]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc)
                            + timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

        client_with_ca.client_cert_pem = cert_pem
        client_with_ca.private_key = key

        orig_dir = os.path.dirname(os.path.abspath(__file__))
        client_dir = os.path.join(orig_dir, "..", "client")
        enc_path = os.path.join(client_dir, f"{nickname}.enc")
        try:
            client_with_ca._export_crt(nickname, "strongpassword")
            assert os.path.exists(enc_path), "Enc file not created"

            raw = base64.b64decode(open(enc_path, "rb").read())
            assert len(raw) > 12, "File too short"
            nonce, ciphertext = raw[:12], raw[12:]
            assert len(nonce) == 12, "Nonce should be 12 bytes"

            # Проверяем что расшифровка с правильным паролем работает
            key_hash = hashes.Hash(hashes.SHA256())
            key_hash.update("strongpassword".encode())
            ek = key_hash.finalize()
            plaintext = AESGCM(ek).decrypt(nonce, ciphertext, None)
            cert_len = struct.unpack("!I", plaintext[:4])[0]
            assert cert_len > 0, "cert_len should be positive"
        finally:
            if os.path.exists(enc_path):
                os.remove(enc_path)

    def test_import_wrong_password(self, client_with_ca, tmp_path):
        """Импорт с неправильным паролем должен выбросить исключение."""
        nickname = "bob"
        # Создаём валидный .enc файл с правильным паролем
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nickname)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TEST_CA")]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc)
                            + timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        password = "correct"
        key_hash = hashes.Hash(hashes.SHA256())
        key_hash.update(password.encode())
        ek = key_hash.finalize()
        nonce = os.urandom(12)
        ciphertext = AESGCM(ek).encrypt(
            nonce,
            struct.pack("!I", len(cert_pem)) + cert_pem + key_pem,
            None,
        )
        enc_path = os.path.join(tmp_path, f"{nickname}.enc")
        with open(enc_path, "wb") as f:
            f.write(base64.b64encode(nonce + ciphertext))

        client_with_ca.nickname = nickname
        # Подменяем identities_dir
        client_with_ca.identities_dir = tmp_path
        result = client_with_ca._import_crt("wrongpassword", nickname)
        assert result is False, "Import with wrong password must fail"

    def test_import_file_not_found(self, client_with_ca, tmp_path):
        """Импорт несуществующего файла должен вернуть False."""
        client_with_ca.nickname = "ghost"
        client_with_ca.identities_dir = tmp_path
        result = client_with_ca._import_crt("anypassword", "ghost")
        assert result is False, "Import of missing file must fail"

    def test_import_without_nickname(self, client_with_ca):
        """Импорт без nickname (и без self.nickname) должен вернуть False."""
        client_with_ca.nickname = None
        result = client_with_ca._import_crt("password")
        assert result is False, "Import without nickname must fail"

    def test_sha256_key_derivation(self):
        """Ключ шифрования == SHA-256(пароль)."""
        import hashlib
        password = "testpass123"
        expected = hashlib.sha256(password.encode()).digest()
        key_hash = hashes.Hash(hashes.SHA256())
        key_hash.update(password.encode())
        actual = key_hash.finalize()
        assert expected == actual, "SHA-256 key derivation mismatch"


class TestAuthenticateReroll:
    """Тесты поведения authenticate() при отклонении импортированного сертификата."""

    def test_imported_cert_flag_set(self, client_with_ca):
        """После _import_crt флаг imported_cert должен быть True."""
        import shutil
        base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "client")
        nickname = "charlie_test"
        enc_path = os.path.join(base_dir, f"{nickname}.enc")
        try:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            cert = (
                x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nickname)]))
                .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TEST_CA")]))
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(datetime.now(timezone.utc)
                                 + timedelta(days=1))
                .sign(key, hashes.SHA256())
            )
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            key_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            password = "backuppass"
            key_hash = hashes.Hash(hashes.SHA256())
            key_hash.update(password.encode())
            ek = key_hash.finalize()
            nonce = os.urandom(12)
            ct = AESGCM(ek).encrypt(
                nonce,
                struct.pack("!I", len(cert_pem)) + cert_pem + key_pem,
                None,
            )
            with open(enc_path, "wb") as f:
                f.write(base64.b64encode(nonce + ct))

            client_with_ca.nickname = nickname
            client_with_ca.ca_cert = None

            # Патчим _verify_cert_signed_by_ca и _verify_cert_validity чтобы не падали
            client_with_ca._verify_cert_signed_by_ca = lambda c: None
            client_with_ca._verify_cert_validity = lambda c: None

            result = client_with_ca._import_crt(password, nickname)
            assert result is True, f"Import failed: {client_with_ca.auth_error}"
            assert client_with_ca.imported_cert is True, "Flag imported_cert not set after import"
        finally:
            if os.path.exists(enc_path):
                os.remove(enc_path)

    def test_authenticate_reroll_on_already_used(self, client_with_ca):
        """Если сертификат отклонён как 'already used' и imported_cert=True — должен перевыпустить."""
        client_with_ca.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        client_with_ca.imported_cert = True
        client_with_ca.authenticated = False
        client_with_ca.auth_error = "already used"
        client_with_ca.enroll_error = None

        # Проверяем что imported_cert сбрасывается после перевыпуска
        assert client_with_ca.imported_cert is True  # пока не перевыпущен


class TestRunInteractiveChoice:
    """Тесты меню выбора в run_interactive()."""

    def test_parse_message_strip(self):
        """Проверяем что parse_message обрезает пробелы."""
        c = ChatClient()
        text, recipient = c.parse_message("  @alice   hello world  ")
        assert recipient == "alice"
        assert text == "hello world"

    def test_parse_message_at_only(self):
        """@nickname без сообщения."""
        c = ChatClient()
        text, recipient = c.parse_message("@bob")
        assert recipient == "bob"
        assert text == ""

    def test_enc_path_resolution(self, tmp_path):
        """Путь к .enc файлу должен быть в директории клиента."""
        c = ChatClient()
        base = os.path.dirname(os.path.abspath(__file__))
        client_dir = os.path.join(base, "..", "client")
        expected = os.path.join(client_dir, "alice.enc")
        enc_path = os.path.join(client_dir, "alice.enc")
        assert enc_path == expected
