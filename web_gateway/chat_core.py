import base64
import json
import logging
import os
import socket
import struct
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

logger = logging.getLogger("WebChatClient")


class Packet:
    VERSION = 1

    def __init__(self, msg_type: str, **kwargs):
        self.version = self.VERSION
        self.msg_type = msg_type
        self.timestamp = kwargs.get("timestamp", int(datetime.now().timestamp()))
        self.from_user = kwargs.get("from")
        self.to_user = kwargs.get("to")
        self.text = kwargs.get("text")
        self.nickname = kwargs.get("nickname")
        self.client_cert = kwargs.get("client_cert")
        self.csr = kwargs.get("csr")
        self.enc_key = kwargs.get("enc_key")
        self.nonce = kwargs.get("nonce")
        self.signature = kwargs.get("signature")
        self.event = kwargs.get("event")
        self.message_id = kwargs.get("message_id")
        self.error = kwargs.get("error")

    def to_dict(self) -> Dict[str, Any]:
        data = {"version": self.version, "type": self.msg_type, "timestamp": self.timestamp}
        if self.from_user:
            data["from"] = self.from_user
        if self.to_user:
            data["to"] = self.to_user
        if self.text:
            data["text"] = self.text
        if self.nickname:
            data["nickname"] = self.nickname
        if self.client_cert:
            data["client_cert"] = self.client_cert
        if self.csr:
            data["csr"] = self.csr
        if self.enc_key:
            data["enc_key"] = self.enc_key
        if self.nonce:
            data["nonce"] = self.nonce
        if self.signature:
            data["signature"] = self.signature
        if self.event:
            data["event"] = self.event
        if self.message_id:
            data["message_id"] = self.message_id
        if self.error:
            data["error"] = self.error
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str) -> "Packet":
        data = json.loads(json_str)
        msg_type = data.get("type", "unknown")
        return cls(msg_type, **data)


EventCallback = Callable[[str, Dict[str, Any]], None]


class ChatClientCore:
    """Клиент TCP-чата без CLI-интерфейса: только API и колбэки."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8888,
        ca_cert_path: Optional[str] = None,
        identities_dir: Optional[str] = None,
        on_event: Optional[EventCallback] = None,
    ):
        self.host = host
        self.port = port
        self.socket: Optional[socket.socket] = None
        self.connected = False
        self.nickname: Optional[str] = None
        self.pending_nickname: Optional[str] = None
        self.authenticated = False
        self.auth_error: Optional[str] = None
        self.auth_result_event = threading.Event()
        self.enroll_error: Optional[str] = None
        self.enroll_result_event = threading.Event()
        self.enroll_nickname: Optional[str] = None
        self.listener_thread: Optional[threading.Thread] = None
        self.private_key = None
        self.client_cert_pem: Optional[str] = None
        self.imported_cert = False
        self.peer_public_keys: Dict[str, Any] = {}
        self.pending_messages: Dict[str, list[str]] = {}
        self.keys_lock = threading.Lock()
        self.on_event = on_event

        gateway_dir = Path(__file__).resolve().parent
        root = gateway_dir.parent
        self.identities_dir = identities_dir or str(gateway_dir / "identities")
        default_gateway_ca = Path(self.identities_dir) / "private_ca.crt"
        self.ca_cert_path = ca_cert_path or str(default_gateway_ca)
        os.makedirs(self.identities_dir, exist_ok=True)
        self.ca_cert = self._load_ca_certificate()

    def _emit(self, name: str, **payload: Any) -> None:
        if self.on_event:
            self.on_event(name, payload)

    def _load_ca_certificate(self):
        with open(self.ca_cert_path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())

    def _identity_paths(self, nickname: str) -> tuple[str, str]:
        return (
            os.path.join(self.identities_dir, f"{nickname}.crt"),
            os.path.join(self.identities_dir, f"{nickname}.key"),
        )

    def _load_identity_for_nickname(self, nickname: str):
        cert_path, key_path = self._identity_paths(nickname)
        if not (os.path.exists(cert_path) and os.path.exists(key_path)):
            raise FileNotFoundError("Не найдены файлы сертификата/ключа клиента")

        with open(cert_path, "rb") as f:
            cert_bytes = f.read()
        cert = x509.load_pem_x509_certificate(cert_bytes)
        self._verify_cert_signed_by_ca(cert)
        self._verify_cert_validity(cert)
        self._verify_nickname_in_cert(cert, nickname)

        with open(key_path, "rb") as f:
            key_bytes = f.read()
        private_key = serialization.load_pem_private_key(key_bytes, password=None)
        if private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ) != cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ):
            raise ValueError("Приватный ключ не соответствует сертификату")

        self.private_key = private_key
        self.client_cert_pem = cert_bytes.decode("utf-8")

    def _build_csr_for_nickname(self, nickname: str) -> str:
        if not isinstance(self.private_key, rsa.RSAPrivateKey):
            raise ValueError("Для авто-выпуска поддерживаются только RSA-ключи")
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COUNTRY_NAME, "RU"),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SUN_IN"),
                        x509.NameAttribute(NameOID.COMMON_NAME, nickname),
                    ]
                )
            )
            .sign(self.private_key, hashes.SHA256())
        )
        return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    def _load_peer_public_key(self, nickname: str, cert_pem: str):
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        self._verify_cert_signed_by_ca(cert)
        self._verify_cert_validity(cert)
        self._verify_nickname_in_cert(cert, nickname)
        with self.keys_lock:
            self.peer_public_keys[nickname] = cert.public_key()

    def _get_peer_public_key(self, nickname: str):
        with self.keys_lock:
            return self.peer_public_keys.get(nickname)

    def _sign_payload(self, payload: bytes) -> str:
        if isinstance(self.private_key, rsa.RSAPrivateKey):
            signature = self.private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(self.private_key, ec.EllipticCurvePrivateKey):
            signature = self.private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
        elif isinstance(self.private_key, ed25519.Ed25519PrivateKey):
            signature = self.private_key.sign(payload)
        elif isinstance(self.private_key, ed448.Ed448PrivateKey):
            signature = self.private_key.sign(payload)
        else:
            raise ValueError("Неподдерживаемый тип приватного ключа")
        return base64.b64encode(signature).decode("utf-8")

    def _encrypt_for_recipient(self, recipient: str, text: str) -> tuple[str, str, str]:
        peer_key = self._get_peer_public_key(recipient)
        if peer_key is None:
            raise ValueError(f"Ключ получателя {recipient} не найден")
        if not isinstance(peer_key, rsa.RSAPublicKey):
            raise ValueError("Поддерживаются только RSA-сертификаты получателя")

        aes_key = os.urandom(32)
        nonce = os.urandom(12)
        encrypted_text = AESGCM(aes_key).encrypt(nonce, text.encode("utf-8"), None)
        encrypted_key = peer_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return (
            base64.b64encode(encrypted_key).decode("utf-8"),
            base64.b64encode(nonce).decode("utf-8"),
            base64.b64encode(encrypted_text).decode("utf-8"),
        )

    def _decrypt_message(self, packet: Packet) -> str:
        if not isinstance(self.private_key, rsa.RSAPrivateKey):
            raise ValueError("Поддерживаются только RSA-ключи клиента")
        encrypted_key = base64.b64decode(packet.enc_key.encode("utf-8"))
        nonce = base64.b64decode(packet.nonce.encode("utf-8"))
        encrypted_text = base64.b64decode(packet.text.encode("utf-8"))
        aes_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return AESGCM(aes_key).decrypt(nonce, encrypted_text, None).decode("utf-8")

    def _recv_exactly(self, num_bytes: int) -> Optional[bytes]:
        data = bytearray()
        while len(data) < num_bytes and self.socket is not None:
            try:
                chunk = self.socket.recv(num_bytes - len(data))
                if not chunk:
                    return None
                data.extend(chunk)
            except (ConnectionResetError, OSError):
                return None
        return bytes(data)

    def connect(self) -> bool:
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.connected = True
            self.listener_thread = threading.Thread(target=self._listen_server, daemon=True)
            self.listener_thread.start()
            self._emit("status", text=f"Подключено к {self.host}:{self.port}")
            return True
        except Exception as exc:
            self._emit("error", error=f"Ошибка подключения: {exc}")
            return False

    def _listen_server(self):
        try:
            while self.connected:
                length_bytes = self._recv_exactly(4)
                if not length_bytes:
                    break
                msg_length = struct.unpack("!I", length_bytes)[0]
                payload = self._recv_exactly(msg_length)
                if not payload:
                    break
                self._handle_packet(Packet.from_json(payload.decode("utf-8")))
        except Exception as exc:
            self._emit("error", error=f"Ошибка при чтении от сервера: {exc}")
        finally:
            self.disconnect(emit=False)
            self._emit("status", text="Соединение закрыто")

    def _send_pending_messages(self, recipient: str):
        queue = self.pending_messages.pop(recipient, [])
        for message_text in queue:
            self.send_private_message(recipient, message_text)

    def _handle_packet(self, packet: Packet):
        if packet.msg_type == "event":
            if packet.event == "auth_success":
                self.nickname = self.pending_nickname
                self.pending_nickname = None
                self.authenticated = True
                self.auth_error = None
                self.auth_result_event.set()
            self._emit("event", event=packet.event, text=packet.text, nickname=packet.nickname)
            return

        if packet.msg_type == "auth_challenge":
            if not packet.nonce:
                self.auth_error = "challenge без nonce"
                self.auth_result_event.set()
                self._emit("error", error=self.auth_error)
                return
            try:
                nonce_bytes = base64.b64decode(packet.nonce.encode("utf-8"))
                signature_b64 = self._sign_payload(nonce_bytes)
                self.send_packet(Packet("auth_proof", signature=signature_b64))
            except Exception as exc:
                self.auth_error = f"Ошибка подписи challenge: {exc}"
                self.auth_result_event.set()
                self._emit("error", error=self.auth_error)
            return

        if packet.msg_type == "cert_enroll_response":
            if not packet.nickname or not packet.client_cert:
                self.enroll_error = "Получен некорректный cert_enroll_response"
                self.enroll_result_event.set()
                return
            if self.enroll_nickname and packet.nickname != self.enroll_nickname:
                self.enroll_error = "Никнейм в cert_enroll_response не совпадает"
                self.enroll_result_event.set()
                return
            try:
                cert = x509.load_pem_x509_certificate(packet.client_cert.encode("utf-8"))
                self._verify_cert_signed_by_ca(cert)
                self._verify_cert_validity(cert)
                self._verify_nickname_in_cert(cert, packet.nickname)
                if self.private_key is None:
                    raise ValueError("Локальный приватный ключ отсутствует")
                if self.private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ) != cert.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ):
                    raise ValueError("Сертификат не соответствует локальному ключу")
                cert_path, key_path = self._identity_paths(packet.nickname)
                with open(cert_path, "wb") as f:
                    f.write(packet.client_cert.encode("utf-8"))
                with open(key_path, "wb") as f:
                    f.write(
                        self.private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption(),
                        )
                    )
                self.client_cert_pem = packet.client_cert
                self.enroll_error = None
                self._emit("status", text=f"Сертификат для {packet.nickname} сохранен")
            except Exception as exc:
                self.enroll_error = f"Ошибка обработки выданного сертификата: {exc}"
            self.enroll_result_event.set()
            return

        if packet.msg_type == "message":
            from_user = packet.from_user or "unknown"
            try:
                text = self._decrypt_message(packet)
                self._emit("message", from_user=from_user, text=text)
            except Exception as exc:
                self._emit("error", error=f"Не удалось расшифровать сообщение от {from_user}: {exc}")
            return

        if packet.msg_type == "key_response":
            if not packet.nickname or not packet.client_cert:
                self._emit("error", error="Получен некорректный ответ с сертификатом")
                return
            try:
                self._load_peer_public_key(packet.nickname, packet.client_cert)
                self._emit("status", text=f"Получен сертификат пользователя {packet.nickname}")
                self._send_pending_messages(packet.nickname)
            except Exception as exc:
                self._emit("error", error=f"Ошибка обработки сертификата {packet.nickname}: {exc}")
            return

        if packet.msg_type == "error":
            if self.enroll_nickname:
                self.enroll_error = packet.error
                self.enroll_result_event.set()
            if not self.authenticated and self.pending_nickname:
                self.auth_error = packet.error
                self.auth_result_event.set()
            self._emit("error", error=packet.error or "Неизвестная ошибка")

    def send_packet(self, packet: Packet) -> bool:
        if not self.connected or self.socket is None:
            self._emit("error", error="Нет подключения к серверу")
            return False
        try:
            data = packet.to_json().encode("utf-8")
            self.socket.sendall(struct.pack("!I", len(data)) + data)
            return True
        except Exception as exc:
            self._emit("error", error=f"Ошибка отправки данных: {exc}")
            self.disconnect()
            return False

    def authenticate(self, nickname: str, timeout_seconds: float = 6.0) -> bool:
        if self.ca_cert is None:
            self.auth_error = "Не загружен private_ca.crt"
            return False

        try:
            self._load_identity_for_nickname(nickname)
        except FileNotFoundError:
            try:
                self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                csr_pem = self._build_csr_for_nickname(nickname)
                self.enroll_nickname = nickname
                self.enroll_error = None
                self.enroll_result_event.clear()
                if not self.send_packet(Packet("cert_enroll", nickname=nickname, csr=csr_pem)):
                    self.auth_error = "Ошибка отправки cert_enroll"
                    self.enroll_nickname = None
                    return False
                self.enroll_result_event.wait(timeout=timeout_seconds)
                self.enroll_nickname = None
                if self.enroll_error:
                    self.auth_error = f"Не удалось выпустить сертификат: {self.enroll_error}"
                    return False
                if not self.client_cert_pem:
                    self.auth_error = "Сервер не вернул сертификат"
                    return False
            except Exception as exc:
                self.auth_error = f"Не удалось выпустить сертификат клиента: {exc}"
                self.enroll_nickname = None
                return False
        except Exception as exc:
            self.auth_error = f"Не удалось загрузить сертификат клиента: {exc}"
            return False

        # Цикл: если импортированный сертификат отклонён — перевыпускаем и ретраим.
        while True:
            self.pending_nickname = nickname
            self.authenticated = False
            self.auth_error = None
            self.auth_result_event.clear()
            if not self.send_packet(Packet("auth_init", nickname=nickname, client_cert=self.client_cert_pem)):
                return False
            self.auth_result_event.wait(timeout=timeout_seconds)
            if self.authenticated:
                return True
            if (self.imported_cert
                    and self.auth_error
                    and "already" in self.auth_error.lower()):
                self._emit("status", text=f"Сертификат для {nickname} уже недействителен — перевыпускаю...")
                self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                csr_pem = self._build_csr_for_nickname(nickname)
                self.enroll_nickname = nickname
                self.enroll_error = None
                self.enroll_result_event.clear()
                if not self.send_packet(Packet("cert_enroll", nickname=nickname, csr=csr_pem)):
                    self.auth_error = "Ошибка отправки cert_enroll"
                    self.enroll_nickname = None
                    return False
                self.enroll_result_event.wait(timeout=timeout_seconds)
                self.enroll_nickname = None
                if self.enroll_error:
                    self.auth_error = f"Не удалось перевыпустить сертификат: {self.enroll_error}"
                    return False
                if not self.client_cert_pem:
                    self.auth_error = "Сервер не вернул сертификат"
                    return False
                self.imported_cert = False
                continue
            return False

    def request_peer_key(self, nickname: str) -> bool:
        return self.send_packet(Packet("key_request", to=nickname))

    def send_private_message(self, to_user: str, text: str) -> bool:
        if not self.authenticated:
            self._emit("error", error="Сначала выполните авторизацию")
            return False
        if not to_user:
            self._emit("error", error="Нужно указать получателя")
            return False
        peer_key = self._get_peer_public_key(to_user)
        if peer_key is None:
            self.pending_messages.setdefault(to_user, []).append(text)
            self._emit("status", text=f"Запрашиваю сертификат пользователя {to_user}")
            return self.request_peer_key(to_user)
        try:
            enc_key, nonce, encrypted_text = self._encrypt_for_recipient(to_user, text)
        except Exception as exc:
            self._emit("error", error=f"Ошибка шифрования: {exc}")
            return False
        return self.send_packet(Packet("message", to=to_user, text=encrypted_text, enc_key=enc_key, nonce=nonce))

    def _export_crt(self, nickname: str, password: str):
        """Экспорт сертификата и ключа в зашифрованном виде.

        Ключ шифрования: SHA-256 от пароля (32 байта).
        Шифрование: AES-GCM (случайный nonce, auth tag).
        Формат файла: nonce (12 байт) || cert_len (4 байта) || cert_bytes || key_bytes
        Всё кодируется в base64 при записи.
        """
        if not self.client_cert_pem:
            self._emit("error", error="Нет сертификата для экспорта. Сначала зарегистрируйтесь.")
            return
        if not self.private_key:
            self._emit("error", error="Нет приватного ключа для экспорта.")
            return

        cert_pem = self.client_cert_pem.encode("utf-8")
        key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Ключ из пароля: SHA-256
        key_hash = hashes.Hash(hashes.SHA256())
        key_hash.update(password.encode("utf-8"))
        encryption_key = key_hash.finalize()  # 32 байта

        nonce = os.urandom(12)  # 96-битный nonce для AES-GCM
        aesgcm = AESGCM(encryption_key)
        cert_len = struct.pack("!I", len(cert_pem))
        plaintext = cert_len + cert_pem + key_pem
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        output_path = os.path.join(self.identities_dir, f"{nickname}.enc")
        with open(output_path, "wb") as f:
            f.write(base64.b64encode(nonce + ciphertext))
        self._emit("status", text=f"Сертификат и ключ экспортированы в {output_path}")

    def _import_crt(self, password: str, nickname: Optional[str] = None) -> bool:
        """Импорт сертификата и ключа из зашифрованного файла.

        Пароль -> SHA-256 -> ключ AES-GCM.
        Формат файла: base64(nonce (12 байт) || ciphertext)
        Расшифрованные данные: cert_len (4 байта) || cert_pem || key_pem
        nickname — если передан, читает файл для этого никнейма (до подключения).
        """
        target = nickname or self.nickname
        if not target:
            self._emit("error", error="Неизвестен никнейм — сначала укажите его")
            return False

        enc_path = os.path.join(self.identities_dir, f"{target}.enc")
        if not os.path.exists(enc_path):
            self._emit("error", error=f"Файл {enc_path} не найден")
            return False

        try:
            with open(enc_path, "rb") as f:
                raw = base64.b64decode(f.read())

            key_hash = hashes.Hash(hashes.SHA256())
            key_hash.update(password.encode("utf-8"))
            encryption_key = key_hash.finalize()

            nonce = raw[:12]
            ciphertext = raw[12:]
            plaintext = AESGCM(encryption_key).decrypt(nonce, ciphertext, None)

            cert_len = struct.unpack("!I", plaintext[:4])[0]
            cert_pem = plaintext[4:4 + cert_len]
            key_pem = plaintext[4 + cert_len:]

            # Валидация сертификата
            cert = x509.load_pem_x509_certificate(cert_pem)
            self._verify_cert_signed_by_ca(cert)
            self._verify_cert_validity(cert)
            self._verify_nickname_in_cert(cert, target)

            # Сохраняем как обычные файлы
            cert_path, key_path = self._identity_paths(target)
            with open(cert_path, "wb") as f:
                f.write(cert_pem)
            with open(key_path, "wb") as f:
                f.write(key_pem)

            self.client_cert_pem = cert_pem.decode("utf-8")
            key_obj = serialization.load_pem_private_key(key_pem, password=None)
            self.private_key = key_obj
            self.imported_cert = True
            self._emit("status", text=f"Сертификат и ключ восстановлены из {enc_path}")
            return True
        except Exception as exc:
            self._emit("error", error=f"Ошибка импорта: {exc}")
            return False

    def disconnect(self, emit: bool = True):
        if self.connected:
            self.connected = False
            try:
                if self.socket:
                    self.socket.close()
            except Exception:
                pass
        self.socket = None
        self.authenticated = False
        self.nickname = None
        self.pending_nickname = None
        if emit:
            self._emit("status", text="Отключено")

    def _verify_cert_signed_by_ca(self, cert: x509.Certificate):
        ca_public_key = self.ca_cert.public_key()
        if isinstance(ca_public_key, rsa.RSAPublicKey):
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
            return
        if isinstance(ca_public_key, ec.EllipticCurvePublicKey):
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
            return
        raise ValueError("Неподдерживаемый тип ключа CA")

    @staticmethod
    def _verify_cert_validity(cert: x509.Certificate):
        now = datetime.now(timezone.utc)
        if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
            raise ValueError("Сертификат просрочен или еще не вступил в силу")

    @staticmethod
    def _verify_nickname_in_cert(cert: x509.Certificate, nickname: str):
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not cn_attrs:
            raise ValueError("В сертификате отсутствует CN")
        cert_cn = cn_attrs[0].value.strip()
        if cert_cn != nickname:
            raise ValueError(f"CN сертификата ({cert_cn}) не совпадает с nickname ({nickname})")
