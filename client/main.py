import socket
import threading
import json
import struct
import logging
from typing import Optional, Dict, Any
from datetime import datetime, timezone
import time
import base64
import os

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec, ed25519, ed448
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Настройка логирования
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%H:%M:%S'
)

logger = logging.getLogger('ChatClient')


class Packet:
    VERSION = 1

    def __init__(self, msg_type: str, **kwargs):
        self.version = self.VERSION
        self.msg_type = msg_type
        self.timestamp = kwargs.get('timestamp', int(datetime.now().timestamp()))
        self.from_user = kwargs.get('from')
        self.to_user = kwargs.get('to')
        self.text = kwargs.get('text')
        self.nickname = kwargs.get('nickname')
        self.client_cert = kwargs.get('client_cert')
        self.csr = kwargs.get('csr')
        self.enc_key = kwargs.get('enc_key')
        self.nonce = kwargs.get('nonce')
        self.signature = kwargs.get('signature')
        self.event = kwargs.get('event')
        self.message_id = kwargs.get('message_id')
        self.error = kwargs.get('error')

    def to_dict(self) -> Dict[str, Any]:
        data = {'version': self.version, 'type': self.msg_type, 'timestamp': self.timestamp}
        if self.from_user: data['from'] = self.from_user
        if self.to_user: data['to'] = self.to_user
        if self.text: data['text'] = self.text
        if self.nickname: data['nickname'] = self.nickname
        if self.client_cert: data['client_cert'] = self.client_cert
        if self.csr: data['csr'] = self.csr
        if self.enc_key: data['enc_key'] = self.enc_key
        if self.nonce: data['nonce'] = self.nonce
        if self.signature: data['signature'] = self.signature
        if self.event: data['event'] = self.event
        if self.message_id: data['message_id'] = self.message_id
        if self.error: data['error'] = self.error
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Packet':
        msg_type = data.get('type', 'unknown')
        return cls(msg_type, **data)

    @classmethod
    def from_json(cls, json_str: str) -> 'Packet':
        data = json.loads(json_str)
        return cls.from_dict(data)

    @staticmethod
    def create_event(event: str, **kwargs) -> 'Packet':
        return Packet('event', event=event, **kwargs)

    def __repr__(self):
        return f"Packet(type={self.msg_type}, from={self.from_user}, to={self.to_user})"


class ChatClient:
    """Клиент чата с поддержкой многопоточности"""

    def __init__(self, host='127.0.0.1', port=8888):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        self.nickname = None
        self.pending_nickname = None
        self.authenticated = False
        self.auth_error = None
        self.auth_result_event = threading.Event()
        self.enroll_error = None
        self.enroll_result_event = threading.Event()
        self.enroll_nickname = None
        self.listener_thread = None
        self.private_key = None
        self.client_cert_pem = None
        self.ca_cert = self._load_ca_certificate()
        self.peer_public_keys: Dict[str, Any] = {}
        self.pending_messages: Dict[str, list[str]] = {}
        self.keys_lock = threading.Lock()

    def _load_ca_certificate(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        ca_path = os.path.join(base_dir, 'private_ca.crt')
        try:
            with open(ca_path, 'rb') as f:
                return x509.load_pem_x509_certificate(f.read())
        except Exception as e:
            logger.error(f"Не удалось загрузить private_ca.crt: {e}")
            return None

    def _load_identity_for_nickname(self, nickname: str):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        candidates = [
            (os.path.join(base_dir, f"{nickname}.crt"), os.path.join(base_dir, f"{nickname}.key")),
            (os.path.join(base_dir, "client.crt"), os.path.join(base_dir, "client.key"))
        ]
        cert_path = key_path = None
        for c_path, k_path in candidates:
            if os.path.exists(c_path) and os.path.exists(k_path):
                cert_path, key_path = c_path, k_path
                break
        if not cert_path:
            raise FileNotFoundError("Не найдены файлы сертификата/ключа клиента")

        with open(cert_path, 'rb') as f:
            cert_bytes = f.read()
        cert = x509.load_pem_x509_certificate(cert_bytes)
        # Клиент доверяет только сертификатам от pinned CA и с корректным CN.
        self._verify_cert_signed_by_ca(cert)
        self._verify_cert_validity(cert)
        self._verify_nickname_in_cert(cert, nickname)

        with open(key_path, 'rb') as f:
            key_bytes = f.read()
        private_key = serialization.load_pem_private_key(key_bytes, password=None)
        if private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ) != cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ):
            raise ValueError("Приватный ключ не соответствует сертификату")

        self.private_key = private_key
        self.client_cert_pem = cert_bytes.decode('utf-8')

    @staticmethod
    def _identity_paths(nickname: str) -> tuple[str, str]:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(base_dir, f"{nickname}.crt"), os.path.join(base_dir, f"{nickname}.key")

    def _build_csr_for_nickname(self, nickname: str) -> str:
        if not isinstance(self.private_key, rsa.RSAPrivateKey):
            raise ValueError("Для авто-выпуска поддерживаются только RSA-ключи")
        csr = (
            # CSR фиксирует CN=nickname, сервер подпишет только корректный запрос.
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "RU"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SUN_IN"),
                    x509.NameAttribute(NameOID.COMMON_NAME, nickname),
                ])
            )
            .sign(self.private_key, hashes.SHA256())
        )
        return csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    def _load_peer_public_key(self, nickname: str, cert_pem: str):
        cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
        self._verify_cert_signed_by_ca(cert)
        self._verify_cert_validity(cert)
        self._verify_nickname_in_cert(cert, nickname)
        key = cert.public_key()
        with self.keys_lock:
            self.peer_public_keys[nickname] = key

    def _get_peer_public_key(self, nickname: str):
        with self.keys_lock:
            return self.peer_public_keys.get(nickname)

    def request_peer_key(self, nickname: str):
        self.send_packet(Packet('key_request', to=nickname))

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
        return base64.b64encode(signature).decode('utf-8')

    def _encrypt_for_recipient(self, recipient: str, text: str) -> tuple[str, str, str]:
        peer_key = self._get_peer_public_key(recipient)
        if peer_key is None:
            raise ValueError(f"Ключ получателя {recipient} не найден")
        if not isinstance(peer_key, rsa.RSAPublicKey):
            raise ValueError("Поддерживаются только RSA-сертификаты получателя")

        aes_key = os.urandom(32)
        nonce = os.urandom(12)
        aesgcm = AESGCM(aes_key)
        # Гибридное E2E: текст шифруется AES-GCM, AES-ключ — RSA получателя.
        encrypted_text = aesgcm.encrypt(nonce, text.encode('utf-8'), None)
        encrypted_key = peer_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return (
            base64.b64encode(encrypted_key).decode('utf-8'),
            base64.b64encode(nonce).decode('utf-8'),
            base64.b64encode(encrypted_text).decode('utf-8')
        )

    def _decrypt_message(self, packet: Packet) -> str:
        if self.private_key is None:
            raise ValueError("Ключ клиента не загружен")
        if not isinstance(self.private_key, rsa.RSAPrivateKey):
            raise ValueError("Поддерживаются только RSA-ключи клиента")
        encrypted_key = base64.b64decode(packet.enc_key.encode('utf-8'))
        nonce = base64.b64decode(packet.nonce.encode('utf-8'))
        encrypted_text = base64.b64decode(packet.text.encode('utf-8'))
        aes_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, encrypted_text, None)
        return plaintext.decode('utf-8')

    def _send_pending_messages(self, recipient: str):
        queue = self.pending_messages.pop(recipient, [])
        for message_text in queue:
            self.send_message(message_text, recipient)

    def _recv_exactly(self, num_bytes: int) -> Optional[bytes]:
        """
        Вспомогательный метод. Считывает ровно num_bytes из сокета.
        """
        data = bytearray()
        while len(data) < num_bytes:
            try:
                packet = self.socket.recv(num_bytes - len(data))
                if not packet:
                    return None  # Соединение закрыто сервером
                data.extend(packet)
            except (ConnectionResetError, OSError):
                return None
        return bytes(data)

    def connect(self) -> bool:
        """Подключение к серверу"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.connected = True
            logger.info(f"Подключено к серверу {self.host}:{self.port}")
            
            # Запускаем поток для прослушивания сообщений от сервера
            self.listener_thread = threading.Thread(target=self._listen_server, daemon=True)
            self.listener_thread.start()
            
            return True
        except Exception as e:
            logger.error(f"Ошибка подключения: {e}")
            return False

    def _listen_server(self):
        """Цикл чтения данных от сервера (работает в отдельном потоке)"""
        logger.info("Запущен поток прослушивания сервера")
        try:
            while self.connected:
                # 1. Читаем ровно 4 байта (заголовок с длиной сообщения)
                length_bytes = self._recv_exactly(4)
                if not length_bytes:
                    logger.warning("Сервер закрыл соединение")
                    break

                # Распаковываем 4 байта в целое число
                msg_length = struct.unpack('!I', length_bytes)[0]

                # 2. Читаем ровно столько байт, сколько указано в длине
                payload = self._recv_exactly(msg_length)
                if not payload:
                    break

                # Декодируем и парсим
                json_str = payload.decode('utf-8')
                packet = Packet.from_json(json_str)

                logger.debug(f"Получено: {packet.msg_type}")
                self._handle_packet(packet)

        except Exception as e:
            logger.error(f"Ошибка при чтении от сервера: {e}")
        finally:
            self.disconnect()

    def _handle_packet(self, packet: Packet):
        """Обработка полученных пакетов от сервера"""
        if packet.msg_type == 'event':
            if packet.event == 'auth_success':
                self.nickname = self.pending_nickname
                self.pending_nickname = None
                self.authenticated = True
                self.auth_error = None
                self.auth_result_event.set()
                print(f"\n✓ {packet.text}")
            elif packet.event == 'users_list':
                print(f"\n{packet.text}")
            elif packet.event == 'user_joined':
                print(f"\n► {packet.text}")
            elif packet.event == 'user_left':
                print(f"\n◄ {packet.text}")
            else:
                print(f"\n[Событие] {packet.event}: {packet.text if packet.text else ''}")

        elif packet.msg_type == 'auth_challenge':
            if not packet.nonce:
                print("\n✗ Ошибка: challenge без nonce")
                print(f"[{self.pending_nickname or '?'}] > ", end='', flush=True)
                return
            try:
                nonce_bytes = base64.b64decode(packet.nonce.encode('utf-8'))
                # Подписываем challenge приватным ключом из клиентского сертификата.
                signature_b64 = self._sign_payload(nonce_bytes)
                self.send_packet(Packet('auth_proof', signature=signature_b64))
            except Exception as e:
                self.auth_error = f"Ошибка подписи challenge: {e}"
                self.auth_result_event.set()
                print(f"\n✗ {self.auth_error}")
                print(f"[{self.pending_nickname or '?'}] > ", end='', flush=True)

        elif packet.msg_type == 'cert_enroll_response':
            if not packet.nickname or not packet.client_cert:
                self.enroll_error = "Получен некорректный cert_enroll_response"
                self.enroll_result_event.set()
                return
            if self.enroll_nickname and packet.nickname != self.enroll_nickname:
                self.enroll_error = "Никнейм в cert_enroll_response не совпадает"
                self.enroll_result_event.set()
                return
            try:
                cert = x509.load_pem_x509_certificate(packet.client_cert.encode('utf-8'))
                # Сразу валидируем выданный сервером сертификат перед сохранением.
                self._verify_cert_signed_by_ca(cert)
                self._verify_cert_validity(cert)
                self._verify_nickname_in_cert(cert, packet.nickname)
                if self.private_key is None:
                    raise ValueError("Локальный приватный ключ отсутствует")
                if self.private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ) != cert.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ):
                    raise ValueError("Сертификат не соответствует локальному ключу")
                cert_path, key_path = self._identity_paths(packet.nickname)
                with open(cert_path, 'wb') as f:
                    f.write(packet.client_cert.encode('utf-8'))
                with open(key_path, 'wb') as f:
                    f.write(self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption(),
                    ))
                self.client_cert_pem = packet.client_cert
                self.enroll_error = None
            except Exception as e:
                self.enroll_error = f"Ошибка обработки выданного сертификата: {e}"
            self.enroll_result_event.set()

        elif packet.msg_type == 'message':
            from_user = packet.from_user
            try:
                text = self._decrypt_message(packet)
                print(f"\n[E2E от {from_user}]: {text}")
            except Exception as e:
                print(f"\n✗ Не удалось расшифровать сообщение от {from_user}: {e}")
            print(f"[{self.nickname}] > ", end='', flush=True)

        elif packet.msg_type == 'key_response':
            if not packet.nickname or not packet.client_cert:
                print("\n✗ Получен некорректный ответ с сертификатом")
                print(f"[{self.nickname}] > ", end='', flush=True)
                return

            try:
                self._load_peer_public_key(packet.nickname, packet.client_cert)
                print(f"\n✓ Получен сертификат пользователя {packet.nickname}")
                self._send_pending_messages(packet.nickname)
            except Exception as e:
                print(f"\n✗ Ошибка обработки сертификата пользователя {packet.nickname}: {e}")
            print(f"[{self.nickname}] > ", end='', flush=True)

        elif packet.msg_type == 'error':
            if self.enroll_nickname:
                self.enroll_error = packet.error
                self.enroll_result_event.set()
            if not self.authenticated and self.pending_nickname:
                self.auth_error = packet.error
                self.auth_result_event.set()
            print(f"\n✗ Ошибка: {packet.error}")
            prompt_nick = self.nickname or self.pending_nickname or "?"
            print(f"[{prompt_nick}] > ", end='', flush=True)

    def send_packet(self, packet: Packet) -> bool:
        """Отправка пакета на сервер"""
        if not self.connected:
            logger.error("Нет подключения к серверу")
            return False

        try:
            data = packet.to_json().encode('utf-8')
            header = struct.pack('!I', len(data))
            self.socket.sendall(header + data)
            return True
        except Exception as e:
            logger.error(f"Ошибка отправки данных: {e}")
            self.disconnect()
            return False

    def authenticate(self, nickname: str) -> bool:
        """Авторизация на сервере"""
        if self.ca_cert is None:
            self.auth_error = "Не загружен private_ca.crt"
            return False

        try:
            self._load_identity_for_nickname(nickname)
        except FileNotFoundError:
            try:
                # Автовыпуск: генерируем ключ, отправляем CSR и ждем cert_enroll_response.
                self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                csr_pem = self._build_csr_for_nickname(nickname)
                self.enroll_nickname = nickname
                self.enroll_error = None
                self.enroll_result_event.clear()
                if not self.send_packet(Packet('cert_enroll', nickname=nickname, csr=csr_pem)):
                    self.auth_error = "Ошибка отправки cert_enroll"
                    self.enroll_nickname = None
                    return False
                self.enroll_result_event.wait(timeout=5)
                self.enroll_nickname = None
                if self.enroll_error:
                    self.auth_error = f"Не удалось выпустить сертификат: {self.enroll_error}"
                    return False
                if not self.client_cert_pem:
                    self.auth_error = "Сервер не вернул сертификат"
                    return False
            except Exception as e:
                self.auth_error = f"Не удалось выпустить сертификат клиента: {e}"
                self.enroll_nickname = None
                return False
        except Exception as e:
            self.auth_error = f"Не удалось загрузить сертификат клиента: {e}"
            return False

        self.pending_nickname = nickname
        self.authenticated = False
        self.auth_error = None
        self.auth_result_event.clear()
        packet = Packet('auth_init', nickname=nickname, client_cert=self.client_cert_pem)
        if not self.send_packet(packet):
            return False
        self.auth_result_event.wait(timeout=5)
        return self.authenticated

    def send_message(self, text: str, to_user: Optional[str] = None):
        """Отправка приватного сообщения"""
        if not self.authenticated:
            print("\n✗ Сначала выполните авторизацию")
            return

        if not to_user:
            print("\n✗ Ошибка: необходимо указать получателя через @nickname")
            return

        peer_key = self._get_peer_public_key(to_user)
        if peer_key is None:
            self.pending_messages.setdefault(to_user, []).append(text)
            print(f"… запрашиваю сертификат пользователя {to_user}")
            self.request_peer_key(to_user)
            return

        try:
            enc_key, nonce, encrypted_text = self._encrypt_for_recipient(to_user, text)
        except Exception as e:
            print(f"\n✗ Ошибка шифрования: {e}")
            return

        packet = Packet('message', to=to_user, text=encrypted_text, enc_key=enc_key, nonce=nonce)
        self.send_packet(packet)

    def _verify_cert_signed_by_ca(self, cert: x509.Certificate):
        if self.ca_cert is None:
            raise ValueError("Не загружен CA-сертификат")
        ca_public_key = self.ca_cert.public_key()
        if isinstance(ca_public_key, rsa.RSAPublicKey):
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
            return
        if isinstance(ca_public_key, ec.EllipticCurvePublicKey):
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm)
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
    
    def parse_message(self, text: str) -> tuple:
        """
        Парсит сообщение и извлекает получателя, если указан через @nickname
        Возвращает (текст_сообщения, получатель или None)
        """
        text = text.strip()
        if text.startswith('@'):
            # Ищем первый пробел
            space_idx = text.find(' ')
            if space_idx > 1:
                # @nickname сообщение
                recipient = text[1:space_idx]
                message_text = text[space_idx+1:].strip()
                return (message_text, recipient)
            else:
                # Только @nickname без сообщения
                return ("", text[1:])
        return (text, None)

    def disconnect(self):
        """Отключение от сервера"""
        if self.connected:
            self.connected = False
            try:
                if self.socket:
                    self.socket.close()
            except Exception:
                pass
            logger.info("Отключено от сервера")

    def run_interactive(self):
        """Интерактивный режим работы клиента"""
        print("=" * 50)
        print("      Добро пожаловать в чат!")
        print("=" * 50)
        
        # Подключение к серверу
        if not self.connect():
            print("Не удалось подключиться к серверу. Завершение работы.")
            return

        # Авторизация
        nickname = input("\nВведите ваш никнейм: ").strip()
        if not nickname:
            print("Никнейм не может быть пустым!")
            self.disconnect()
            return

        if not self.authenticate(nickname):
            print(f"Ошибка авторизации! {self.auth_error or ''}".strip())
            self.disconnect()
            return

        time.sleep(0.5)

        print("Как отправлять сообщения:")
        print("  @nickname сообщение - отправить приватное сообщение")
        print("Команды:")
        print("  /quit - выход из чата")
        print("  /help - справка")
        print("  /list - список пользователей онлайн")
        print("-" * 50)

        try:
            while self.connected:
                message = input(f"[{self.nickname}] > ")
                
                if not message:
                    continue

                if message == '/quit':
                    print("Выход из чата...")
                    break
                elif message == '/help':
                    print("Доступные команды:")
                    print("  /quit - выход")
                    print("  /help - эта справка")
                    print("  /list - список пользователей онлайн")
                    print("Отправка сообщений:")
                    print("  @nickname сообщение - сообщение пользователю")
                    continue
                elif message == '/list':
                    print("Используйте @nickname для отправки сообщения")
                    continue
                else:
                    # Парсим сообщение - теперь обязательно должен быть @nickname
                    text, recipient = self.parse_message(message)
                    if not recipient:
                        print("✗ Необходимо указать получателя. Используйте: @nickname сообщение")
                        continue
                    if not text:
                        print("✗ Укажите текст сообщения после никнейма")
                        continue
                    self.send_message(text, to_user=recipient)

        except KeyboardInterrupt:
            print("\n\nПрервано пользователем")
        finally:
            self.disconnect()


if __name__ == '__main__':
    client = ChatClient()
    client.run_interactive()
