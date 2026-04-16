import socket
import threading
import json
import struct
import logging
import base64
import os
from typing import Optional, Dict, Any
from datetime import datetime, timezone, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec, ed25519, ed448

# Настройка логирования
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%H:%M:%S'
)

logger = logging.getLogger('ChatServer')


class Packet:
    VERSION = 1

    def __init__(self, msg_type: str, **kwargs):
        self.version = self.VERSION  # Версия протокола пакетов
        self.msg_type = msg_type  # Тип пакета: auth_init/auth_proof/message/event/error и т.д.
        self.timestamp = kwargs.get('timestamp', int(datetime.now().timestamp()))  # Unix-время создания пакета
        self.from_user = kwargs.get('from')  # Ник отправителя
        self.to_user = kwargs.get('to')  # Ник получателя (для приватного сообщения/запроса ключа)
        self.text = kwargs.get('text')  # Текст или E2E-шифротекст (base64)
        self.nickname = kwargs.get('nickname')  # Ник клиента в auth/enroll операциях
        self.client_cert = kwargs.get('client_cert')  # PEM-сертификат клиента
        self.csr = kwargs.get('csr')  # PEM CSR для выпуска сертификата на сервере
        self.enc_key = kwargs.get('enc_key')  # AES-ключ, зашифрованный публичным ключом получателя (base64)
        self.nonce = kwargs.get('nonce')  # nonce для AES-GCM (base64)
        self.signature = kwargs.get('signature')  # Подпись challenge/данных приватным ключом клиента (base64)
        self.event = kwargs.get('event')  # Имя системного события (auth_success, user_joined и т.п.)
        self.message_id = kwargs.get('message_id')  # Идентификатор сообщения (если используется)
        self.error = kwargs.get('error')  # Текст ошибки

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




class ClientHandler:
    """Обработчик одного клиента в отдельном потоке"""

    def __init__(self, client_socket: socket.socket, address: tuple, server: 'ChatServer'):
        self.socket = client_socket
        self.address = address
        self.server = server
        self.nickname = None
        self.public_key = None
        self.client_cert_pem = None
        self._pending_nickname = None
        self._pending_cert = None
        self._auth_nonce = None
        self.connected = True
    
    def get_nickname(self) -> Optional[str]:
        return self.nickname

    def _recv_exactly(self, num_bytes: int) -> Optional[bytes]:
        """
        Вспомогательный метод. Считывает ровно num_bytes из сокета.
        Это необходимо, так как socket.recv() не особо подходит.
        """
        data = bytearray()
        while len(data) < num_bytes:
            try:
                packet = self.socket.recv(num_bytes - len(data))
                if not packet:
                    return None  # Соединение закрыто клиентом
                data.extend(packet)
            except ConnectionResetError:
                return None
        return bytes(data)

    def start_listening(self):
        """Цикл чтения данных (работает в отдельном потоке)"""
        logger.info(f"Начинаем слушать клиента {self.address}")
        try:
            while self.connected:
                # 1. Читаем ровно 4 байта (заголовок с длиной сообщения)
                length_bytes = self._recv_exactly(4)
                if not length_bytes:
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

                logger.debug(f"[{self.address}] Получено: {packet.msg_type}")
                self.handle_packet(packet)

        except Exception as e:
            logger.error(f"Ошибка клиента {self.address}: {e}")
        finally:
            self.disconnect()

    def send_packet(self, packet: Packet):
        """Безопасная отправка пакета клиенту"""
        if not self.connected:
            return

        try:
            data = packet.to_json().encode('utf-8')
            header = struct.pack('!I', len(data))

            # sendall гарантирует, что отправятся все байты до конца
            self.socket.sendall(header + data)
        except Exception as e:
            logger.error(f"Ошибка отправки данных клиенту {self.address}: {e}")
            self.disconnect()

    def handle_packet(self, packet: Packet):
        """Принятие решений на основе пакета"""
        if packet.msg_type == 'auth_init':
            if self.nickname:
                self.send_packet(Packet('error', error="Повторная авторизация запрещена"))
                return

            if not packet.nickname or not packet.client_cert:
                self.send_packet(Packet('error', error="Для авторизации нужны nickname и client_cert"))
                return

            if self.server.find_client_by_nickname(packet.nickname):
                self.send_packet(Packet('error', error=f"Никнейм {packet.nickname} уже используется"))
                return

            try:
                # Проверяем, что сертификат подписан нашим CA и CN совпадает с ником.
                cert = self.server.validate_client_certificate(packet.client_cert, packet.nickname)
            except Exception as e:
                self.send_packet(Packet('error', error=f"Сертификат отклонен: {e}"))
                return

            self._pending_nickname = packet.nickname
            self._pending_cert = cert
            self.client_cert_pem = packet.client_cert
            self.public_key = cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            # Challenge-response: сервер выдает nonce, клиент должен подписать его своим ключом.
            self._auth_nonce = os.urandom(32)
            nonce_b64 = base64.b64encode(self._auth_nonce).decode('utf-8')
            self.send_packet(Packet('auth_challenge', nonce=nonce_b64))
            return

        elif packet.msg_type == 'auth_proof':
            if self.nickname:
                self.send_packet(Packet('error', error="Повторная авторизация запрещена"))
                return
            if not self._pending_nickname or not self._pending_cert or not self._auth_nonce:
                self.send_packet(Packet('error', error="Сначала отправьте auth_init"))
                return
            if not packet.signature:
                self.send_packet(Packet('error', error="Для auth_proof нужна подпись"))
                return

            try:
                signature = base64.b64decode(packet.signature.encode('utf-8'))
                # Доказательство владения приватным ключом из client_cert.
                self.server.verify_client_signature(self._pending_cert.public_key(), self._auth_nonce, signature)
            except Exception as e:
                self.send_packet(Packet('error', error=f"Проверка подписи не пройдена: {e}"))
                return

            self.nickname = self._pending_nickname
            self._pending_nickname = None
            self._pending_cert = None
            self._auth_nonce = None
            logger.info(f"Клиент {self.address} авторизовался как '{self.nickname}'")

            response = Packet.create_event('auth_success', text="Успешная авторизация!")
            self.send_packet(response)
            
            # Отправляем список пользователей онлайн
            online_users = self.server.get_online_users()
            if online_users:
                users_list = ", ".join(online_users)
                self.send_packet(Packet.create_event('users_list', text=f"Пользователи онлайн: {users_list}"))
            
            # Уведомляем всех о новом пользователе
            self.server.broadcast(
                Packet.create_event('user_joined', nickname=self.nickname, text=f"{self.nickname} присоединился к чату"),
                exclude=self
            )

        elif packet.msg_type == 'cert_enroll':
            if self.nickname:
                self.send_packet(Packet('error', error="Сертификат уже выдан для текущей сессии"))
                return
            if not packet.nickname or not packet.csr:
                self.send_packet(Packet('error', error="Для cert_enroll нужны nickname и csr"))
                return
            if self.server.find_client_by_nickname(packet.nickname):
                self.send_packet(Packet('error', error=f"Никнейм {packet.nickname} уже используется"))
                return
            try:
                # Выпуск сертификата по CSR для нового клиента.
                cert_pem = self.server.issue_client_certificate(packet.nickname, packet.csr)
            except Exception as e:
                self.send_packet(Packet('error', error=f"Не удалось выпустить сертификат: {e}"))
                return
            self.send_packet(Packet('cert_enroll_response', nickname=packet.nickname, client_cert=cert_pem))

        elif not self.nickname:
            logger.warning(f"Неавторизованный клиент {self.address} отправил {packet.msg_type}")
            self.send_packet(Packet('error', error="Сначала выполните авторизацию"))
            return

        elif packet.msg_type == 'message':
            # Все сообщения должны быть приватными
            if not packet.to_user:
                logger.warning(f"Клиент {self.nickname} попытался отправить публичное сообщение")
                error_packet = Packet('error', error="Публичные сообщения запрещены. Используйте @nickname для отправки")
                self.send_packet(error_packet)
                return

            if not packet.text or not packet.enc_key or not packet.nonce:
                self.send_packet(Packet('error', error="Сообщение должно быть в E2E формате (text, enc_key, nonce)"))
                return

            logger.info(f"E2E-сообщение от {self.nickname} к {packet.to_user}")
            relay_packet = Packet(
                'message',
                **{
                    'from': self.nickname,
                    'to': packet.to_user,
                    'text': packet.text,
                    'enc_key': packet.enc_key,
                    'nonce': packet.nonce
                }
            )
            # Отправляем только конкретному клиенту
            if not self.server.send_to_user(packet.to_user, relay_packet):
                # Если пользователь не найден, отправляем ошибку отправителю
                error_packet = Packet('error', error=f"Пользователь {packet.to_user} не найден")
                self.send_packet(error_packet)

        elif packet.msg_type == 'key_request':
            if not packet.to_user:
                self.send_packet(Packet('error', error="Для запроса ключа укажите to"))
                return

            target_cert = self.server.get_user_certificate(packet.to_user)
            if not target_cert:
                self.send_packet(Packet('error', error=f"Сертификат пользователя {packet.to_user} не найден"))
                return

            self.send_packet(Packet('key_response', nickname=packet.to_user, client_cert=target_cert))

    def disconnect(self):
        """Корректное закрытие соединения"""
        if self.connected:
            self.connected = False
            nickname = self.nickname
            try:
                self.socket.close()
            except Exception:
                pass
            self.server.remove_client(self)
            
            # Уведомляем всех об отключении пользователя
            if nickname:
                self.server.broadcast(
                    Packet.create_event('user_left', nickname=nickname, text=f"{nickname} покинул чат")
                )
            
            logger.info(f"Соединение с {self.address} закрыто.")



# ГЛАВНЫЙ КЛАСС СЕРВЕРА
class ChatServer:
    def __init__(self, host='127.0.0.1', port=8888):
        self.host = host
        self.port = port
        self.clients = set()
        base_dir = os.path.dirname(os.path.abspath(__file__))
        ca_path = os.path.join(base_dir, 'private_ca.crt')
        ca_key_path = os.path.join(base_dir, 'private_ca.key')
        with open(ca_path, 'rb') as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read())
        with open(ca_key_path, 'rb') as f:
            self.ca_private_key = serialization.load_pem_private_key(f.read(), password=None)

        # Настройка главного сокета сервера
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Позволяет переиспользовать порт сразу после перезапуска сервера
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def remove_client(self, client: ClientHandler):
        """Удаляет клиента из списка при отключении"""
        if client in self.clients:
            self.clients.remove(client)
            logger.debug(f"Клиент удален. Всего онлайн: {len(self.clients)}")
    
    def get_online_users(self) -> list:
        """Возвращает список никнеймов онлайн пользователей"""
        return [client.get_nickname() for client in self.clients if client.get_nickname()]

    def get_user_public_key(self, nickname: str) -> Optional[str]:
        client = self.find_client_by_nickname(nickname)
        if client:
            return client.public_key
        return None

    def get_user_certificate(self, nickname: str) -> Optional[str]:
        client = self.find_client_by_nickname(nickname)
        if client:
            return client.client_cert_pem
        return None

    def validate_client_certificate(self, client_cert_pem: str, nickname: str) -> x509.Certificate:
        cert = x509.load_pem_x509_certificate(client_cert_pem.encode('utf-8'))
        self._verify_cert_signed_by_ca(cert)
        self._verify_cert_validity(cert)
        self._verify_nickname_in_cert(cert, nickname)
        return cert

    def issue_client_certificate(self, nickname: str, csr_pem: str) -> str:
        csr = x509.load_pem_x509_csr(csr_pem.encode('utf-8'))
        # Ник закреплен в CN, чтобы сервер и клиенты проверяли привязку identity -> cert.
        self._verify_nickname_in_cert(csr, nickname)

        now = datetime.now(timezone.utc)
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        )
        cert = cert_builder.sign(private_key=self.ca_private_key, algorithm=hashes.SHA256())
        return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    def _verify_cert_signed_by_ca(self, cert: x509.Certificate):
        # Разрешаем только сертификаты, подписанные нашим private CA.
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

    @staticmethod
    def verify_client_signature(public_key, payload: bytes, signature: bytes):
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
            return
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
            return
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, payload)
            return
        if isinstance(public_key, ed448.Ed448PublicKey):
            public_key.verify(signature, payload)
            return
        raise ValueError("Неподдерживаемый тип ключа клиента")
    
    def find_client_by_nickname(self, nickname: str) -> Optional[ClientHandler]:
        """Находит клиента по никнейму"""
        for client in self.clients:
            if client.get_nickname() == nickname:
                return client
        return None
    
    def send_to_user(self, nickname: str, packet: Packet) -> bool:
        """Отправляет пакет конкретному пользователю по никнейму"""
        client = self.find_client_by_nickname(nickname)
        if client:
            try:
                client.send_packet(packet)
                return True
            except Exception as e:
                logger.error(f"Ошибка отправки клиенту {nickname}: {e}")
                client.disconnect()
                return False
        return False
    
    def broadcast(self, packet: Packet, exclude: ClientHandler = None):
        """Рассылка пакета всем подключенным клиентам исключая exclude"""
        logger.debug(f"Broadcast: {packet.msg_type} (исключая {exclude.nickname if exclude else 'никого'})")
        disconnected = []
        
        for client in self.clients:
            if client == exclude:
                continue
            
            try:
                client.send_packet(packet)
            except Exception as e:
                logger.error(f"Ошибка отправки клиенту {client.nickname}: {e}")
                disconnected.append(client)
        
        # Удаляем отключенных клиентов
        for client in disconnected:
            client.disconnect()

    def start(self):
        """Запуск сервера в основном потоке"""
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen()  # Слушаем и не ассуждаем
            logger.info(f"Сервер запущен на {self.host}:{self.port}...")

            while True:
                # Метод accept() блокирует выполнение
                client_socket, address = self.server_socket.accept()
                logger.info(f"Новое подключение: {address}")

                # Создаем обработчик
                client = ClientHandler(client_socket, address, server=self)
                self.clients.add(client)

                # daemon=True означает, что поток завершится автоматически при выключении сервера
                client_thread = threading.Thread(target=client.start_listening, daemon=True)
                client_thread.start()

        except KeyboardInterrupt:
            logger.info("Остановка сервера...")
        except Exception as e:
            logger.error(f"Критическая ошибка сервера: {e}")
        finally:
            self.server_socket.close()


if __name__ == '__main__':
    server = ChatServer()
    server.start()
