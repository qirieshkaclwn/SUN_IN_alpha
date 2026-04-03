import socket
import threading
import json
import struct
import logging
from typing import Optional, Dict, Any
from datetime import datetime

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
        self.version = self.VERSION
        self.msg_type = msg_type
        self.timestamp = kwargs.get('timestamp', int(datetime.now().timestamp()))
        self.from_user = kwargs.get('from')
        self.to_user = kwargs.get('to')
        self.text = kwargs.get('text')
        self.nickname = kwargs.get('nickname')
        self.event = kwargs.get('event')
        self.message_id = kwargs.get('message_id')
        self.error = kwargs.get('error')

    def to_dict(self) -> Dict[str, Any]:
        data = {'version': self.version, 'type': self.msg_type, 'timestamp': self.timestamp}
        if self.from_user: data['from'] = self.from_user
        if self.to_user: data['to'] = self.to_user
        if self.text: data['text'] = self.text
        if self.nickname: data['nickname'] = self.nickname
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
        if packet.msg_type == 'auth':
            self.nickname = packet.nickname
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

        elif packet.msg_type == 'message':
            # Все сообщения должны быть приватными
            if not packet.to_user:
                logger.warning(f"Клиент {self.nickname} попытался отправить публичное сообщение")
                error_packet = Packet('error', error="Публичные сообщения запрещены. Используйте @nickname для отправки")
                self.send_packet(error_packet)
                return
            
            logger.info(f"Приватное сообщение от {self.nickname} к {packet.to_user}: {packet.text}")
            # Создаем пакет с информацией об отправителе и получателе
            relay_packet = Packet('message', text=packet.text, **{'from': self.nickname, 'to': packet.to_user})
            # Отправляем только конкретному клиенту
            if not self.server.send_to_user(packet.to_user, relay_packet):
                # Если пользователь не найден, отправляем ошибку отправителю
                error_packet = Packet('error', error=f"Пользователь {packet.to_user} не найден")
                self.send_packet(error_packet)

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