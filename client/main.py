import socket
import threading
import json
import struct
import logging
from typing import Optional, Dict, Any
from datetime import datetime
import time

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


class ChatClient:
    """Клиент чата с поддержкой многопоточности"""

    def __init__(self, host='127.0.0.1', port=8888):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        self.nickname = None
        self.listener_thread = None

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
                print(f"\n✓ {packet.text}")
            elif packet.event == 'users_list':
                print(f"\n{packet.text}")
            elif packet.event == 'user_joined':
                print(f"\n► {packet.text}")
            elif packet.event == 'user_left':
                print(f"\n◄ {packet.text}")
            else:
                print(f"\n[Событие] {packet.event}: {packet.text if packet.text else ''}")

        elif packet.msg_type == 'message':
            from_user = packet.from_user
            if packet.to_user:
                print(f"\n[Приватно от {from_user}]: {packet.text}")
            else:
                print(f"\n[{from_user}]: {packet.text}")
            print(f"[{self.nickname}] > ", end='', flush=True)

        elif packet.msg_type == 'error':
            print(f"\n✗ Ошибка: {packet.error}")
            print(f"[{self.nickname}] > ", end='', flush=True)

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
        self.nickname = nickname
        packet = Packet('auth', nickname=nickname)
        return self.send_packet(packet)

    def send_message(self, text: str, to_user: Optional[str] = None):
        """Отправка приватного сообщения"""
        if not to_user:
            print("\n✗ Ошибка: необходимо указать получателя через @nickname")
            return
        
        packet = Packet('message', text=text, to=to_user)
        self.send_packet(packet)
    
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
            print("Ошибка авторизации!")
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
