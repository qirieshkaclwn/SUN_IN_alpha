# SUN_IN_- $$\alpha$$
## М3O-209БВ-24 Мизюрёв Ф.В.
чат-приложение на базе TCP-сокетов с end-to-end шифрованием (E2E).
Сервер используется как маршрутизатор: он знает, кто онлайн, хранит никнеймы и публичные ключи, но не может прочитать текст переписки.

## Что делает проект

- Подключает клиентов к общему TCP-серверу.
- Шифрует сообщения на стороне отправителя и расшифровывает только на стороне получателя.
- Отправляет системные уведомления о событиях чата и статусах доставки.

## Архитектура

- **Клиент**:
  - генерирует пару ключей (публичный/приватный);
  - регистрируется на сервере (ник + публичный ключ);
  - шифрует исходящие сообщения;
  - расшифровывает входящие сообщения.
- **Сервер**:
  - принимает подключения;
  - хранит соответствие `никнейм -> соединение + публичный ключ`;
  - пересылает зашифрованные payload нужному получателю;
  - отправляет служебные уведомления.

## Технологии

Базовый стек:

- `Python 3`
- `socket` — TCP-соединения
- `threading` — параллельная обработка клиентов
- `json` — формат сообщений
- `struct` — framing (длина пакета перед JSON)



## Как передаются сообщения

Обычно используется JSON-пакет с полем типа и payload


## Как работают уведомления

Сервер формирует служебные события (`type = event`) и отправляет их клиентам.

Примеры уведомлений:

- `auth_success` — успешено авторизация 
- `user_joined` — пользователь подключился
- `user_left` —  пользователь отключился
- `users_list` — list пользователей
...



Для формирования пакета будет реализованн класс
```
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

```
