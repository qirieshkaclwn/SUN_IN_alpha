
Открыть: `http://127.0.0.1:8000`

## HTTP API

- `POST /api/connect` `{ "host": "127.0.0.1", "port": 8888, "nickname": "q1" }`
- `POST /api/send` `{ "to": "q2", "text": "hello" }`
- `POST /api/disconnect`
- `GET /api/events?since=0`
- `GET /api/state`

## WebSocket

- `GET /ws` — поток событий от gateway.
