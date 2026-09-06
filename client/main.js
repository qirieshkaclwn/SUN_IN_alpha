import { SunInClient } from './sun_in_client.js';
import WebSocket from 'ws';
import path from 'path';
import { fileURLToPath } from 'url';

// Регистрируем WebSocket для Node.js окружения
globalThis.WebSocket = WebSocket;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function main() {
    const protoPath = path.resolve(__dirname, '../proto/protocol.proto');
    const client = new SunInClient('ws://127.0.0.1:8765', 'alice_js');

    // Загружаем схему
    await client.loadProto(protoPath);

    // Подписка на входящий ответ PONG
    client.on('PONG', (packet) => {
        console.log(`[OK] Ответ PONG получен! Сервер ответил: ${JSON.stringify(packet.pong)}`);
        client.disconnect();
        process.exit(0);
    });

    try {
        await client.connect();
        client.ping();
    } catch (e) {
        console.error('Ошибка подключения клиента:', e);
    }
}

main();
