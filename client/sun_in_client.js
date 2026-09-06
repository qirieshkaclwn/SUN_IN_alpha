import protobuf from 'protobufjs';

/**
 * Универсальный клиент SUN_IN на базе Protobuf и WebSocket.
 * Работает как в браузере (нативный WebSocket), так и в Node.js.
 */
export class SunInClient {
    /**
     * @param {string} url WebSocket URL сервера (например ws://127.0.0.1:8765)
     * @param {string} nickname Никнейм пользователя
     */
    constructor(url = 'ws://127.0.0.1:8765', nickname = 'guest') {
        this.url = url;
        this.nickname = nickname;
        this.ws = null;
        this.root = null;
        this.Packet = null;
        this.PacketType = null;
        this.seqId = 0;
        this.listeners = new Map();
    }

    /**
     * Загрузка схемы Protobuf.
     * @param {string|object} protoSource Путь к .proto файлу или JSON-дескриптор
     */
    async loadProto(protoSource = '../proto/protocol.proto') {
        if (typeof protoSource === 'string') {
            this.root = await protobuf.load(protoSource);
        } else {
            this.root = protobuf.Root.fromJSON(protoSource);
        }
        this.Packet = this.root.lookupType('sun_in.Packet');
        this.PacketType = this.root.lookupEnum('sun_in.PacketType').values;
    }

    /**
     * Подключение к WebSocket серверу.
     */
    async connect() {
        if (!this.Packet) {
            await this.loadProto();
        }

        return new Promise((resolve, reject) => {
            // Поддержка WebSocket как в браузере (window.WebSocket), так и в Node.js
            let WebSocketImpl;
            if (typeof window !== 'undefined' && window.WebSocket) {
                WebSocketImpl = window.WebSocket;
            } else {
                WebSocketImpl = (globalThis.WebSocket || null);
            }

            if (!WebSocketImpl) {
                return reject(new Error('WebSocket реализация не найдена. В Node.js импортируйте ws'));
            }

            this.ws = new WebSocketImpl(this.url);
            this.ws.binaryType = 'arraybuffer';

            this.ws.onopen = () => {
                console.log(`[SUN_IN Client] Подключено к ${this.url}`);
                resolve();
            };

            this.ws.onerror = (err) => {
                console.error('[SUN_IN Client] Ошибка WebSocket:', err);
                reject(err);
            };

            this.ws.onclose = () => {
                console.log('[SUN_IN Client] Соединение закрыто');
                this._emit('close');
            };

            this.ws.onmessage = (event) => {
                const buffer = new Uint8Array(event.data);
                const message = this.Packet.decode(buffer);
                this._handleIncomingPacket(message);
            };
        });
    }

    /**
     * Подписка на события (например on('PONG', callback))
     */
    on(eventName, callback) {
        if (!this.listeners.has(eventName)) {
            this.listeners.set(eventName, []);
        }
        this.listeners.get(eventName).push(callback);
    }

    _emit(eventName, data) {
        const callbacks = this.listeners.get(eventName) || [];
        for (const cb of callbacks) {
            cb(data);
        }
    }

    _handleIncomingPacket(packet) {
        // Находим имя типа пакета
        let typeName = 'UNKNOWN';
        for (const [key, val] of Object.entries(this.PacketType)) {
            if (val === packet.type) {
                typeName = key;
                break;
            }
        }

        console.log(`[SUN_IN Client] Получен пакет: ${typeName} (seq=${packet.seqId})`);
        this._emit(typeName, packet);
        this._emit('packet', packet);
    }

    /**
     * Отправка произвольного пакета
     */
    sendPacket(type, payloadKey = null, payloadObj = null) {
        if (!this.ws || this.ws.readyState !== 1) {
            throw new Error('WebSocket не подключен!');
        }

        this.seqId += 1;
        const packetObj = {
            version: 1,
            seqId: this.seqId,
            timestamp: Date.now(),
            type: type,
        };

        if (payloadKey && payloadObj) {
            packetObj[payloadKey] = payloadObj;
        }

        const errMsg = this.Packet.verify(packetObj);
        if (errMsg) throw new Error('Ошибка валидации пакета: ' + errMsg);

        const message = this.Packet.create(packetObj);
        const buffer = this.Packet.encode(message).finish();
        this.ws.send(buffer);
        return this.seqId;
    }

    /**
     * Авторизация / регистрация на сервере
     */
    authenticate(token = '') {
        console.log(`[SUN_IN Client] Авторизация '${this.nickname}'...`);
        return this.sendPacket(this.PacketType.AUTH_INIT, 'authInit', {
            nickname: this.nickname,
            token: token || '',
        });
    }

    /**
     * Отправка тестового PING
     */
    ping() {
        console.log(`[SUN_IN Client] Отправка PING от '${this.nickname}'...`);
        return this.sendPacket(this.PacketType.PING, 'ping', { sender: this.nickname });
    }

    /**
     * Отправка прямого сообщения
     */
    sendDirectMessage(toUser, text) {
        return this.sendPacket(this.PacketType.MSG_DIRECT, 'msgDirect', {
            fromUser: this.nickname,
            toUser: toUser,
            text: text,
        });
    }

    /**
     * Закрыть соединение
     */
    disconnect() {
        if (this.ws) {
            this.ws.close();
        }
    }
}
