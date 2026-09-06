// sun_in_pure.js - Минимальный Protobuf кодек и клиент без внешних библиотек
// Работает в любом современном браузере

export const PacketType = {
    PACKET_TYPE_UNSPECIFIED: 0,
    PING: 1,
    PONG: 2,
    AUTH_INIT: 3,
    AUTH_CHALLENGE: 4,
    AUTH_PROOF: 5,
    AUTH_SUCCESS: 6,
    AUTH_FAIL: 7,
    USER_LIST_REQ: 8,
    USER_LIST_RESP: 9,
    MSG_DIRECT: 10,
    MSG_ACK: 11,
    CHAT_MSG: 12,
    CHAT_LIST_REQ: 13,
    CHAT_LIST_RESP: 14,
    CHAT_JOIN_REQ: 15,
    CHAT_JOIN_RESP: 16,
    ERROR: 20,
};

export const PacketTypeName = Object.fromEntries(
    Object.entries(PacketType).map(([k, v]) => [v, k])
);

// Простейший Protobuf энкодер (varint, string, embedded message)
class ProtoWriter {
    constructor() {
        this.bytes = [];
    }

    writeVarint(val) {
        val = BigInt(val);
        while (val > 0x7fn) {
            this.bytes.push(Number((val & 0x7fn) | 0x80n));
            val >>= 7n;
        }
        this.bytes.push(Number(val));
    }

    writeTag(fieldNumber, wireType) {
        this.writeVarint((fieldNumber << 3) | wireType);
    }

    writeUint32(fieldNumber, val) {
        if (val === 0 || val === undefined || val === null) return;
        this.writeTag(fieldNumber, 0);
        this.writeVarint(val);
    }

    writeUint64(fieldNumber, val) {
        if (val === 0 || val === 0n || val === undefined || val === null) return;
        this.writeTag(fieldNumber, 0);
        this.writeVarint(val);
    }

    writeString(fieldNumber, str) {
        if (!str) return;
        const encoded = new TextEncoder().encode(str);
        this.writeTag(fieldNumber, 2);
        this.writeVarint(encoded.length);
        for (let i = 0; i < encoded.length; i++) this.bytes.push(encoded[i]);
    }

    writeBytes(fieldNumber, bytes) {
        if (!bytes || bytes.length === 0) return;
        this.writeTag(fieldNumber, 2);
        this.writeVarint(bytes.length);
        for (let i = 0; i < bytes.length; i++) this.bytes.push(bytes[i]);
    }

    writeMessage(fieldNumber, writer) {
        const subBytes = writer.finish();
        if (subBytes.length === 0) return;
        this.writeTag(fieldNumber, 2);
        this.writeVarint(subBytes.length);
        for (let i = 0; i < subBytes.length; i++) this.bytes.push(subBytes[i]);
    }

    finish() {
        return new Uint8Array(this.bytes);
    }
}

// Простейший Protobuf декодер
class ProtoReader {
    constructor(buffer) {
        this.buf = new Uint8Array(buffer);
        this.pos = 0;
    }

    hasMore() {
        return this.pos < this.buf.length;
    }

    readVarint() {
        let res = 0n;
        let shift = 0n;
        while (this.pos < this.buf.length) {
            const b = BigInt(this.buf[this.pos++]);
            res |= (b & 0x7fn) << shift;
            if ((b & 0x80n) === 0n) break;
            shift += 7n;
        }
        return res;
    }

    readTag() {
        const tag = Number(this.readVarint());
        return { fieldNumber: tag >> 3, wireType: tag & 0x07 };
    }

    skip(wireType) {
        if (wireType === 0) {
            this.readVarint();
        } else if (wireType === 2) {
            const len = Number(this.readVarint());
            this.pos += len;
        } else if (wireType === 1) {
            this.pos += 8;
        } else if (wireType === 5) {
            this.pos += 4;
        }
    }

    readString() {
        const len = Number(this.readVarint());
        const slice = this.buf.subarray(this.pos, this.pos + len);
        this.pos += len;
        return new TextDecoder().decode(slice);
    }

    readBytes() {
        const len = Number(this.readVarint());
        const slice = this.buf.subarray(this.pos, this.pos + len);
        this.pos += len;
        return new Uint8Array(slice);
    }

    readSubReader() {
        const len = Number(this.readVarint());
        const slice = this.buf.subarray(this.pos, this.pos + len);
        this.pos += len;
        return new ProtoReader(slice);
    }
}

export function encodePacket(pkt) {
    const w = new ProtoWriter();
    w.writeUint32(1, pkt.version || 1);
    w.writeUint64(2, pkt.seq_id || 0);
    w.writeUint64(3, pkt.timestamp || Date.now());
    w.writeUint32(4, pkt.type || 0);

    if (pkt.ping) {
        const sub = new ProtoWriter();
        sub.writeString(1, pkt.ping.sender);
        w.writeMessage(10, sub);
    } else if (pkt.pong) {
        const sub = new ProtoWriter();
        sub.writeString(1, pkt.pong.sender);
        w.writeMessage(11, sub);
    } else if (pkt.auth_init) {
        const sub = new ProtoWriter();
        sub.writeString(1, pkt.auth_init.nickname);
        sub.writeString(2, pkt.auth_init.token || "");
        w.writeMessage(12, sub);
    } else if (pkt.auth_challenge) {
        const sub = new ProtoWriter();
        sub.writeBytes(1, pkt.auth_challenge.nonce);
        w.writeMessage(13, sub);
    } else if (pkt.auth_proof) {
        const sub = new ProtoWriter();
        sub.writeBytes(1, pkt.auth_proof.proof);
        w.writeMessage(14, sub);
    } else if (pkt.msg_direct) {
        const sub = new ProtoWriter();
        sub.writeString(1, pkt.msg_direct.from_user);
        sub.writeString(2, pkt.msg_direct.to_user);
        sub.writeString(3, pkt.msg_direct.text);
        w.writeMessage(19, sub);
    } else if (pkt.chat_msg) {
        const sub = new ProtoWriter();
        sub.writeString(1, pkt.chat_msg.chat_id);
        sub.writeString(2, pkt.chat_msg.from_user);
        sub.writeString(3, pkt.chat_msg.text);
        w.writeMessage(21, sub);
    } else if (pkt.user_list_req) {
        const sub = new ProtoWriter();
        w.writeMessage(17, sub);
    }
    return w.finish();
}

export function decodePacket(buffer) {
    const r = new ProtoReader(buffer);
    const pkt = { version: 1, seq_id: 0, timestamp: 0, type: 0 };

    while (r.hasMore()) {
        const { fieldNumber, wireType } = r.readTag();
        if (fieldNumber === 1) pkt.version = Number(r.readVarint());
        else if (fieldNumber === 2) pkt.seq_id = Number(r.readVarint());
        else if (fieldNumber === 3) pkt.timestamp = Number(r.readVarint());
        else if (fieldNumber === 4) pkt.type = Number(r.readVarint());
        else if (fieldNumber === 10) {
            const sub = r.readSubReader();
            pkt.ping = { sender: '' };
            while (sub.hasMore()) {
                const tag = sub.readTag();
                if (tag.fieldNumber === 1) pkt.ping.sender = sub.readString();
                else sub.skip(tag.wireType);
            }
        } else if (fieldNumber === 11) {
            const sub = r.readSubReader();
            pkt.pong = { sender: '' };
            while (sub.hasMore()) {
                const tag = sub.readTag();
                if (tag.fieldNumber === 1) pkt.pong.sender = sub.readString();
                else sub.skip(tag.wireType);
            }
        } else if (fieldNumber === 13) {
            const sub = r.readSubReader();
            pkt.auth_challenge = { nonce: new Uint8Array(0) };
            while (sub.hasMore()) {
                const tag = sub.readTag();
                if (tag.fieldNumber === 1) pkt.auth_challenge.nonce = sub.readBytes();
                else sub.skip(tag.wireType);
            }
        } else if (fieldNumber === 14) {
            const sub = r.readSubReader();
            pkt.auth_proof = { proof: new Uint8Array(0) };
            while (sub.hasMore()) {
                const tag = sub.readTag();
                if (tag.fieldNumber === 1) pkt.auth_proof.proof = sub.readBytes();
                else sub.skip(tag.wireType);
            }
        } else if (fieldNumber === 15) {
            const sub = r.readSubReader();
            pkt.auth_success = { user_id: '', nickname: '', message: '' };
            while (sub.hasMore()) {
                const tag = sub.readTag();
                if (tag.fieldNumber === 1) pkt.auth_success.user_id = sub.readString();
                else if (tag.fieldNumber === 2) pkt.auth_success.nickname = sub.readString();
                else if (tag.fieldNumber === 3) pkt.auth_success.message = sub.readString();
                else sub.skip(tag.wireType);
            }
        } else if (fieldNumber === 16) {
            const sub = r.readSubReader();
            pkt.auth_fail = { reason: '' };
            while (sub.hasMore()) {
                const tag = sub.readTag();
                if (tag.fieldNumber === 1) pkt.auth_fail.reason = sub.readString();
                else sub.skip(tag.wireType);
            }
        } else if (fieldNumber === 18) {
            const sub = r.readSubReader();
            pkt.user_list_resp = { users: [] };
            while (sub.hasMore()) {
                const tag = sub.readTag();
                if (tag.fieldNumber === 1) pkt.user_list_resp.users.push(sub.readString());
                else sub.skip(tag.wireType);
            }
        } else if (fieldNumber === 19) {
            const sub = r.readSubReader();
            pkt.msg_direct = { from_user: '', to_user: '', text: '' };
            while (sub.hasMore()) {
                const tag = sub.readTag();
                if (tag.fieldNumber === 1) pkt.msg_direct.from_user = sub.readString();
                else if (tag.fieldNumber === 2) pkt.msg_direct.to_user = sub.readString();
                else if (tag.fieldNumber === 3) pkt.msg_direct.text = sub.readString();
                else sub.skip(tag.wireType);
            }
        } else if (fieldNumber === 21) {
            const sub = r.readSubReader();
            pkt.chat_msg = { chat_id: '', from_user: '', text: '' };
            while (sub.hasMore()) {
                const tag = sub.readTag();
                if (tag.fieldNumber === 1) pkt.chat_msg.chat_id = sub.readString();
                else if (tag.fieldNumber === 2) pkt.chat_msg.from_user = sub.readString();
                else if (tag.fieldNumber === 3) pkt.chat_msg.text = sub.readString();
                else sub.skip(tag.wireType);
            }
        } else if (fieldNumber === 23) {
            const sub = r.readSubReader();
            pkt.chat_list_resp = { chats: [] };
            while (sub.hasMore()) {
                const tag = sub.readTag();
                if (tag.fieldNumber === 1) {
                    const cSub = sub.readSubReader();
                    const chat = { chat_id: '', name: '', member_count: 0 };
                    while (cSub.hasMore()) {
                        const cTag = cSub.readTag();
                        if (cTag.fieldNumber === 1) chat.chat_id = cSub.readString();
                        else if (cTag.fieldNumber === 2) chat.name = cSub.readString();
                        else if (cTag.fieldNumber === 3) chat.member_count = Number(cSub.readVarint());
                        else cSub.skip(cTag.wireType);
                    }
                    pkt.chat_list_resp.chats.push(chat);
                } else sub.skip(tag.wireType);
            }
        } else if (fieldNumber === 25) {
            const sub = r.readSubReader();
            pkt.chat_join_resp = { chat_id: '', success: false, message: '' };
            while (sub.hasMore()) {
                const tag = sub.readTag();
                if (tag.fieldNumber === 1) pkt.chat_join_resp.chat_id = sub.readString();
                else if (tag.fieldNumber === 2) pkt.chat_join_resp.success = Boolean(sub.readVarint());
                else if (tag.fieldNumber === 3) pkt.chat_join_resp.message = sub.readString();
                else sub.skip(tag.wireType);
            }
        } else if (fieldNumber === 26) {
            const sub = r.readSubReader();
            pkt.error = { code: 0, message: '' };
            while (sub.hasMore()) {
                const tag = sub.readTag();
                if (tag.fieldNumber === 1) pkt.error.code = Number(sub.readVarint());
                else if (tag.fieldNumber === 2) pkt.error.message = sub.readString();
                else sub.skip(tag.wireType);
            }
        } else {
            r.skip(wireType);
        }
    }
    return pkt;
}

export class SunInClient {
    constructor(url = 'ws://127.0.0.1:8888', nickname = 'web_user') {
        this.url = url;
        this.nickname = nickname;
        this.ws = null;
        this.seqId = 0;
        this.listeners = {};
    }

    on(event, cb) {
        if (!this.listeners[event]) this.listeners[event] = [];
        this.listeners[event].push(cb);
    }

    _emit(event, data) {
        (this.listeners[event] || []).forEach(cb => cb(data));
    }

    connect() {
        return new Promise((resolve, reject) => {
            this.ws = new WebSocket(this.url);
            this.ws.binaryType = 'arraybuffer';

            this.ws.onopen = () => {
                this._emit('open');
                resolve();
            };
            this.ws.onclose = () => this._emit('close');
            this.ws.onerror = (e) => {
                this._emit('error', e);
                reject(e);
            };
            this.ws.onmessage = (evt) => {
                const pkt = decodePacket(evt.data);
                const typeName = PacketTypeName[pkt.type] || 'UNKNOWN';
                this._emit(typeName, pkt);
                this._emit('packet', pkt);
            };
        });
    }

    send(packetData) {
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
            throw new Error('WebSocket не подключен');
        }
        this.seqId++;
        packetData.seq_id = this.seqId;
        packetData.timestamp = Date.now();
        packetData.version = 1;
        const bytes = encodePacket(packetData);
        this.ws.send(bytes);
        return this.seqId;
    }

    ping() {
        return this.send({
            type: PacketType.PING,
            ping: { sender: this.nickname }
        });
    }

    authenticate(nickname, token = "") {
        this.nickname = nickname;
        return this.send({
            type: PacketType.AUTH_INIT,
            auth_init: {
                nickname: nickname,
                token: token || ""
            }
        });
    }

    sendProof(proof) {
        return this.send({
            type: PacketType.AUTH_PROOF,
            auth_proof: {
                proof: proof
            }
        });
    }

    requestUsers() {
        return this.send({
            type: PacketType.USER_LIST_REQ,
            user_list_req: {}
        });
    }

    requestChats() {
        return this.send({
            type: PacketType.CHAT_LIST_REQ,
            chat_list_req: {}
        });
    }

    joinChat(chatId) {
        return this.send({
            type: PacketType.CHAT_JOIN_REQ,
            chat_join_req: {
                chat_id: chatId
            }
        });
    }

    sendChatMsg(chatId, text) {
        return this.send({
            type: PacketType.CHAT_MSG,
            chat_msg: {
                chat_id: chatId,
                from_user: this.nickname,
                text: text
            }
        });
    }

    sendDirect(toUser, text) {
        return this.send({
            type: PacketType.MSG_DIRECT,
            msg_direct: {
                from_user: this.nickname,
                to_user: toUser,
                text: text
            }
        });
    }

    disconnect() {
        if (this.ws) this.ws.close();
    }
}
