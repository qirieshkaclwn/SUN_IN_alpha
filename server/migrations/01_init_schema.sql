-- ====================================================================
-- Схема базы данных PostgreSQL для сервера SUN_IN
-- Версия миграции: 01_init_schema.sql
-- ====================================================================

-- 1. Таблица пользователей
CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR(64) PRIMARY KEY,
    nickname VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Примечание: ограничение UNIQUE на nickname автоматически создает B-Tree индекс в PostgreSQL.

-- 2. Таблица X.509 сертификатов (PKI / E2E безопасность: 1 сертификат на пользователя)
CREATE TABLE IF NOT EXISTS certificates (
    user_id VARCHAR(64) PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
    cert_pem TEXT NOT NULL,
    fingerprint VARCHAR(128),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    revoked BOOLEAN NOT NULL DEFAULT FALSE
);

-- Примечание: PRIMARY KEY на user_id автоматически создает уникальный B-Tree индекс.

-- 3. Таблица прямых сообщений 1-на-1 (MSG_DIRECT)
CREATE TABLE IF NOT EXISTS direct_messages (
    id BIGSERIAL PRIMARY KEY,
    seq_id BIGINT NOT NULL,
    from_user_id VARCHAR(64) NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    to_user_id VARCHAR(64) NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    text TEXT NOT NULL,
    is_delivered BOOLEAN NOT NULL DEFAULT FALSE,
    delivered_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_direct_messages_sender_seq UNIQUE (from_user_id, seq_id)
);

-- Составной индекс для выборки и сортировки истории переписки между двумя пользователями
CREATE INDEX IF NOT EXISTS idx_direct_messages_dialog ON direct_messages(from_user_id, to_user_id, id DESC);
-- Частичный индекс для мгновенной выборки недоставленных оффлайн-сообщений
CREATE INDEX IF NOT EXISTS idx_direct_messages_undelivered ON direct_messages(to_user_id, id) WHERE is_delivered = FALSE;
CREATE INDEX IF NOT EXISTS idx_direct_messages_created_at ON direct_messages(created_at);

-- 4. Таблица групповых чатов (ChatInfo)
CREATE TABLE IF NOT EXISTS chats (
    chat_id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    creator_id VARCHAR(64) REFERENCES users(user_id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 5. Таблица участников групповых чатов (ChatJoinReq)
CREATE TABLE IF NOT EXISTS chat_members (
    chat_id VARCHAR(64) NOT NULL REFERENCES chats(chat_id) ON DELETE CASCADE,
    user_id VARCHAR(64) NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    joined_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (chat_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_chat_members_user_id ON chat_members(user_id);

-- 6. Таблица сообщений групповых чатов (ChatMsg)
CREATE TABLE IF NOT EXISTS chat_messages (
    id BIGSERIAL PRIMARY KEY,
    chat_id VARCHAR(64) NOT NULL REFERENCES chats(chat_id) ON DELETE CASCADE,
    from_user_id VARCHAR(64) REFERENCES users(user_id) ON DELETE SET NULL,
    text TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_chat_messages_chat_created ON chat_messages(chat_id, created_at DESC);

-- 7. Таблица активных сессий пользователей
CREATE TABLE IF NOT EXISTS sessions (
    session_id VARCHAR(128) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
