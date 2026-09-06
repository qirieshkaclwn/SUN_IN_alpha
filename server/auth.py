"""
Модуль аутентификации и управления сессиями SUN_IN.

Поддерживает:
- Валидацию никнеймов (длина, допустимые символы).
- Регистрацию новых пользователей с генерацией безопасных криптографических токенов и user_id.
- Вход по сессионным токенам и паролям (PBKDF2-HMAC-SHA256).
- Challenge-Response криптографическую авторизацию (nonce + proof).
- Управление временем жизни сессий (TTL) и защиту от захвата никнеймов.
"""
from dataclasses import dataclass, field
import hashlib
import hmac
import logging
import re
import secrets
import time
from typing import Dict, Optional, Tuple

logger = logging.getLogger("SUN_IN.Auth")

# Регулярное выражение для никнейма: 3-32 символа, латиница, цифры, дефис, подчеркивание
NICKNAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]{3,32}$")

# Время жизни сессии: 30 дней
DEFAULT_SESSION_TTL_SECONDS = 30 * 24 * 60 * 60

# Время жизни challenge nonce: 60 секунд
CHALLENGE_TTL_SECONDS = 60


@dataclass
class UserRecord:
    user_id: str
    nickname: str
    token_hash: str
    salt: str
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)


@dataclass
class SessionRecord:
    session_id: str
    user_id: str
    nickname: str
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + DEFAULT_SESSION_TTL_SECONDS)


@dataclass
class ChallengeRecord:
    nickname: str
    nonce: bytes
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + CHALLENGE_TTL_SECONDS)


@dataclass
class AuthResult:
    success: bool
    message: str
    user_id: str = ""
    nickname: str = ""
    session_token: str = ""
    is_new_user: bool = False


class AuthManager:
    """Менеджер учетных записей, авторизации и сессий."""

    def __init__(self, session_ttl: int = DEFAULT_SESSION_TTL_SECONDS):
        self.session_ttl = session_ttl
        # Хранилище пользователей: lowercase_nickname -> UserRecord
        self.users: Dict[str, UserRecord] = {}
        # Хранилище сессий: session_id -> SessionRecord
        self.sessions: Dict[str, SessionRecord] = {}
        # Активные challenge: nonce_hex -> ChallengeRecord
        self.pending_challenges: Dict[str, ChallengeRecord] = {}

    @staticmethod
    def validate_nickname(nickname: str) -> Tuple[bool, str]:
        """Проверяет корректность формата никнейма."""
        if not nickname:
            return False, "Никнейм не может быть пустым"
        nick = nickname.strip()
        if len(nick) < 3:
            return False, "Никнейм слишком короткий (минимум 3 символа)"
        if len(nick) > 32:
            return False, "Никнейм слишком длинный (максимум 32 символа)"
        if not NICKNAME_REGEX.match(nick):
            return False, "Никнейм может содержать только латинские буквы, цифры, '_' и '-'"
        return True, ""

    @staticmethod
    def hash_secret(secret: str, salt: str) -> str:
        """Хэширует секрет/пароль/токен с солью через PBKDF2-HMAC-SHA256."""
        return hashlib.pbkdf2_hmac(
            "sha256",
            secret.encode("utf-8"),
            salt.encode("utf-8"),
            iterations=100_000,
        ).hex()

    def register_or_login(self, nickname: str, token: str = "") -> AuthResult:
        """
        Основной метод авторизации:
        1. Если пользователь новый — регистрирует и выдает персональный токен.
        2. Если пользователь существует — сверяет токен/сессию.
        """
        is_valid, err = self.validate_nickname(nickname)
        if not is_valid:
            return AuthResult(success=False, message=err)

        nick_clean = nickname.strip()
        nick_key = nick_clean.lower()
        token_clean = token.strip() if token else ""

        # 1. Новый пользователь -> Регистрация
        if nick_key not in self.users:
            salt = secrets.token_hex(16)
            # Если токен не передан пользователем, генерируем надежный ключ
            assigned_token = token_clean if token_clean and token_clean != "dummy_token" else secrets.token_urlsafe(32)
            token_hash = self.hash_secret(assigned_token, salt)
            user_id = f"usr_{secrets.token_hex(4)}"

            user = UserRecord(
                user_id=user_id,
                nickname=nick_clean,
                token_hash=token_hash,
                salt=salt,
            )
            self.users[nick_key] = user

            # Создаем сессию
            session_id = secrets.token_urlsafe(32)
            self.sessions[session_id] = SessionRecord(
                session_id=session_id,
                user_id=user_id,
                nickname=nick_clean,
                expires_at=time.time() + self.session_ttl,
            )

            logger.info(f"Зарегистрирован новый пользователь: @{nick_clean} (id={user_id})")
            return AuthResult(
                success=True,
                message=f"Успешная регистрация. Ваш токен: {assigned_token}",
                user_id=user_id,
                nickname=nick_clean,
                session_token=assigned_token,
                is_new_user=True,
            )

        # 2. Существующий пользователь -> Проверка подлинности
        user = self.users[nick_key]

        # Если токен не предоставлен или это плейсхолдер при существующем аккаунте
        if not token_clean or token_clean == "dummy_token":
            return AuthResult(
                success=False,
                message=f"Пользователь @{user.nickname} уже зарегистрирован. Введите персональный токен или пароль для входа.",
                nickname=user.nickname,
            )

        # Проверка 1: Может быть передан действующий session_id
        session = self.sessions.get(token_clean)
        if session and session.user_id == user.user_id and session.expires_at > time.time():
            user.last_seen = time.time()
            session.expires_at = time.time() + self.session_ttl
            logger.info(f"Успешный вход по сессии: @{user.nickname} (id={user.user_id})")
            return AuthResult(
                success=True,
                message="Вход выполнен успешно (по сессии)",
                user_id=user.user_id,
                nickname=user.nickname,
                session_token=token_clean,
            )

        # Проверка 2: Проверка по паролю/токену пользователя
        computed_hash = self.hash_secret(token_clean, user.salt)
        if hmac.compare_digest(computed_hash, user.token_hash):
            user.last_seen = time.time()
            # Создаем новую сессию
            session_id = secrets.token_urlsafe(32)
            self.sessions[session_id] = SessionRecord(
                session_id=session_id,
                user_id=user.user_id,
                nickname=user.nickname,
                expires_at=time.time() + self.session_ttl,
            )
            logger.info(f"Успешный вход по токену: @{user.nickname} (id={user.user_id})")
            return AuthResult(
                success=True,
                message="Вход выполнен успешно",
                user_id=user.user_id,
                nickname=user.nickname,
                session_token=session_id,
            )

        # Неверный токен
        logger.warning(f"Неудачная попытка входа для @{user.nickname}: неверный токен")
        return AuthResult(
            success=False,
            message=f"Неверный токен или пароль для пользователя @{user.nickname}",
            nickname=user.nickname,
        )

    def create_challenge(self, nickname: str) -> Tuple[Optional[bytes], str]:
        """Генерирует криптографический nonce для проверки подлинности."""
        is_valid, err = self.validate_nickname(nickname)
        if not is_valid:
            return None, err

        nick_clean = nickname.strip()
        nonce = secrets.token_bytes(32)
        nonce_hex = nonce.hex()

        self.pending_challenges[nonce_hex] = ChallengeRecord(
            nickname=nick_clean,
            nonce=nonce,
            expires_at=time.time() + CHALLENGE_TTL_SECONDS,
        )
        return nonce, ""

    def verify_proof(self, nonce: bytes, proof: bytes) -> AuthResult:
        """
        Проверяет доказательство (proof) на ранее отправленный challenge nonce.
        Proof вычисляется как HMAC-SHA256(token_hash, nonce).
        """
        nonce_hex = nonce.hex()
        challenge = self.pending_challenges.pop(nonce_hex, None)

        if not challenge:
            return AuthResult(success=False, message="Challenge истек или не существует")

        if challenge.expires_at < time.time():
            return AuthResult(success=False, message="Срок действия challenge истек")

        nick_key = challenge.nickname.lower()
        user = self.users.get(nick_key)
        if not user:
            return AuthResult(success=False, message="Пользователь не найден")

        # Ожидаемый proof = HMAC-SHA256 от token_hash и nonce
        expected_proof = hmac.new(
            user.token_hash.encode("utf-8"),
            nonce,
            hashlib.sha256,
        ).digest()

        if not hmac.compare_digest(expected_proof, proof):
            logger.warning(f"Неверное доказательство (proof) для @{user.nickname}")
            return AuthResult(success=False, message="Криптографическое доказательство неверно")

        user.last_seen = time.time()
        session_id = secrets.token_urlsafe(32)
        self.sessions[session_id] = SessionRecord(
            session_id=session_id,
            user_id=user.user_id,
            nickname=user.nickname,
            expires_at=time.time() + self.session_ttl,
        )

        logger.info(f"Успешная Challenge-Response авторизация: @{user.nickname}")
        return AuthResult(
            success=True,
            message="Криптографическая авторизация успешна",
            user_id=user.user_id,
            nickname=user.nickname,
            session_token=session_id,
        )

    def get_user_by_session(self, session_id: str) -> Optional[UserRecord]:
        """Возвращает профиль пользователя по токену активной сессии."""
        session = self.sessions.get(session_id)
        if not session or session.expires_at < time.time():
            return None
        return self.users.get(session.nickname.lower())

    def purge_expired(self) -> int:
        """Очищает просроченные сессии и челленджи."""
        now = time.time()
        expired_sessions = [sid for sid, s in self.sessions.items() if s.expires_at < now]
        for sid in expired_sessions:
            del self.sessions[sid]

        expired_challenges = [nid for nid, c in self.pending_challenges.items() if c.expires_at < now]
        for nid in expired_challenges:
            del self.pending_challenges[nid]

        return len(expired_sessions) + len(expired_challenges)
