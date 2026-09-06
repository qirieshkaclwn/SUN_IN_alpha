"""
Unit-тесты для модуля авторизации server/auth.py.
"""
import hashlib
import hmac
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from server.auth import AuthManager


class TestAuthManager(unittest.TestCase):
    def setUp(self):
        self.auth = AuthManager(session_ttl=3600)

    def test_nickname_validation(self):
        """Проверка валидации никнеймов."""
        # Корректные
        self.assertTrue(self.auth.validate_nickname("alice")[0])
        self.assertTrue(self.auth.validate_nickname("bob_123")[0])
        self.assertTrue(self.auth.validate_nickname("user-name-99")[0])

        # Некорректные
        self.assertFalse(self.auth.validate_nickname("")[0])
        self.assertFalse(self.auth.validate_nickname("al")[0])  # слишком короткий (<3)
        self.assertFalse(self.auth.validate_nickname("a" * 33)[0])  # слишком длинный (>32)
        self.assertFalse(self.auth.validate_nickname("alice smith")[0])  # пробелы
        self.assertFalse(self.auth.validate_nickname("alice@domain")[0])  # недопустимые символы

    def test_register_and_login_flow(self):
        """Тест регистрации и повторного входа пользователя."""
        # 1. Регистрация нового пользователя
        res_reg = self.auth.register_or_login("alice", "secret_pass_123")
        self.assertTrue(res_reg.success)
        self.assertTrue(res_reg.is_new_user)
        self.assertEqual(res_reg.nickname, "alice")
        self.assertTrue(res_reg.user_id.startswith("usr_"))
        self.assertIsNotNone(res_reg.session_token)

        # 2. Вход с верным паролем
        res_login_ok = self.auth.register_or_login("alice", "secret_pass_123")
        self.assertTrue(res_login_ok.success)
        self.assertFalse(res_login_ok.is_new_user)
        self.assertEqual(res_login_ok.user_id, res_reg.user_id)

        # 3. Вход с неверным паролем
        res_login_fail = self.auth.register_or_login("alice", "wrong_pass")
        self.assertFalse(res_login_fail.success)
        self.assertIn("Неверный токен или пароль", res_login_fail.message)

        # 4. Попытка входа без пароля на занятый ник
        res_no_pass = self.auth.register_or_login("alice", "")
        self.assertFalse(res_no_pass.success)
        self.assertIn("уже зарегистрирован", res_no_pass.message)

    def test_session_token_login(self):
        """Тест повторного входа по полученному session_token."""
        res_reg = self.auth.register_or_login("bob", "bob_password")
        self.assertTrue(res_reg.success)
        session_token = res_reg.session_token

        # Вход по session_token
        res_session = self.auth.register_or_login("bob", session_token)
        self.assertTrue(res_session.success)
        self.assertEqual(res_session.user_id, res_reg.user_id)

    def test_challenge_response_authentication(self):
        """Тест криптографической схемы Challenge-Response."""
        # Регистрируем пользователя
        self.auth.register_or_login("charlie", "charlie_key")
        user = self.auth.users["charlie"]

        # Создаем challenge
        nonce, err = self.auth.create_challenge("charlie")
        self.assertIsNotNone(nonce)
        self.assertEqual(len(nonce), 32)
        self.assertEqual(err, "")

        # Формируем корректный proof: HMAC-SHA256(token_hash, nonce)
        correct_proof = hmac.new(
            user.token_hash.encode("utf-8"),
            nonce,
            hashlib.sha256,
        ).digest()

        # Проверяем успешный ответ
        res_ok = self.auth.verify_proof(nonce, correct_proof)
        self.assertTrue(res_ok.success)
        self.assertEqual(res_ok.nickname, "charlie")

        # Пробуем еще один challenge с некорректным proof
        nonce2, _ = self.auth.create_challenge("charlie")
        bad_proof = b"invalid_proof_bytes_000000000000"
        res_fail = self.auth.verify_proof(nonce2, bad_proof)
        self.assertFalse(res_fail.success)


if __name__ == "__main__":
    unittest.main()
