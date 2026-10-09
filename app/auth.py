"""Cookie authentication and CSRF protection for the single-admin web UI."""

from __future__ import annotations

import hashlib
import hmac
import time

from fastapi import Request
from fastapi.responses import RedirectResponse

from . import config as config_module
from . import crypto, db

AUTH_COOKIE = "acme_auth"
CSRF_FIELD = "csrf_token"
MAX_FAILED_LOGINS = 8
LOCKOUT_SECONDS = 600
COOKIE_MAX_AGE = 30 * 86400


class Auth:
    def __init__(self, settings: config_module.Settings):
        self.settings = settings
        self._failures: dict[str, tuple[int, float]] = {}

    @property
    def db_path(self):
        return self.settings.db_path

    def is_configured(self) -> bool:
        with db.session(self.db_path) as conn:
            return bool(db.get_setting(conn, "admin_password_hash", ""))

    def set_password(self, password: str) -> None:
        if len(password) < 10:
            raise ValueError("登录密码至少 10 位，建议包含字母、数字和符号")
        with db.session(self.db_path) as conn:
            db.set_setting(conn, "admin_password_hash", crypto.hash_password(password))
            db.set_setting(conn, "auth_version", str(db.setting_int(conn, "auth_version", 0) + 1))

    def locked_out(self, ip: str) -> int:
        count, until = self._failures.get(ip, (0, 0.0))
        if count >= MAX_FAILED_LOGINS:
            remaining = int(until - time.time())
            if remaining > 0:
                return remaining
            self._failures.pop(ip, None)
        return 0

    def _record_failure(self, ip: str) -> None:
        count, _ = self._failures.get(ip, (0, 0.0))
        count += 1
        self._failures[ip] = (count, time.time() + LOCKOUT_SECONDS)

    def check_password(self, password: str) -> bool:
        """Verify a password without touching the login rate limiter (used for re-auth)."""
        with db.session(self.db_path) as conn:
            stored = db.get_setting(conn, "admin_password_hash", "")
        return bool(stored) and crypto.verify_password(password, stored)

    def login(self, password: str, ip: str) -> str | None:
        """Return the auth cookie value, or None when the password is wrong."""
        if self.locked_out(ip):
            return None
        with db.session(self.db_path) as conn:
            stored = db.get_setting(conn, "admin_password_hash", "")
            version = db.get_setting(conn, "auth_version", "0")
            if not stored or not crypto.verify_password(password, stored):
                self._record_failure(ip)
                return None
        self._failures.pop(ip, None)
        return crypto.sign(version, self._cookie_key(stored))

    def authenticated(self, request: Request) -> bool:
        raw = request.cookies.get(AUTH_COOKIE, "")
        if not raw:
            return False
        with db.session(self.db_path) as conn:
            stored = db.get_setting(conn, "admin_password_hash", "")
            version = db.get_setting(conn, "auth_version", "0")
        if not stored:
            return False
        return crypto.unsign(raw, self._cookie_key(stored)) == version

    def csrf_token(self) -> str:
        with db.session(self.db_path) as conn:
            stored = db.get_setting(conn, "admin_password_hash", "")
        if not stored:
            return ""
        return crypto.csrf_token(self._cookie_key(stored).hex())

    def csrf_valid(self, token: str) -> bool:
        expected = self.csrf_token()
        return bool(expected) and hmac.compare_digest(expected, token or "")

    def apply_cookie(self, response, value: str):
        response.set_cookie(
            AUTH_COOKIE,
            value,
            max_age=COOKIE_MAX_AGE,
            httponly=True,
            samesite="lax",
            secure=self.settings.cookie_secure,
            path="/",
        )
        return response

    def logout_response(self) -> RedirectResponse:
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(AUTH_COOKIE, path="/")
        return response

    def _cookie_key(self, password_hash: str) -> bytes:
        return hashlib.sha256(
            self.settings.master_key + b"|cookie|" + password_hash.encode("utf-8")
        ).digest()
