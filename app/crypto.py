"""Secret storage: AES-GCM encryption of AccessKey secrets, password hashing, signed cookies."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PBKDF2_ITERATIONS = 200_000
SALT_BYTES = 16
NONCE_BYTES = 12


def derive_key(master: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", master, salt, PBKDF2_ITERATIONS, dklen=32)


def encrypt_secret(master: bytes, plaintext: str) -> tuple[str, str, str]:
    """Return (salt, nonce, ciphertext) as base64 strings."""
    salt = secrets.token_bytes(SALT_BYTES)
    nonce = secrets.token_bytes(NONCE_BYTES)
    key = derive_key(master, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return _b64(salt), _b64(nonce), _b64(ciphertext)


def decrypt_secret(master: bytes, salt: str, nonce: str, ciphertext: str) -> str:
    key = derive_key(master, _unb64(salt))
    return AESGCM(key).decrypt(_unb64(nonce), _unb64(ciphertext), None).decode("utf-8")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt_b64, digest_b64 = stored.split("$")
    except ValueError:
        return False
    if scheme != "scrypt":
        return False
    candidate = hashlib.scrypt(
        password.encode("utf-8"), salt=_unb64(salt_b64), n=2**14, r=8, p=1, dklen=32
    )
    return hmac.compare_digest(candidate, _unb64(digest_b64))


def sign(value: str, key: bytes) -> str:
    """Pack a payload with an expiry and HMAC so it can live in an HttpOnly cookie."""
    token = _b64(value.encode("utf-8"))
    expires = int(time.time()) + 30 * 86400
    body = f"{token}.{expires}"
    return f"{body}.{_b64(_mac(key, body).encode())}"


def unsign(signed: str, key: bytes) -> str | None:
    try:
        token, expires, mac_b64 = signed.split(".")
        body = f"{token}.{expires}"
        expected = _mac(key, body)
        if not hmac.compare_digest(expected, _unb64(mac_b64).decode()):
            return None
        if int(expires) < time.time():
            return None
        return _unb64(token).decode("utf-8")
    except (ValueError, TypeError, UnicodeDecodeError):
        return None


def csrf_token(password_hash: str) -> str:
    return hashlib.sha256(f"csrf|{password_hash}".encode("utf-8")).hexdigest()[:32]


def mask_access_key_id(access_key_id: str) -> str:
    if len(access_key_id) <= 4:
        return "*" * len(access_key_id)
    return f"{access_key_id[:4]}****{access_key_id[-4:]}"


def _mac(key: bytes, body: str) -> str:
    return hmac.new(key, body.encode("utf-8"), hashlib.sha256).hexdigest()


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


__all__ = [
    "InvalidTag",
    "csrf_token",
    "decrypt_secret",
    "derive_key",
    "encrypt_secret",
    "hash_password",
    "mask_access_key_id",
    "sign",
    "unsign",
    "verify_password",
]
