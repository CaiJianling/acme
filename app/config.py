"""Runtime configuration read from environment variables and an optional .env file."""

from __future__ import annotations

import os
import pathlib
import secrets
from dataclasses import dataclass, field

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
ENV_FILE = BASE_DIR / ".env"

CA_DIRECTORY_URLS = {
    "letsencrypt": "https://acme-v02.api.letsencrypt.org/directory",
    "letsencrypt-staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "zerossl": "https://acme.zerossl.com/v2/DV90",
}


def _read_env_file(path: pathlib.Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


@dataclass
class Settings:
    data_dir: pathlib.Path
    cert_dir: pathlib.Path
    master_key: bytes
    host: str
    port: int
    cookie_secure: bool
    max_workers: int
    env_file: dict[str, str] = field(default_factory=dict)

    @property
    def db_path(self) -> pathlib.Path:
        return self.data_dir / "acme.db"

    @property
    def account_key_path(self) -> pathlib.Path:
        return self.data_dir / "acme_account.key"


def _load_master_key(data_dir: pathlib.Path, env_file: dict[str, str]) -> bytes:
    from_env = os.environ.get("ACME_MASTER_KEY") or env_file.get("ACME_MASTER_KEY", "")
    if from_env:
        raw = from_env.encode("utf-8")
        if len(raw) < 32:
            raise RuntimeError("ACME_MASTER_KEY 太短，至少需要 32 个字符")
        return raw
    key_file = data_dir / "master.key"
    if not key_file.exists():
        key_file.write_text(secrets.token_hex(32), encoding="utf-8")
        key_file.chmod(0o600)
    return bytes.fromhex(key_file.read_text(encoding="utf-8").strip())


def load(settings_env: str | None = None) -> Settings:
    env_file = _read_env_file(ENV_FILE)

    def get(name: str, default: str = "") -> str:
        return os.environ.get(name) or env_file.get(name, default)

    data_dir = pathlib.Path(settings_env or get("ACME_DATA_DIR", str(BASE_DIR / "data"))).resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    cert_dir = data_dir / "certs"
    cert_dir.mkdir(parents=True, exist_ok=True)

    return Settings(
        data_dir=data_dir,
        cert_dir=cert_dir,
        master_key=_load_master_key(data_dir, env_file),
        host=get("ACME_HOST", "127.0.0.1"),
        port=int(get("ACME_PORT", "8000")),
        cookie_secure=get("ACME_COOKIE_SECURE", "0") in ("1", "true", "yes"),
        max_workers=int(get("ACME_ISSUE_WORKERS", "2")),
        env_file=env_file,
    )
