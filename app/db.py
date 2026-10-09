"""SQLite storage: schema, per-operation connections, and the settings key/value store."""

from __future__ import annotations

import contextlib
import datetime
import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    provider TEXT NOT NULL DEFAULT 'aliyun',
    access_key_id TEXT NOT NULL,
    secret_salt TEXT NOT NULL,
    secret_nonce TEXT NOT NULL,
    secret_cipher TEXT NOT NULL,
    eab_kid TEXT NOT NULL DEFAULT '',
    eab_hmac_key TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    credential_id INTEGER NOT NULL REFERENCES credentials(id) ON DELETE RESTRICT,
    domain TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS subnames (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    rr TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    UNIQUE(domain_id, rr)
);

CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    names TEXT NOT NULL,
    key_type TEXT NOT NULL DEFAULT 'rsa2048',
    status TEXT NOT NULL DEFAULT 'pending',
    ca_directory TEXT NOT NULL DEFAULT '',
    serial TEXT NOT NULL DEFAULT '',
    not_before TEXT,
    not_after TEXT,
    error TEXT NOT NULL DEFAULT '',
    last_notified_date TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    certificate_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
    level TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_cert ON events(certificate_id, id);
CREATE INDEX IF NOT EXISTS idx_certs_status ON certificates(status, not_after);
"""

DEFAULT_SETTINGS: dict[str, str] = {
    "ca_name": "letsencrypt-staging",
    "ca_directory": "",
    "contact_email": "",
    "renew_before_days": "30",
    "warn_before_days": "14",
    "dns_propagation_timeout": "180",
    "cert_key_type": "rsa2048",
    "pfx_password": "",
    "smtp_host": "",
    "smtp_port": "465",
    "smtp_username": "",
    "smtp_password": "",
    "smtp_from": "",
    "smtp_use_ssl": "1",
    "notify_enabled": "0",
    "notify_to": "",
    "renewal_hour": "3",
    "auth_version": "0",
    "auto_renew_enabled": "1",
}


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


@contextlib.contextmanager
def session(path: Path) -> Iterator[sqlite3.Connection]:
    conn = connect(path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init(path: Path) -> None:
    with session(path) as conn:
        conn.executescript(SCHEMA)
        for key, value in DEFAULT_SETTINGS.items():
            conn.execute("INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)", (key, value))


def get_setting(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    if row is None:
        return DEFAULT_SETTINGS.get(key, default)
    return row["value"]


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO settings(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def all_settings(conn: sqlite3.Connection) -> dict[str, str]:
    rows = conn.execute("SELECT key, value FROM settings").fetchall()
    merged = dict(DEFAULT_SETTINGS)
    merged.update({row["key"]: row["value"] for row in rows})
    return merged


def setting_int(conn: sqlite3.Connection, key: str, fallback: int) -> int:
    raw = get_setting(conn, key, str(fallback))
    try:
        return int(raw)
    except (TypeError, ValueError):
        return fallback


def dump_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False)


def load_json(raw: str, default: object = None):
    if not raw:
        return default
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return default
