"""Data access for credentials, domains, host records, certificates and events."""

from __future__ import annotations

import sqlite3
from datetime import datetime

from . import crypto, db, names


def add_credential(
    conn: sqlite3.Connection,
    master: bytes,
    name: str,
    access_key_id: str,
    access_key_secret: str,
    eab_kid: str = "",
    eab_hmac_key: str = "",
) -> int:
    salt, nonce, cipher = crypto.encrypt_secret(master, access_key_secret.strip())
    cur = conn.execute(
        "INSERT INTO credentials(name, provider, access_key_id, secret_salt, secret_nonce, "
        "secret_cipher, eab_kid, eab_hmac_key, created_at) VALUES(?,?,?,?,?,?,?,?,?)",
        (
            name.strip(),
            "aliyun",
            access_key_id.strip(),
            salt,
            nonce,
            cipher,
            eab_kid.strip(),
            eab_hmac_key.strip(),
            db.now(),
        ),
    )
    return int(cur.lastrowid)


def update_credential(
    conn: sqlite3.Connection,
    master: bytes,
    credential_id: int,
    name: str,
    access_key_id: str,
    access_key_secret: str | None,
    eab_kid: str = "",
    eab_hmac_key: str = "",
) -> None:
    row = get_credential(conn, credential_id)
    if row is None:
        raise ValueError("凭证不存在")
    if access_key_secret:
        salt, nonce, cipher = crypto.encrypt_secret(master, access_key_secret.strip())
    else:
        salt, nonce, cipher = row["secret_salt"], row["secret_nonce"], row["secret_cipher"]
    # Blank means "keep what is stored"; clearing EAB is done by deleting the credential.
    kid = eab_kid.strip() or row["eab_kid"]
    hmac_key = eab_hmac_key.strip() or row["eab_hmac_key"]
    conn.execute(
        "UPDATE credentials SET name=?, access_key_id=?, secret_salt=?, secret_nonce=?, "
        "secret_cipher=?, eab_kid=?, eab_hmac_key=? WHERE id=?",
        (
            name.strip(),
            access_key_id.strip(),
            salt,
            nonce,
            cipher,
            kid,
            hmac_key,
            credential_id,
        ),
    )


def list_credentials(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM credentials ORDER BY name").fetchall()


def get_credential(conn: sqlite3.Connection, credential_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()


def delete_credential(conn: sqlite3.Connection, credential_id: int) -> None:
    conn.execute("DELETE FROM credentials WHERE id=?", (credential_id,))


def open_access_key(conn: sqlite3.Connection, master: bytes, credential_id: int) -> tuple[str, str]:
    """Return (access_key_id, access_key_secret), decrypting on demand only."""
    row = get_credential(conn, credential_id)
    if row is None:
        raise ValueError("阿里云凭证不存在")
    return row["access_key_id"], crypto.decrypt_secret(
        master, row["secret_salt"], row["secret_nonce"], row["secret_cipher"]
    )


def add_domain(conn: sqlite3.Connection, credential_id: int, domain: str) -> int:
    cur = conn.execute(
        "INSERT INTO domains(credential_id, domain, created_at) VALUES(?,?,?)",
        (credential_id, names.normalize_domain(domain), db.now()),
    )
    return int(cur.lastrowid)


def list_domains(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT d.*, c.name AS credential_name, "
        "(SELECT COUNT(*) FROM subnames s WHERE s.domain_id = d.id AND s.enabled = 1) AS enabled_count "
        "FROM domains d JOIN credentials c ON c.id = d.credential_id ORDER BY d.domain"
    ).fetchall()


def get_domain(conn: sqlite3.Connection, domain_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT d.*, c.name AS credential_name FROM domains d "
        "JOIN credentials c ON c.id = d.credential_id WHERE d.id=?",
        (domain_id,),
    ).fetchone()


def delete_domain(conn: sqlite3.Connection, domain_id: int) -> None:
    conn.execute("DELETE FROM domains WHERE id=?", (domain_id,))


def list_subnames(conn: sqlite3.Connection, domain_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM subnames WHERE domain_id=? ORDER BY rr", (domain_id,)
    ).fetchall()


def add_subname(conn: sqlite3.Connection, domain_id: int, rr: str, enabled: bool = True) -> int:
    domain = _domain_name(conn, domain_id)
    rr = names.normalize_rr(rr, domain)
    names.rr_to_fqdn(domain, rr)
    cur = conn.execute(
        "INSERT INTO subnames(domain_id, rr, enabled, created_at) VALUES(?,?,?,?) "
        "ON CONFLICT(domain_id, rr) DO UPDATE SET enabled = excluded.enabled",
        (domain_id, rr, 1 if enabled else 0, db.now()),
    )
    return int(cur.lastrowid)


def set_subname_enabled(conn: sqlite3.Connection, subname_id: int, enabled: bool) -> None:
    conn.execute("UPDATE subnames SET enabled=? WHERE id=?", (1 if enabled else 0, subname_id))


def delete_subname(conn: sqlite3.Connection, subname_id: int) -> None:
    conn.execute("DELETE FROM subnames WHERE id=?", (subname_id,))


def enabled_rrs(conn: sqlite3.Connection, domain_id: int) -> list[str]:
    rows = conn.execute(
        "SELECT rr FROM subnames WHERE domain_id=? AND enabled=1 ORDER BY rr", (domain_id,)
    ).fetchall()
    return [row["rr"] for row in rows]


def _domain_name(conn: sqlite3.Connection, domain_id: int) -> str:
    row = conn.execute("SELECT domain FROM domains WHERE id=?", (domain_id,)).fetchone()
    if row is None:
        raise ValueError("域名不存在")
    return row["domain"]


def create_certificate(
    conn: sqlite3.Connection,
    domain_id: int,
    names_: list[str],
    key_type: str,
    ca_directory: str,
) -> int:
    cur = conn.execute(
        "INSERT INTO certificates(domain_id, names, key_type, status, ca_directory, created_at, updated_at) "
        "VALUES(?,?,?,?,?,?,?)",
        (domain_id, db.dump_json(names_), key_type, "pending", ca_directory, db.now(), db.now()),
    )
    return int(cur.lastrowid)


def list_certificates(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT cert.*, d.domain FROM certificates cert JOIN domains d ON d.id = cert.domain_id "
        "ORDER BY cert.id DESC"
    ).fetchall()


def get_certificate(conn: sqlite3.Connection, certificate_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT cert.*, d.domain, d.credential_id FROM certificates cert "
        "JOIN domains d ON d.id = cert.domain_id WHERE cert.id=?",
        (certificate_id,),
    ).fetchone()


def set_certificate_status(
    conn: sqlite3.Connection,
    certificate_id: int,
    status: str,
    error: str = "",
) -> None:
    conn.execute(
        "UPDATE certificates SET status=?, error=?, updated_at=? WHERE id=?",
        (status, error, db.now(), certificate_id),
    )


def record_certificate_issued(
    conn: sqlite3.Connection,
    certificate_id: int,
    serial: str,
    not_before: datetime,
    not_after: datetime,
) -> None:
    conn.execute(
        "UPDATE certificates SET status='active', error='', serial=?, not_before=?, not_after=?, "
        "updated_at=? WHERE id=?",
        (serial, not_before.isoformat(), not_after.isoformat(), db.now(), certificate_id),
    )


def delete_certificate(conn: sqlite3.Connection, certificate_id: int) -> None:
    conn.execute("DELETE FROM certificates WHERE id=?", (certificate_id,))


def mark_notified(conn: sqlite3.Connection, certificate_id: int, day: str) -> None:
    conn.execute(
        "UPDATE certificates SET last_notified_date=? WHERE id=?", (day, certificate_id)
    )


def log_event(
    conn: sqlite3.Connection, certificate_id: int | None, level: str, message: str
) -> None:
    if certificate_id is None:
        return
    conn.execute(
        "INSERT INTO events(certificate_id, level, message, created_at) VALUES(?,?,?,?)",
        (certificate_id, level, message.strip()[:4000], db.now()),
    )


def list_events(
    conn: sqlite3.Connection, certificate_id: int, after_id: int = 0, limit: int = 200
) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM events WHERE certificate_id=? AND id>? ORDER BY id LIMIT ?",
        (certificate_id, after_id, limit),
    ).fetchall()


def prune_events(conn: sqlite3.Connection, certificate_id: int, keep: int = 300) -> None:
    conn.execute(
        "DELETE FROM events WHERE certificate_id=? AND id NOT IN "
        "(SELECT id FROM events WHERE certificate_id=? ORDER BY id DESC LIMIT ?)",
        (certificate_id, certificate_id, keep),
    )
