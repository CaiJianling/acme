"""Orchestrates issuance/renewal: joins the database, Aliyun DNS and the ACME issuer."""

from __future__ import annotations

import datetime
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from . import alidns, certstore, config as config_module, db, issuer, notify, repo
from .crypto import InvalidTag, mask_access_key_id

logger = logging.getLogger(__name__)

ISSUING = "issuing"


def describe_error(exc: Exception, unexpected: bool = False) -> str:
    if isinstance(exc, InvalidTag):
        return (
            "无法解密已保存的 AccessKeySecret：主密钥（master.key 或 ACME_MASTER_KEY）可能已更换。"
            "请到「阿里云凭证」重新填写 AccessKeySecret 并保存。"
        )
    text = str(exc).strip() or "没有错误详情，请查看签发日志"
    return f"{type(exc).__name__}: {text}" if unexpected else text


@dataclass
class JobContext:
    certificate_id: int
    domain: str
    sans: list[str]
    key_type: str
    ca_directory: str
    access_key_id: str
    access_key_secret: str
    eab_kid: str
    eab_hmac_key: str


class Service:
    def __init__(self, settings: config_module.Settings):
        self.settings = settings
        self.executor = ThreadPoolExecutor(max_workers=settings.max_workers, thread_name_prefix="issue")
        self._lock = threading.Lock()
        self._inflight: set[int] = set()

    # ---------- settings helpers ----------

    def settings_map(self) -> dict[str, str]:
        with db.session(self.settings.db_path) as conn:
            return db.all_settings(conn)

    def int_setting(self, key: str, fallback: int) -> int:
        with db.session(self.settings.db_path) as conn:
            return db.setting_int(conn, key, fallback)

    def ca_directory_url(self, values: dict[str, str] | None = None) -> str:
        values = values or self.settings_map()
        custom = values.get("ca_directory", "").strip()
        if custom:
            return custom
        return config_module.CA_DIRECTORY_URLS.get(
            values.get("ca_name", "letsencrypt-staging"),
            config_module.CA_DIRECTORY_URLS["letsencrypt-staging"],
        )

    def recover_interrupted_jobs(self) -> int:
        """Any row still marked 'issuing' at startup belongs to a dead worker thread."""
        with db.session(self.settings.db_path) as conn:
            rows = conn.execute("SELECT id FROM certificates WHERE status=?", (ISSUING,)).fetchall()
            for row in rows:
                repo.set_certificate_status(conn, row["id"], "error", error="上次任务在签发过程中被打断，请重新发起")
                repo.log_event(conn, row["id"], "warn", "服务重启，上一次签发任务已被中止")
        return len(rows)

    # ---------- issuance ----------

    def _context(self, certificate_id: int) -> JobContext:
        with db.session(self.settings.db_path) as conn:
            cert = repo.get_certificate(conn, certificate_id)
            if cert is None:
                raise ValueError("证书记录不存在")
            access_key_id, access_key_secret = repo.open_access_key(
                conn, self.settings.master_key, cert["credential_id"]
            )
            credential = repo.get_credential(conn, cert["credential_id"])
            values = db.all_settings(conn)
            return JobContext(
                certificate_id=certificate_id,
                domain=cert["domain"],
                sans=db.load_json(cert["names"], []) or [],
                key_type=cert["key_type"] or values.get("cert_key_type", "rsa2048"),
                ca_directory=self.ca_directory_url(values),
                access_key_id=access_key_id,
                access_key_secret=access_key_secret,
                eab_kid=credential["eab_kid"],
                eab_hmac_key=credential["eab_hmac_key"],
            )

    def _emitter(self, certificate_id: int):
        def emit(level: str, message: str) -> None:
            try:
                with db.session(self.settings.db_path) as conn:
                    repo.log_event(conn, certificate_id, level, message)
            except Exception:  # a log write must never kill the issuance
                logger.exception("写入签发日志失败")

        return emit

    def start_issue(self, certificate_id: int) -> bool:
        """Queue issuance; returns False when a job for this certificate is already running."""
        with self._lock:
            if certificate_id in self._inflight:
                return False
            self._inflight.add(certificate_id)
        self.executor.submit(self._issue_guarded, certificate_id)
        return True

    def _issue_guarded(self, certificate_id: int) -> None:
        try:
            self.issue(certificate_id)
        finally:
            with self._lock:
                self._inflight.discard(certificate_id)

    def issue(self, certificate_id: int) -> None:
        """Blocking dns-01 issuance for one certificate row; never raises."""
        emit = self._emitter(certificate_id)
        with db.session(self.settings.db_path) as conn:
            repo.set_certificate_status(conn, certificate_id, ISSUING, error="")
        try:
            self._issue_inner(certificate_id, emit)
        except Exception as exc:
            # A rotated master key, a deleted credential or a broken row must not leave
            # the certificate stuck in "issuing" forever.
            logger.exception("签发任务 #%s 出现未预期的错误", certificate_id)
            detail = describe_error(exc, unexpected=True)
            emit("error", detail)
            with db.session(self.settings.db_path) as conn:
                repo.set_certificate_status(conn, certificate_id, "error", error=detail[:2000])

    def _issue_inner(self, certificate_id: int, emit: issuer.Emitter) -> None:
        ctx = self._context(certificate_id)
        emit("info", f"使用凭证 {mask_access_key_id(ctx.access_key_id)}，CA 目录 {ctx.ca_directory}")
        account_key = issuer.load_account_key(self.settings.account_key_path)
        cfg = issuer.IssuerConfig(
            directory_url=ctx.ca_directory,
            contact_email=self.settings_map().get("contact_email", ""),
            eab_kid=ctx.eab_kid,
            eab_hmac_key=ctx.eab_hmac_key,
            propagation_timeout=self.int_setting("dns_propagation_timeout", 180),
        )
        try:
            dns = alidns.AliDns(ctx.access_key_id, ctx.access_key_secret)
            result = issuer.issue_certificate(
                dns, account_key, cfg, ctx.domain, ctx.sans, ctx.key_type, emit
            )
        except (alidns.AliDnsError, issuer.IssuerError, ValueError) as exc:
            detail = describe_error(exc)
            emit("error", detail)
            with db.session(self.settings.db_path) as conn:
                repo.set_certificate_status(conn, certificate_id, "error", error=detail[:2000])
            self._notify_failure(ctx, detail)
            return

        directory = certstore.save(
            self.settings.cert_dir, certificate_id, result.privkey_pem, result.fullchain_pem
        )
        with db.session(self.settings.db_path) as conn:
            repo.record_certificate_issued(
                conn, certificate_id, result.serial, result.not_before, result.not_after
            )
            repo.prune_events(conn, certificate_id)
        emit("info", f"证书已保存到 {directory}")

    # ---------- renewal ----------

    def due_certificates(self, at: datetime.datetime | None = None) -> list[dict]:
        """Certificates that are active and inside the renewal window (or already expired)."""
        now = at or datetime.datetime.now(datetime.timezone.utc)
        with db.session(self.settings.db_path) as conn:
            window = db.setting_int(conn, "renew_before_days", 30)
            rows = conn.execute(
                "SELECT cert.*, d.domain FROM certificates cert JOIN domains d ON d.id = cert.domain_id "
                "WHERE cert.status IN ('active', 'error', 'expired') AND cert.not_after IS NOT NULL"
            ).fetchall()
        due = []
        for row in rows:
            not_after = certstore.parse_iso(row["not_after"])
            if not_after is None:
                continue
            remaining = certstore.days_left(not_after, now)
            if remaining <= window:
                due.append(
                    {
                        "id": row["id"],
                        "domain": row["domain"],
                        "names": db.load_json(row["names"], []),
                        "status": row["status"],
                        "remaining": remaining,
                        "not_after": not_after,
                    }
                )
        return due

    def renew_due(self) -> list[int]:
        started = []
        if not self._auto_renew_enabled():
            return started
        for item in self.due_certificates():
            if self.start_issue(item["id"]):
                started.append(item["id"])
        return started

    def _auto_renew_enabled(self) -> bool:
        return self.settings_map().get("auto_renew_enabled", "1") in ("1", "true", "yes")

    def warn_expiring(self, at: datetime.datetime | None = None) -> list[dict]:
        """Certificates close to expiry that have not been notified about today."""
        now = at or datetime.datetime.now(datetime.timezone.utc)
        today = now.astimezone().date().isoformat()
        warned = []
        with db.session(self.settings.db_path) as conn:
            threshold = db.setting_int(conn, "warn_before_days", 14)
            rows = repo.list_certificates(conn)
            for row in rows:
                not_after = certstore.parse_iso(row["not_after"])
                if not_after is None:
                    continue
                remaining = certstore.days_left(not_after, now)
                if remaining > threshold or row["last_notified_date"] == today:
                    continue
                warned.append(
                    {
                        "id": row["id"],
                        "domain": row["domain"],
                        "names": db.load_json(row["names"], []),
                        "remaining": remaining,
                        "not_after": not_after,
                    }
                )
                repo.mark_notified(conn, row["id"], today)
        return warned

    # ---------- notifications ----------

    def _notify_failure(self, ctx: JobContext, reason: str) -> None:
        values = self.settings_map()
        if values.get("notify_enabled") not in ("1", "true", "yes"):
            return
        body = (
            f"证书自动签发/续期失败。\n域名：{ctx.domain}\n包含：{', '.join(ctx.sans)}\n"
            f"CA：{ctx.ca_directory}\n原因：{reason}\n"
        )
        self._try_send(values, f"[证书告警] {ctx.domain} 签发失败", body)

    def notify_warnings(self) -> int:
        values = self.settings_map()
        items = self.warn_expiring()
        if not items or values.get("notify_enabled") not in ("1", "true", "yes"):
            return 0
        lines = [
            f"- {item['domain']} (#{item['id']}) 剩余 {item['remaining']} 天，到期 "
            f"{item['not_after'].astimezone().isoformat(timespec='minutes')}"
            for item in items
        ]
        self._try_send(
            values,
            f"[证书告警] {len(items)} 张证书即将到期",
            "以下证书即将到期，请检查自动续期是否被关闭或失败：\n" + "\n".join(lines),
        )
        return len(items)

    def _try_send(self, values: dict[str, str], subject: str, body: str) -> None:
        try:
            notify.send(notify.build_mail_config(values), subject, body)
        except Exception as exc:
            logger.warning("发送通知邮件失败：%s", exc)

    # ---------- other actions ----------

    def test_account(self) -> str:
        values = self.settings_map()
        account_key = issuer.load_account_key(self.settings.account_key_path)
        cfg = issuer.IssuerConfig(
            directory_url=self.ca_directory_url(values),
            contact_email=values.get("contact_email", ""),
            propagation_timeout=self.int_setting("dns_propagation_timeout", 180),
        )
        return issuer.test_account_connection(cfg, account_key)

    def test_dns(self, credential_id: int) -> list[dict]:
        with db.session(self.settings.db_path) as conn:
            access_key_id, access_key_secret = repo.open_access_key(
                conn, self.settings.master_key, credential_id
            )
        dns = alidns.AliDns(access_key_id, access_key_secret)
        return dns.list_domains()

    def revoke(self, certificate_id: int) -> None:
        values = self.settings_map()
        with db.session(self.settings.db_path) as conn:
            cert = repo.get_certificate(conn, certificate_id)
            if cert is None:
                raise ValueError("证书记录不存在")
            directory = certstore.cert_path(self.settings.cert_dir, certificate_id)
        pem = certstore.read(directory, "cert")
        account_key = issuer.load_account_key(self.settings.account_key_path)
        issuer.revoke_certificate(
            account_key,
            issuer.IssuerConfig(directory_url=self.ca_directory_url(values)),
            pem,
        )
        with db.session(self.settings.db_path) as conn:
            repo.set_certificate_status(conn, certificate_id, "revoked", error="已按用户要求吊销")
            repo.log_event(conn, certificate_id, "warn", "证书已吊销")
