"""Expiry / failure notifications over SMTP."""

from __future__ import annotations

import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage


@dataclass
class MailConfig:
    host: str
    port: int
    username: str
    password: str
    sender: str
    use_ssl: bool = True
    recipients: str = ""

    @property
    def enabled(self) -> bool:
        return bool(self.host and self.sender)

    @property
    def to_list(self) -> list[str]:
        raw = self.recipients or self.sender
        return [address.strip() for address in raw.replace(";", ",").split(",") if address.strip()]


def send(config: MailConfig, subject: str, body: str) -> None:
    if not config.enabled:
        raise ValueError("SMTP 未配置完整（缺少服务器或发件人）")
    if not config.to_list:
        raise ValueError("没有填写收件人邮箱")

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = config.sender
    message["To"] = ", ".join(config.to_list)
    message.set_content(body)

    if config.use_ssl:
        server: smtplib.SMTP = smtplib.SMTP_SSL(
            config.host, config.port, timeout=20, context=ssl.create_default_context()
        )
    else:
        server = smtplib.SMTP(config.host, config.port, timeout=20)

    with server:
        if not config.use_ssl:
            try:
                server.ehlo()
                if server.has_extn("starttls"):
                    server.starttls(context=ssl.create_default_context())
                    server.ehlo()
            except smtplib.SMTPException as exc:
                raise RuntimeError(f"STARTTLS 协商失败：{exc}") from exc
        if config.username:
            server.login(config.username, config.password)
        server.send_message(message)


def build_mail_config(settings: dict[str, str]) -> MailConfig:
    return MailConfig(
        host=settings.get("smtp_host", "").strip(),
        port=int(settings.get("smtp_port", "465") or 465),
        username=settings.get("smtp_username", "").strip(),
        password=settings.get("smtp_password", "").strip(),
        sender=settings.get("smtp_from", "").strip(),
        use_ssl=settings.get("smtp_use_ssl", "1") in ("1", "true", "yes"),
        recipients=settings.get("notify_to", "").strip(),
    )
