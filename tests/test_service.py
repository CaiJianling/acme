"""End-to-end issuance orchestration: DB status transitions, files, renewal window, alerts."""

from __future__ import annotations

import datetime

import pytest

from app import certstore, db, issuer, repo
from app.service import Service


class FakeDns:
    def __init__(self, access_key_id, access_key_secret):
        self.access_key_id = access_key_id
        self.calls = []

    def upsert_txt(self, domain, rr, value, ttl=600):
        self.calls.append((rr, value))
        return ["rec-1"]

    def delete_records(self, record_ids):
        return len(record_ids)

    def list_domains(self):
        return [{"domain": "example.com", "record_count": 3, "version_name": "个人版"}]


def fake_result(fake_fullchain, days: int = 90) -> issuer.IssueResult:
    now = datetime.datetime.now(datetime.timezone.utc)
    return issuer.IssueResult(
        fullchain_pem=fake_fullchain["fullchain"],
        privkey_pem=fake_fullchain["leaf_key"],
        not_before=now,
        not_after=now + datetime.timedelta(days=days),
        serial="3039",
        order_uri="https://ca/order/1",
        names=["example.com", "*.example.com"],
    )


@pytest.fixture
def wired(settings, monkeypatch, fake_fullchain):
    service = Service(settings)
    monkeypatch.setattr("app.alidns.AliDns", FakeDns)
    seen: dict[str, object] = {}

    def fake_issue(dns, account_key, config, domain, sans, key_type, emit):
        seen["domain"] = domain
        seen["sans"] = sans
        seen["key_type"] = key_type
        seen["eab"] = (config.eab_kid, config.eab_hmac_key)
        emit("info", "fake: 已添加 TXT")
        return fake_result(fake_fullchain)

    monkeypatch.setattr(issuer, "issue_certificate", fake_issue)
    yield service, seen
    service.executor.shutdown(wait=False)


def test_issue_writes_files_and_database(wired, settings):
    service, seen = wired
    names = ["*.example.com", "example.com", "www.example.com"]
    with db.session(settings.db_path) as conn:
        credential_id = repo.add_credential(conn, settings.master_key, "ali", "LTAI", "sec")
        domain_id = repo.add_domain(conn, credential_id, "example.com")
        for rr in ("@", "*", "www"):
            repo.add_subname(conn, domain_id, rr)
        cert_id = repo.create_certificate(
            conn, domain_id, names, "rsa2048",
            "https://acme-staging-v02.api.letsencrypt.org/directory",
        )

    service.issue(cert_id)

    assert seen["domain"] == "example.com"
    assert seen["sans"] == names
    assert seen["key_type"] == "rsa2048"
    assert seen["eab"] == ("", "")
    with db.session(settings.db_path) as conn:
        cert = repo.get_certificate(conn, cert_id)
        assert cert["status"] == "active"
        assert cert["serial"] == "3039"
        assert cert["not_after"] is not None
        messages = [row["message"] for row in repo.list_events(conn, cert_id)]
    assert any("已添加 TXT" in message for message in messages)
    directory = certstore.cert_path(settings.cert_dir, cert_id)
    assert (directory / "fullchain.pem").is_file()
    assert (directory / "privkey.pem").is_file()
    assert certstore.load_certificate((directory / "cert.pem").read_bytes()).serial_number == 12345


def test_issue_failure_is_recorded_and_visible(wired, settings, monkeypatch):
    service, _ = wired
    monkeypatch.setattr(
        issuer, "issue_certificate",
        lambda *args, **kwargs: (_ for _ in ()).throw(issuer.IssuerError("TXT 迟迟没有生效")),
    )
    with db.session(settings.db_path) as conn:
        credential_id = repo.add_credential(conn, settings.master_key, "ali", "LTAI", "sec")
        domain_id = repo.add_domain(conn, credential_id, "example.com")
        repo.add_subname(conn, domain_id, "@")
        cert_id = repo.create_certificate(conn, domain_id, ["@"], "rsa2048", "https://x/directory")

    service.issue(cert_id)

    with db.session(settings.db_path) as conn:
        cert = repo.get_certificate(conn, cert_id)
        assert cert["status"] == "error"
        assert "TXT" in cert["error"]
        assert any("TXT" in row["message"] for row in repo.list_events(conn, cert_id))


def test_unreadable_secret_does_not_stay_issuing(settings, monkeypatch, tmp_path):
    """A rotated master.key must surface as an error instead of hanging the certificate."""
    with db.session(settings.db_path) as conn:
        credential_id = repo.add_credential(conn, settings.master_key, "ali", "LTAI", "sec")
        domain_id = repo.add_domain(conn, credential_id, "example.com")
        cert_id = repo.create_certificate(conn, domain_id, ["example.com"], "rsa2048", "https://x/directory")

    import dataclasses

    broken = dataclasses.replace(settings, master_key=b"another-master-key-32-bytes-long!!")
    service = Service(broken)
    service.issue(cert_id)

    with db.session(settings.db_path) as conn:
        cert = repo.get_certificate(conn, cert_id)
        assert cert["status"] == "error"
        assert cert["error"]


def test_renewal_window_and_auto_renew_switch(wired, settings):
    service, _ = wired
    with db.session(settings.db_path) as conn:
        credential_id = repo.add_credential(conn, settings.master_key, "ali", "LTAI", "sec")
        domain_id = repo.add_domain(conn, credential_id, "example.com")
        soon = repo.create_certificate(conn, domain_id, ["@"], "rsa2048", "https://x/directory")
        later = repo.create_certificate(conn, domain_id, ["www"], "rsa2048", "https://x/directory")
        now = datetime.datetime.now(datetime.timezone.utc)
        for cert_id, days in ((soon, 12), (later, 120)):
            repo.record_certificate_issued(
                conn, cert_id, "S", now, now + datetime.timedelta(days=days)
            )
            repo.set_certificate_status(conn, cert_id, "active")

    assert [item["id"] for item in service.due_certificates()] == [soon]
    assert service.renew_due() == [soon]

    db.set_setting(conn := db.connect(settings.db_path), "auto_renew_enabled", "0")
    conn.commit()
    conn.close()
    assert service.renew_due() == []


def test_warn_expiring_notifies_once_per_day(wired, settings):
    service, _ = wired
    with db.session(settings.db_path) as conn:
        credential_id = repo.add_credential(conn, settings.master_key, "ali", "LTAI", "sec")
        domain_id = repo.add_domain(conn, credential_id, "example.com")
        cert_id = repo.create_certificate(conn, domain_id, ["@"], "rsa2048", "https://x/directory")
        now = datetime.datetime.now(datetime.timezone.utc)
        repo.record_certificate_issued(conn, cert_id, "S", now, now + datetime.timedelta(days=5))
        repo.set_certificate_status(conn, cert_id, "active")

    first = service.warn_expiring()
    assert [item["id"] for item in first] == [cert_id]
    assert service.warn_expiring() == []
    with db.session(settings.db_path) as conn:
        assert repo.get_certificate(conn, cert_id)["last_notified_date"]


def test_interrupted_jobs_are_recovered(wired, settings):
    service, _ = wired
    with db.session(settings.db_path) as conn:
        credential_id = repo.add_credential(conn, settings.master_key, "ali", "LTAI", "sec")
        domain_id = repo.add_domain(conn, credential_id, "example.com")
        cert_id = repo.create_certificate(conn, domain_id, ["@"], "rsa2048", "https://x/directory")
        repo.set_certificate_status(conn, cert_id, "issuing")

    assert service.recover_interrupted_jobs() == 1
    with db.session(settings.db_path) as conn:
        cert = repo.get_certificate(conn, cert_id)
        assert cert["status"] == "error"
        assert "打断" in cert["error"]


def test_ca_url_resolution_prefers_custom_directory(wired, settings):
    service, _ = wired
    with db.session(settings.db_path) as conn:
        db.set_setting(conn, "ca_name", "zerossl")
    assert service.ca_directory_url().endswith("/v2/DV90")
    with db.session(settings.db_path) as conn:
        db.set_setting(conn, "ca_directory", "https://acme.internal/directory")
    assert service.ca_directory_url() == "https://acme.internal/directory"


def test_double_issue_is_not_queued_twice(settings, monkeypatch, fake_fullchain):
    service = Service(settings)
    monkeypatch.setattr("app.alidns.AliDns", FakeDns)
    monkeypatch.setattr(
        issuer, "issue_certificate",
        lambda *args, **kwargs: fake_result(fake_fullchain),
    )
    with db.session(settings.db_path) as conn:
        credential_id = repo.add_credential(conn, settings.master_key, "ali", "LTAI", "sec")
        domain_id = repo.add_domain(conn, credential_id, "example.com")
        cert_id = repo.create_certificate(conn, domain_id, ["@"], "rsa2048", "https://x/directory")

    service._inflight.add(cert_id)
    assert service.start_issue(cert_id) is False
    service._inflight.discard(cert_id)
    assert service.start_issue(cert_id) is True
    service.executor.shutdown(wait=True)
    with db.session(settings.db_path) as conn:
        assert repo.get_certificate(conn, cert_id)["status"] == "active"
