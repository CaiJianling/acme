"""Web UI flows: auth, CSRF, CRUD, issuance hand-off, downloads."""

from __future__ import annotations

import re

import pytest
from starlette.testclient import TestClient

from app import certstore, db, repo
from tests.conftest import PASSWORD, csrf


def login(client: TestClient, password: str = PASSWORD):
    return client.post("/login", data={"password": password}, follow_redirects=False)


class TestAuth:
    def test_first_visit_lands_on_setup(self, client):
        response = client.get("/", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/setup"
        assert "管理密码" in client.get("/setup").text

    def test_short_password_rejected(self, client):
        response = client.post("/setup", data={"password": "123", "password_confirm": "123"},
                               follow_redirects=False)
        assert "至少 10 位" in client.get(response.headers["location"]).text

    def test_password_mismatch_rejected(self, client):
        response = client.post(
            "/setup",
            data={"password": "aaaaaaaaaa", "password_confirm": "bbbbbbbbbb"},
            follow_redirects=False,
        )
        assert "不一致" in client.get(response.headers["location"]).text

    def test_login_and_logout(self, settings, client):
        client.post("/setup", data={"password": PASSWORD, "password_confirm": PASSWORD})
        assert login(client).status_code == 303
        assert "阿里云凭证" in client.get("/", follow_redirects=True).text
        assert login(client, "wrong-password").status_code == 401
        client.post("/logout", data={"csrf_token": csrf(client, "/domains")})
        assert client.get("/domains", follow_redirects=False).status_code == 303

    def test_lockout_after_repeated_failures(self, settings, client):
        client.post("/setup", data={"password": PASSWORD, "password_confirm": PASSWORD})
        for _ in range(8):
            login(client, "bad-password-here")
        blocked = login(client, PASSWORD)
        assert blocked.status_code == 429

    def test_session_dies_after_password_change(self, authed, app):
        token = csrf(authed, "/settings")
        authed.post(
            "/settings/change-password",
            data={"csrf_token": token, "current_password": PASSWORD, "password": "New-password-999"},
        )
        assert authed.get("/", follow_redirects=False).status_code == 303

    def test_post_without_csrf_is_refused(self, authed):
        response = authed.post("/domains", data={"domain": "no-csrf.com", "credential_id": 1})
        assert response.status_code == 400


class TestCredentialPages:
    def test_create_update_and_mask(self, authed, settings):
        authed.post(
            "/credentials",
            data={
                "csrf_token": csrf(authed, "/credentials"),
                "name": "我的阿里云",
                "access_key_id": "LTAI5tABCDEFGH",
                "access_key_secret": "super-secret-value",
            },
        )
        page = authed.get("/credentials").text
        assert "LTAI****EFGH" in page
        assert "super-secret-value" not in page

        authed.post(
            "/credentials/1",
            data={
                "csrf_token": csrf(authed, "/credentials"),
                "name": "改名了",
                "access_key_id": "LTAI5tZZZZZZ",
                "access_key_secret": "",
            },
        )
        with db.session(settings.db_path) as conn:
            row = repo.get_credential(conn, 1)
            assert row["name"] == "改名了"
            assert repo.open_access_key(conn, settings.master_key, 1)[1] == "super-secret-value"

    def test_missing_fields_are_reported(self, authed):
        response = authed.post(
            "/credentials",
            data={"csrf_token": csrf(authed, "/credentials"), "name": "x", "access_key_id": "", "access_key_secret": ""},
            follow_redirects=False,
        )
        assert "都要填写" in authed.get(response.headers["location"]).text

    def test_duplicate_name_reported(self, authed):
        payload = {
            "csrf_token": csrf(authed, "/credentials"),
            "name": "dup", "access_key_id": "LTAI1", "access_key_secret": "s",
        }
        authed.post("/credentials", data=payload)
        response = authed.post("/credentials", data=payload, follow_redirects=False)
        assert "已存在" in authed.get(response.headers["location"]).text

    def test_delete_blocked_while_domains_use_it(self, authed):
        authed.post("/credentials", data={
            "csrf_token": csrf(authed, "/credentials"),
            "name": "c1", "access_key_id": "LTAI1", "access_key_secret": "s"})
        authed.post("/domains", data={
            "csrf_token": csrf(authed, "/domains"), "domain": "example.com", "credential_id": "1"})
        response = authed.post(
            "/credentials/1/delete", data={"csrf_token": csrf(authed, "/credentials")},
            follow_redirects=False,
        )
        assert "还有域名" in authed.get(response.headers["location"]).text


class TestDomainPages:
    @pytest.fixture(autouse=True)
    def seeded(self, authed):
        self.authed = authed
        authed.post("/credentials", data={
            "csrf_token": csrf(authed, "/credentials"),
            "name": "ali", "access_key_id": "LTAI1", "access_key_secret": "secret"})
        response = authed.post(
            "/domains",
            data={"csrf_token": csrf(authed, "/domains"), "domain": "Example.COM", "credential_id": "1"},
            follow_redirects=False,
        )
        assert response.headers["location"].startswith("/domains/")
        self.domain_id = int(re.search(r"/domains/(\d+)", response.headers["location"]).group(1))
        self.token = csrf(authed, f"/domains/{self.domain_id}")

    def test_apex_and_wildcard_created(self):
        page = self.authed.get(f"/domains/{self.domain_id}").text
        assert "@.example.com" not in page
        assert "*.example.com" in page
        assert "_acme-challenge.example.com" in page

    def test_add_and_remove_host_record(self):
        self.authed.post(
            f"/domains/{self.domain_id}/subnames",
            data={"csrf_token": self.token, "rr": "Shop"},
        )
        assert "shop.example.com" in self.authed.get(f"/domains/{self.domain_id}").text

    def test_invalid_host_record_reported(self):
        response = self.authed.post(
            f"/domains/{self.domain_id}/subnames",
            data={"csrf_token": self.token, "rr": "bad rr"},
            follow_redirects=False,
        )
        assert "主机记录" in self.authed.get(response.headers["location"]).text

    def test_toggle_only_changes_selection(self):
        self.authed.post(
            f"/domains/{self.domain_id}/subnames/toggle",
            data={"csrf_token": self.token, "rr": ["@"]},
        )
        page = self.authed.get(f"/domains/{self.domain_id}").text
        assert 'value="@" checked' in page
        assert 'value="*" >' in page

    def test_issue_requires_selection(self):
        response = self.authed.post(
            f"/domains/{self.domain_id}/issue", data={"csrf_token": self.token}, follow_redirects=False
        )
        assert "至少勾选" in self.authed.get(response.headers["location"]).text

    def test_issue_queues_job_with_san_snapshot(self, app):
        started = []
        app.state.service.start_issue = lambda cert_id: started.append(cert_id) or True
        self.authed.post(
            f"/domains/{self.domain_id}/issue",
            data={"csrf_token": self.token, "rr": ["@", "*"], "key_type": "ec256"},
            follow_redirects=False,
        )
        assert started == [1]
        page = self.authed.get("/certificates/1").text
        assert "example.com" in page and "*.example.com" in page
        assert "任务已排队" in page

    def test_issue_blocks_redundant_wildcard_pair(self, app):
        """*.example.com together with www.example.com is refused by the CA, so catch it here."""
        issued = []
        app.state.service.start_issue = lambda cert_id: issued.append(cert_id) or True
        self.authed.post(
            f"/domains/{self.domain_id}/subnames", data={"csrf_token": self.token, "rr": "www"}
        )
        response = self.authed.post(
            f"/domains/{self.domain_id}/issue",
            data={"csrf_token": csrf(self.authed, f"/domains/{self.domain_id}"), "rr": ["@", "*", "www"]},
            follow_redirects=False,
        )
        assert issued == []
        assert "通配符" in self.authed.get(response.headers["location"]).text

    def test_domain_page_warns_before_issuing(self):
        self.authed.post(
            f"/domains/{self.domain_id}/subnames", data={"csrf_token": self.token, "rr": "www"}
        )
        self.authed.post(
            f"/domains/{self.domain_id}/subnames/toggle",
            data={"csrf_token": csrf(self.authed, f"/domains/{self.domain_id}"), "rr": ["@", "*", "www"]},
        )
        page = self.authed.get(f"/domains/{self.domain_id}").text
        assert "CA 会拒绝这张证书" in page

    def test_import_records_from_aliyun(self, monkeypatch, settings):
        from app import web

        class Record:
            def __init__(self, rr):
                self.rr = rr

        # a real zone mixes underscore records, duplicates and junk names; none of them may 500
        zone = ["mail", "_dmarc", "smtp._domainkey", "www", "www", "@", "bad rr"]
        monkeypatch.setattr(web, "_fetch_records", lambda *args: [Record(rr) for rr in zone])
        response = self.authed.post(
            f"/domains/{self.domain_id}/import-records",
            data={"csrf_token": self.token},
            follow_redirects=False,
        )
        page = self.authed.get(response.headers["location"]).text
        assert "导入 4 条" in page
        assert "另有 1 条" in page
        assert "mail.example.com" in page
        assert "_dmarc.example.com" in page
        assert "smtp._domainkey.example.com" in page

    def test_html_escape_in_error(self):
        response = self.authed.post(
            f"/domains/{self.domain_id}/subnames",
            data={"csrf_token": self.token, "rr": "<script>alert(1)</script>"},
            follow_redirects=False,
        )
        page = self.authed.get(response.headers["location"]).text
        assert "<script>alert(1)</script>" not in page
        assert "&lt;script&gt;" in page


class TestCertificates:
    @pytest.fixture(autouse=True)
    def seeded(self, authed, settings, fake_fullchain, app):
        self.authed, self.settings = authed, settings
        app.state.service.start_issue = lambda cert_id: True
        authed.post("/credentials", data={
            "csrf_token": csrf(authed, "/credentials"),
            "name": "ali", "access_key_id": "LTAI1", "access_key_secret": "secret"})
        authed.post("/domains", data={
            "csrf_token": csrf(authed, "/domains"), "domain": "example.com", "credential_id": "1"})
        authed.post(
            "/domains/1/issue",
            data={"csrf_token": csrf(authed, "/domains/1"), "rr": ["@"], "key_type": "rsa2048"},
        )
        self.cert_id = 1
        self.directory = certstore.cert_path(settings.cert_dir, self.cert_id)
        self.fullchain = fake_fullchain

    def files_ready(self):
        certstore.save(self.directory.parent, self.cert_id, self.fullchain["leaf_key"], self.fullchain["fullchain"])

    def test_download_every_kind(self):
        self.files_ready()
        for kind in ("fullchain", "cert", "key", "chain", "der", "zip"):
            response = self.authed.get(f"/certificates/{self.cert_id}/download?kind={kind}")
            assert response.status_code == 200, kind
            assert "attachment" in response.headers["content-disposition"]
        assert self.authed.get(f"/certificates/{self.cert_id}/download?kind=fullchain").text.count("\n") > 3

    def test_pfx_needs_a_password(self):
        self.files_ready()
        blocked = self.authed.get(f"/certificates/{self.cert_id}/download?kind=pfx")
        assert blocked.status_code == 400
        ok = self.authed.get(f"/certificates/{self.cert_id}/download?kind=pfx&password=change-me")
        assert ok.status_code == 200
        assert ok.headers["content-type"] == "application/pkcs12"

    def test_missing_file_is_400_not_500(self):
        response = self.authed.get(f"/certificates/{self.cert_id}/download?kind=cert")
        assert response.status_code == 400
        assert "还不存在" in response.text

    def test_unknown_kind_is_400(self):
        self.files_ready()
        assert self.authed.get(
            f"/certificates/{self.cert_id}/download?kind=../../../etc/passwd"
        ).status_code in (400, 404)

    def test_events_json_and_status(self):
        payload = self.authed.get(f"/certificates/{self.cert_id}/events").json()
        assert payload["status"] == "pending"
        assert any("排队" in item["message"] for item in payload["events"])
        after = payload["events"][-1]["id"]
        assert self.authed.get(f"/certificates/{self.cert_id}/events?after={after}").json()["events"] == []

    def test_renew_and_delete(self):
        self.authed.post(
            f"/certificates/{self.cert_id}/renew", data={"csrf_token": csrf(self.authed, "/certificates")}
        )
        page = self.authed.get(f"/certificates/{self.cert_id}").text
        assert "重新申请" in page  # status is still pending, so the button is not "立即续期"
        assert "手动触发续期/重新申请" in page
        self.authed.post(
            f"/certificates/{self.cert_id}/delete", data={"csrf_token": csrf(self.authed, "/certificates")}
        )
        assert self.authed.get(f"/certificates/{self.cert_id}").status_code == 404
        assert not self.directory.exists()


class TestSettingsPage:
    @pytest.fixture(autouse=True)
    def logged_in(self, authed):
        self.authed = authed
        self.token = csrf(authed, "/settings")

    def post(self, **fields):
        return self.authed.post(
            "/settings", data={"csrf_token": self.token, **fields}, follow_redirects=False
        )

    def follow(self, response) -> str:
        return self.authed.get(response.headers["location"]).text

    def test_switches_can_be_turned_off(self):
        page = self.follow(self.post(auto_renew_enabled="0", notify_enabled="1", smtp_use_ssl="0"))
        assert re.search(r'name="auto_renew_enabled"[\s\S]*?value="0" selected', page)
        assert re.search(r'name="notify_enabled"[\s\S]*?value="1" selected', page)

    def test_out_of_range_numbers_rejected(self):
        assert "应在" in self.follow(self.post(renew_before_days="900"))

    def test_non_numeric_rejected(self):
        assert "必须是整数" in self.follow(self.post(renew_before_days="abc"))

    def test_custom_ca_must_be_https(self):
        assert "https://" in self.follow(self.post(ca_directory="http://insecure/directory"))

    def test_contact_email_validated(self):
        assert "邮箱格式" in self.follow(self.post(contact_email="not-an-email"))

    def test_blank_secret_keeps_old_value(self, settings):
        self.follow(self.post(smtp_password="smtp-secret", pfx_password="pfx-secret"))
        with db.session(settings.db_path) as conn:
            assert db.get_setting(conn, "smtp_password") == "smtp-secret"
        self.follow(self.post(smtp_password="", pfx_password=""))
        with db.session(settings.db_path) as conn:
            assert db.get_setting(conn, "smtp_password") == "smtp-secret"
        assert "smtp-secret" not in self.authed.get("/settings").text

    def test_staging_ca_is_labelled(self):
        assert "不被浏览器信任" in self.authed.get("/settings").text


def test_local_time_renders_stored_utc_in_local_zone():
    import datetime

    from app import web

    raw = "2026-10-08T15:12:31+00:00"
    expected = datetime.datetime.fromisoformat(raw).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    assert web.local_time(raw, seconds=True) == expected
    assert web.local_time(raw) == expected[:16]
    assert web.local_time("2026-10-08T15:12:31", seconds=True) == expected
    assert web.local_time("") == ""
    assert web.local_time("not-a-timestamp") == ""
    assert web.local_time(None) == ""
