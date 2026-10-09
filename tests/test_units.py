from __future__ import annotations

import datetime

import pytest

from app import certstore, crypto, db, names, repo


class TestNames:
    def test_normalize_domain_accepts_common_forms(self):
        assert names.normalize_domain("Example.com") == "example.com"
        assert names.normalize_domain("https://example.com") == "example.com"
        assert names.normalize_domain("example.com.") == "example.com"
        assert names.normalize_domain("*.example.com") == "example.com"
        # 子域名不会被自动缩成主域名：阿里云的 DomainName 必须是账号里的那个域名
        assert names.normalize_domain("www.example.com/x") == "www.example.com"

    def test_normalize_domain_rejects_junk(self):
        for value in ("", "example", "-bad.com", "exa mple.com", "a..b.com", "http://"):
            with pytest.raises(ValueError):
                names.normalize_domain(value)

    def test_rr_roundtrip(self):
        assert names.normalize_rr("", "example.com") == names.APEX
        assert names.normalize_rr("@", "example.com") == names.APEX
        assert names.normalize_rr("example.com", "example.com") == names.APEX
        assert names.normalize_rr("*.example.com", "example.com") == "*"
        assert names.normalize_rr("WWW.example.com.", "example.com") == "www"
        assert names.normalize_rr("www.other.com", "example.com") == "www.other.com"
        # real zones are full of underscore-prefixed records; they must not break imports
        assert names.normalize_rr("_dmarc", "example.com") == "_dmarc"
        assert names.normalize_rr("mail._domainkey", "example.com") == "mail._domainkey"
        assert names.normalize_rr("_acme-challenge", "example.com") == "_acme-challenge"
        assert names.rr_to_fqdn("example.com", "_dmarc") == "_dmarc.example.com"
        assert names.rr_to_fqdn("example.com", "*") == "*.example.com"
        assert names.rr_to_fqdn("example.com", "a.b") == "a.b.example.com"
        assert names.fqdn_to_rr("example.com", "_acme-challenge.a.b.example.com") == "_acme-challenge.a.b"

    def test_normalize_rr_rejects_junk(self):
        for value in ("not good", "bad..rr", ".www", "-bad", "www-", "www example", "带中文"):
            with pytest.raises(ValueError):
                names.normalize_rr(value, "example.com")

    def test_rr_to_fqdn_rejects_junk(self):
        with pytest.raises(ValueError):
            names.rr_to_fqdn("example.com", "has space")
        with pytest.raises(ValueError):
            names.fqdn_to_rr("example.com", "other.com")

    def test_txt_record_layout(self):
        assert names.txt_fqdn("example.com") == "_acme-challenge.example.com"
        assert names.txt_fqdn("*.example.com") == "_acme-challenge.example.com"
        assert names.txt_rr("example.com", "*.example.com") == "_acme-challenge"
        assert names.txt_rr("example.com", "www.example.com") == "_acme-challenge.www"

    def test_build_names_dedupes_and_sorts(self):
        assert names.build_names("example.com", ["www", "@", "www"]) == [
            "example.com",
            "www.example.com",
        ]
        with pytest.raises(ValueError):
            names.build_names("example.com", [])

    def test_wildcard_conflicts_match_the_live_ca_rule(self):
        # 实测 Let's Encrypt staging：通配符只覆盖一级标签，直接子级会被判为冗余，更深层可以共存
        assert names.wildcard_conflicts(["*.example.com", "www.example.com"]) == [
            ("www.example.com", "*.example.com")
        ]
        assert names.wildcard_conflicts(["*.sub.example.com", "www.sub.example.com"])
        assert names.wildcard_conflicts(["*.example.com", "deep.sub.example.com"]) == []
        assert names.wildcard_conflicts(["*.example.com", "example.com"]) == []
        assert names.wildcard_conflicts(["*.a.example.com", "*.b.example.com"]) == []

    def test_build_names_refuses_redundant_pairs(self):
        with pytest.raises(ValueError, match="通配符"):
            names.build_names("example.com", ["*", "www"])
        assert names.build_names("example.com", ["*", "@"]) == ["*.example.com", "example.com"]
        assert names.build_names("example.com", ["*", "deep.sub"]) == [
            "*.example.com",
            "deep.sub.example.com",
        ]


class TestCrypto:
    def test_secret_roundtrip(self):
        master = b"master-key-material-32-bytes-long"
        salt, nonce, cipher = crypto.encrypt_secret(master, "s3cr3t-AccessKey")
        assert "s3cr3t" not in cipher
        assert crypto.decrypt_secret(master, salt, nonce, cipher) == "s3cr3t-AccessKey"

    def test_wrong_master_key_cannot_decrypt(self):
        salt, nonce, cipher = crypto.encrypt_secret(b"A" * 32, "secret")
        with pytest.raises(Exception):
            crypto.decrypt_secret(b"B" * 32, salt, nonce, cipher)

    def test_same_secret_twice_differs(self):
        master = b"K" * 32
        assert crypto.encrypt_secret(master, "x") != crypto.encrypt_secret(master, "x")

    def test_password_hash_and_verify(self):
        stored = crypto.hash_password("correct horse battery staple")
        assert crypto.verify_password("correct horse battery staple", stored)
        assert not crypto.verify_password("nope", stored)
        assert not crypto.verify_password("x", "")

    def test_signed_token_detects_tampering(self):
        key = b"cookie-key"
        value = crypto.sign("7", key)
        assert crypto.unsign(value, key) == "7"
        assert crypto.unsign(value[:-2] + "xy", key) is None
        assert crypto.unsign(value, b"other-key") is None
        assert crypto.unsign("garbage", key) is None


class TestCertstore:
    @pytest.mark.parametrize("kind", list(certstore.KEY_TYPES))
    def test_key_and_csr(self, kind):
        from cryptography import x509

        key = certstore.generate_key(kind)
        csr = x509.load_pem_x509_csr(certstore.create_csr(key, ["example.com", "*.example.com"]))
        sans = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert set(sans.get_values_for_type(x509.DNSName)) == {"example.com", "*.example.com"}
        assert certstore.load_private_key(certstore.key_pem(key)) is not None

    def test_unknown_key_type(self):
        with pytest.raises(ValueError):
            certstore.generate_key("dsa1024")

    def test_days_left(self):
        later = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=45)
        assert 44 <= certstore.days_left(later) <= 45

    def test_split_and_chain(self, fake_fullchain):
        fullchain = fake_fullchain["fullchain"]
        assert len(certstore.split_pem_blocks(fullchain)) == 2
        assert "-----BEGIN CERTIFICATE-----" in certstore.chain_pem(fullchain)
        assert certstore.split_pem_blocks("not pem at all") == []

    def test_save_read_and_exports(self, tmp_path, fake_fullchain):
        directory = certstore.save(tmp_path, 7, fake_fullchain["leaf_key"], fake_fullchain["fullchain"])
        assert (directory / "fullchain.pem").is_file()
        assert (directory / "chain.pem").is_file()
        assert certstore.read(directory, "cert") == fake_fullchain["leaf_pem"].encode()
        assert certstore.load_private_key(certstore.read(directory, "key")) is not None

        certificate = certstore.load_certificate(certstore.read(directory, "cert"))
        assert certstore.serial(certificate) == "3039"
        assert certstore.validity(certificate)[1] == fake_fullchain["not_after"]

        assert certstore.as_der(directory)[:1] == b"\x30"
        assert len(certstore.as_pfx(directory, b"gateway")) > 500
        assert len(certstore.as_pfx(directory, b"")) > 200

    def test_read_rejects_unknown_kind(self, tmp_path, fake_fullchain):
        directory = certstore.save(tmp_path, 8, fake_fullchain["leaf_key"], fake_fullchain["fullchain"])
        with pytest.raises(ValueError):
            certstore.read(directory, "../../etc/passwd")
        with pytest.raises(FileNotFoundError):
            certstore.read(tmp_path / "cert-404", "cert")


class TestRepo:
    def test_credential_secret_stays_encrypted(self, settings):
        master = settings.master_key
        with db.session(settings.db_path) as conn:
            credential_id = repo.add_credential(conn, master, "ali", "LTAI5tABCDEFGHIJ", "topsecret")
            row = repo.get_credential(conn, credential_id)
            assert "topsecret" not in row["secret_cipher"]
            assert "topsecret" not in "".join(str(v) for v in tuple(row))
            assert repo.open_access_key(conn, master, credential_id) == ("LTAI5tABCDEFGHIJ", "topsecret")
            assert crypto.mask_access_key_id(row["access_key_id"]) == "LTAI****GHIJ"

    def test_blank_secret_and_eab_are_kept(self, settings):
        with db.session(settings.db_path) as conn:
            credential_id = repo.add_credential(
                conn, settings.master_key, "ali", "LTAI1", "secret", "kid-1", "hmac-1"
            )
            repo.update_credential(conn, settings.master_key, credential_id, "renamed", "LTAI2", None)
            assert repo.open_access_key(conn, settings.master_key, credential_id) == ("LTAI2", "secret")
            row = repo.get_credential(conn, credential_id)
            assert row["name"] == "renamed"
            assert (row["eab_kid"], row["eab_hmac_key"]) == ("kid-1", "hmac-1")

    def test_domain_and_subnames(self, settings):
        with db.session(settings.db_path) as conn:
            credential_id = repo.add_credential(conn, settings.master_key, "ali", "LTAI", "sec")
            domain_id = repo.add_domain(conn, credential_id, "example.com")
            repo.add_subname(conn, domain_id, "@")
            repo.add_subname(conn, domain_id, "*")
            repo.add_subname(conn, domain_id, "www.example.com")
            repo.add_subname(conn, domain_id, "api", enabled=False)
            assert repo.enabled_rrs(conn, domain_id) == ["*", "@", "www"]
            rows = {row["rr"]: row for row in repo.list_subnames(conn, domain_id)}
            assert len(rows) == 4
            repo.set_subname_enabled(conn, rows["*"]["id"], False)
            assert repo.enabled_rrs(conn, domain_id) == ["@", "www"]
            # re-adding an existing rr turns it back on instead of duplicating the row
            repo.add_subname(conn, domain_id, "*")
            assert repo.enabled_rrs(conn, domain_id) == ["*", "@", "www"]
            repo.delete_subname(conn, rows["www"]["id"])
            assert "www" not in repo.enabled_rrs(conn, domain_id)

    def test_credential_with_domains_cannot_disappear(self, settings):
        with db.session(settings.db_path) as conn:
            credential_id = repo.add_credential(conn, settings.master_key, "ali", "LTAI", "sec")
            repo.add_domain(conn, credential_id, "example.com")
        import sqlite3

        with pytest.raises(sqlite3.IntegrityError):
            with db.session(settings.db_path) as conn:
                repo.delete_credential(conn, credential_id)

    def test_events_are_pruned(self, settings):
        with db.session(settings.db_path) as conn:
            credential_id = repo.add_credential(conn, settings.master_key, "ali", "LTAI", "sec")
            domain_id = repo.add_domain(conn, credential_id, "example.com")
            cert_id = repo.create_certificate(conn, domain_id, ["example.com"], "rsa2048", "https://x/directory")
            for index in range(20):
                repo.log_event(conn, cert_id, "info", f"step {index}")
            repo.prune_events(conn, cert_id, keep=5)
            assert len(repo.list_events(conn, cert_id)) == 5
            assert repo.list_events(conn, cert_id, after_id=19)[0]["message"] == "step 19"

    def test_settings_defaults_and_ints(self, settings):
        with db.session(settings.db_path) as conn:
            values = db.all_settings(conn)
            assert values["ca_name"] == "letsencrypt-staging"
            assert db.setting_int(conn, "renew_before_days", 7) == 30
            db.set_setting(conn, "renew_before_days", "oops")
            assert db.setting_int(conn, "renew_before_days", 7) == 7
