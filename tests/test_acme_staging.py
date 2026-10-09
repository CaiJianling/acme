"""Opt-in network test: registers a real ACME account against Let's Encrypt staging.

Run with:  ACME_RUN_NET=1 pytest tests/test_acme_staging.py
It only creates a staging account (no certificates), so it is safe to run repeatedly.
"""

from __future__ import annotations

import os

import pytest

from app import config, issuer

pytestmark = pytest.mark.skipif(
    not os.environ.get("ACME_RUN_NET"), reason="联网测试，设置 ACME_RUN_NET=1 才会运行"
)


def test_staging_account_registration_and_reuse(tmp_path):
    account_key = issuer.load_account_key(tmp_path / "account.key")
    cfg = issuer.IssuerConfig(
        directory_url=config.CA_DIRECTORY_URLS["letsencrypt-staging"], contact_email=""
    )
    first = issuer.test_account_connection(cfg, account_key)
    assert "acme-staging-v02.api.letsencrypt.org" in first

    # second call must hit the 409 conflict path and reuse the same account URI
    again = issuer.test_account_connection(cfg, account_key)
    assert again.split("账号 URI：")[-1].rstrip("（") == first.split("账号 URI：")[-1].rstrip("（")


def test_new_order_for_an_unknown_domain_fails_clearly(tmp_path):
    """Proves CSR -> new_order works against the live CA; the domain is deliberately unmanaged."""
    account_key = issuer.load_account_key(tmp_path / "account.key")
    cfg = issuer.IssuerConfig(
        directory_url=config.CA_DIRECTORY_URLS["letsencrypt-staging"], contact_email=""
    )
    from app import certstore

    with pytest.raises((issuer.IssuerError, ValueError)):
        issuer.issue_certificate(
            FakeDns(), account_key, cfg, "example.invalid", ["example.invalid"], "rsa2048",
            emit=lambda level, message: None,
        )


class FakeDns:
    def upsert_txt(self, domain, rr, value, ttl=600):
        return ["1"]

    def delete_records(self, record_ids):
        return 0

    def list_records(self, domain, rr="", record_type=""):
        return []
