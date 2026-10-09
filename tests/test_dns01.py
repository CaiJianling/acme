"""dns-01 record layout tests: no network, real DNS01 challenge objects."""

from __future__ import annotations

import base64
import hashlib
import types

import pytest
from acme import challenges

from app import alidns, issuer


def make_token(text: str) -> bytes:
    """acme stores challenge tokens as bytes; josepy base64-encodes them on the wire."""
    return base64.urlsafe_b64encode(hashlib.sha256(text.encode("utf-8")).digest()).rstrip(b"=")


def dns01(token: str) -> types.SimpleNamespace:
    return types.SimpleNamespace(chall=challenges.DNS01(token=make_token(token)))


def authz(identifier: str, token: str) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        body=types.SimpleNamespace(
            identifier=types.SimpleNamespace(value=identifier),
            challenges=[dns01(token)],
        )
    )


class FakeDns:
    def __init__(self):
        self.calls: list[tuple[str, str, str]] = []

    def upsert_txt(self, domain, rr, value, ttl=600):
        self.calls.append((domain, rr, value))
        return [str(len(self.calls))]

    def delete_records(self, record_ids):
        self.deleted = record_ids
        return len(record_ids)


class FakeClient:
    def __init__(self):
        self.answered = []

    def answer_challenge(self, challb, response):
        self.answered.append((challb, response))


@pytest.fixture
def account_key(tmp_path):
    return issuer.load_account_key(tmp_path / "account.key")


@pytest.fixture
def patched_checker(monkeypatch):
    """Make the propagation wait succeed instantly and record the names it was asked about."""
    seen: list[str] = []

    class Checker:
        def __init__(self, timeout: int = 0):
            self.timeout = timeout

        def wait(self, fqdn, value):
            seen.append(fqdn)
            return True, f"{fqdn} ok"

    monkeypatch.setattr(alidns, "PropagationChecker", Checker)
    return seen


def test_apex_and_wildcard_share_one_name_with_two_values(account_key, patched_checker):
    order = types.SimpleNamespace(
        authorizations=[authz("example.com", "token-a"), authz("example.com", "token-b")]
    )
    dns, client = FakeDns(), FakeClient()

    issuer._present_dns01(
        dns,
        client,
        account_key,
        "example.com",
        order,
        issuer.IssuerConfig(directory_url="https://x/directory"),
        [],
        lambda level, message: None,
    )

    assert [call[1] for call in dns.calls] == ["_acme-challenge", "_acme-challenge"]
    assert dns.calls[0][2] != dns.calls[1][2]
    assert patched_checker == ["_acme-challenge.example.com", "_acme-challenge.example.com"]
    assert len(client.answered) == 2


def test_wildcard_identifier_is_stripped_before_building_txt_name(account_key, patched_checker):
    order = types.SimpleNamespace(authorizations=[authz("*.example.com", "token-w")])
    record_ids: list[str] = []

    issuer._present_dns01(
        FakeDns(), FakeClient(), account_key, "example.com", order,
        issuer.IssuerConfig(directory_url="https://x/directory"), record_ids,
        lambda level, message: None,
    )
    assert patched_checker == ["_acme-challenge.example.com"]
    assert record_ids == ["1"]


def test_subdomain_names_and_multiple_labels(account_key, patched_checker):
    order = types.SimpleNamespace(
        authorizations=[authz("www.example.com", "t1"), authz("deep.sub.example.com", "t2")]
    )
    dns = FakeDns()

    issuer._present_dns01(
        dns, FakeClient(), account_key, "example.com", order,
        issuer.IssuerConfig(directory_url="https://x/directory"), [],
        lambda level, message: None,
    )
    assert [call[1] for call in dns.calls] == ["_acme-challenge.www", "_acme-challenge.deep.sub"]
    assert patched_checker == [
        "_acme-challenge.www.example.com",
        "_acme-challenge.deep.sub.example.com",
    ]


def test_identifier_outside_the_managed_domain_reports_clearly(account_key, patched_checker):
    order = types.SimpleNamespace(authorizations=[authz("evil.other.tld", "t")])

    with pytest.raises(ValueError):
        issuer._present_dns01(
            FakeDns(), FakeClient(), account_key, "example.com", order,
            issuer.IssuerConfig(directory_url="https://x/directory"), [],
            lambda level, message: None,
        )


def test_missing_dns01_challenge_is_an_error(account_key, patched_checker):
    order = types.SimpleNamespace(
        authorizations=[
            types.SimpleNamespace(
                body=types.SimpleNamespace(
                    identifier=types.SimpleNamespace(value="example.com"), challenges=[]
                )
            )
        ]
    )
    with pytest.raises(issuer.IssuerError, match="dns-01"):
        issuer._present_dns01(
            FakeDns(), FakeClient(), account_key, "example.com", order,
            issuer.IssuerConfig(directory_url="https://x/directory"), [],
            lambda level, message: None,
        )


def test_txt_cleanup_runs_even_when_validation_fails(account_key, monkeypatch):
    class Boom(alidns.PropagationChecker):
        def wait(self, fqdn, value):
            return False, "超时"

    monkeypatch.setattr(alidns, "PropagationChecker", Boom)
    record_ids = ["9"]
    dns = FakeDns()

    with pytest.raises(issuer.IssuerError, match="没有生效"):
        issuer._present_dns01(
            dns, FakeClient(), account_key, "example.com",
            types.SimpleNamespace(authorizations=[authz("example.com", "t")]),
            issuer.IssuerConfig(directory_url="https://x/directory"), record_ids,
            lambda level, message: None,
        )
    issuer._cleanup_txt(dns, record_ids, lambda level, message: None)
    # the caller-owned list accumulates every record id created so far, so cleanup can remove them all
    assert dns.deleted == ["9", "1"]


def test_account_key_is_persisted_and_reused(tmp_path):
    path = tmp_path / "account.key"
    first = issuer.load_account_key(path)
    assert path.is_file()
    assert issuer.load_account_key(path).thumbprint() == first.thumbprint()


@pytest.mark.parametrize(
    "typ,detail,fragment",
    [
        ("urn:ietf:params:acme:error:dns", "DNS problem", "NS 指向"),
        ("urn:ietf:params:acme:error:rateLimited", "too many", "速率限制"),
        ("urn:ietf:params:acme:error:caa", "caa", "CAA"),
        ("urn:ietf:params:acme:error:unauthorized", "jws", "服务条款"),
    ],
)
def test_error_mapping_gives_domestic_actionable_hints(typ, detail, fragment):
    text = issuer.acme_error_text(types.SimpleNamespace(typ=typ, detail=detail))
    assert fragment in text


def test_ca_overload_is_not_reported_as_a_quota_problem():
    """Boulder uses the rateLimited type for its own "Service busy" throttling."""
    text = issuer.acme_error_text(
        types.SimpleNamespace(
            typ="urn:ietf:params:acme:error:rateLimited", detail="Service busy; retry later."
        )
    )
    assert "CA 服务暂时不可用" in text
    assert "不是你的域名额度用尽" in text
    assert "每周约 50 张" not in text
