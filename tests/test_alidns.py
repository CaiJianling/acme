"""Aliyun DNS wrapper tests: request shapes, TXT de-duplication, error mapping, TXT reading.

These use a stubbed SDK client (no network) because the parameter names of the generated
models are exactly the kind of thing that breaks silently.
"""

from __future__ import annotations

import pytest

from app import alidns


class StubResponse:
    def __init__(self, body):
        self.body = body


class RecordBody:
    def __init__(self, record_id, rr, rtype, value, ttl=600):
        self.record_id = record_id
        self.rr = rr
        self.type = rtype
        self.value = value
        self.ttl = ttl


class FakeSdkClient:
    """Stands in for alibabacloud_alidns20150109.client.Client."""

    def __init__(self, records=(), total=None, error=None):
        self.requests = []
        self.records = list(records)
        self.total = total if total is not None else len(records)
        self.error = error

    def _fail(self):
        if self.error is not None:
            raise self.error

    def describe_domains(self, request):
        self.requests.append(("describe_domains", request))
        self._fail()

        class Domains:
            domain = []

        body = type("Body", (), {"domains": Domains(), "total_count": 0})()
        return StubResponse(body)

    def describe_domain_records(self, request):
        self.requests.append(("describe_domain_records", request))
        self._fail()
        start = (request.page_number - 1) * request.page_size
        chunk = self.records[start : start + request.page_size]
        container = type("Records", (), {"record": chunk})()
        body = type("Body", (), {"domain_records": container, "total_count": self.total})()
        return StubResponse(body)

    def add_domain_record(self, request):
        self.requests.append(("add_domain_record", request))
        self._fail()
        return StubResponse(type("Body", (), {"record_id": "rec-77"})())

    def delete_domain_record(self, request):
        self.requests.append(("delete_domain_record", request))
        self._fail()
        return StubResponse(type("Body", (), {})())


@pytest.fixture
def dns() -> alidns.AliDns:
    instance = alidns.AliDns("LTAI5test", "secret")
    instance._client = FakeSdkClient()
    return instance


def records_of(*pairs, ttl=600):
    return [RecordBody(index + 1, rr, rtype, value, ttl) for index, (rr, rtype, value) in enumerate(pairs)]


class TestListRecords:
    def test_request_uses_the_generated_parameter_names(self, dns):
        dns._client = FakeSdkClient(records=records_of(("_acme-challenge", "TXT", "abc")))
        result = dns.list_records("example.com", rr="_acme-challenge", record_type="TXT")

        method, request = dns._client.requests[0]
        assert method == "describe_domain_records"
        assert request.domain_name == "example.com"
        assert request.rrkey_word == "_acme-challenge"
        assert request.type == "TXT"
        assert request.page_size == 500
        assert [record.value for record in result] == ["abc"]

    def test_empty_filters_are_not_sent(self, dns):
        dns._client = FakeSdkClient()
        dns.list_records("example.com")
        _, request = dns._client.requests[0]
        assert request.rrkey_word is None and request.type is None

    def test_pagination_walks_every_page(self, dns):
        many = records_of(*(("www", "A", f"1.2.3.{i}") for i in range(7)))

        def paging(request):
            chunk = many[:5] if request.page_number == 1 else many[5:]
            container = type("Records", (), {"record": chunk})()
            return StubResponse(type("Body", (), {"domain_records": container, "total_count": 7})())

        dns._client = FakeSdkClient()
        dns._client.describe_domain_records = paging
        assert len(dns.list_records("example.com")) == 7

    def test_sdk_error_becomes_readable(self, dns):
        dns._client = FakeSdkClient(error=RuntimeError("boom"))
        with pytest.raises(alidns.AliDnsError, match="阿里云 DNS"):
            dns.list_records("example.com")


class TestUpsertTxt:
    def test_existing_identical_txt_is_reused(self, dns):
        dns._client = FakeSdkClient(
            records=records_of(("_acme-challenge", "TXT", "same-value"), ("_acme-challenge", "TXT", "other"))
        )
        kept = dns.upsert_txt("example.com", "_acme-challenge", "same-value")
        assert kept == ["1"]
        assert not [name for name, _ in dns._client.requests if name == "add_domain_record"]

    def test_missing_record_is_created_with_ttl(self, dns):
        dns._client = FakeSdkClient(records=records_of(("_acme-challenge.www", "TXT", "zz")))
        kept = dns.upsert_txt("example.com", "_acme-challenge", "brand-new")
        assert kept == ["rec-77"]
        _, request = [entry for entry in dns._client.requests if entry[0] == "add_domain_record"][0]
        assert (request.domain_name, request.rr, request.type, request.value, request.ttl) == (
            "example.com",
            "_acme-challenge",
            "TXT",
            "brand-new",
            alidns.DEFAULT_TTL,
        )

    def test_fuzzy_server_match_on_another_rr_is_ignored(self, dns):
        """Aliyun filters RR fuzzily; a record for _acme-challenge.www must not satisfy _acme-challenge."""
        dns._client = FakeSdkClient(records=records_of(("_acme-challenge.www", "TXT", "value-we-want")))
        kept = dns.upsert_txt("example.com", "_acme-challenge", "value-we-want")
        assert kept == ["rec-77"]

    def test_delete_records_returns_count(self, dns):
        dns._client = FakeSdkClient()
        assert dns.delete_records(["1", "2", "3"]) == 3


class TestErrorMessages:
    class TeaError(Exception):
        def __init__(self, code, message, status=None, data=None):
            super().__init__(f"Error: {code} code: {status}, {message}")
            self.code = code
            self.message = message
            self.status_code = status
            self.data = data or {}

    @pytest.mark.parametrize(
        "code,fragment",
        [
            ("InvalidAccessKeyId.NotFound", "AccessKeyId 不存在或填错"),
            ("SignatureDoesNotMatch", "AccessKeySecret 不正确"),
            ("Forbidden.RAM", "RAM 权限不足"),
            ("InvalidDomainName.NotFound", "不在当前阿里云账号"),
            ("Throttling.User", "限流"),
        ],
    )
    def test_each_code_gets_a_chinese_hint(self, code, fragment):
        text = alidns._friendly_aliyun_error(self.TeaError(code, "some server text", 400))
        assert fragment in text
        assert code in text

    def test_hint_stays_short(self):
        long = "x" * 500
        text = alidns._friendly_aliyun_error(self.TeaError("InternalError", long, 500))
        assert len(text) < 400

    def test_message_without_code_still_readable(self):
        assert "阿里云 DNS 接口调用失败" in alidns._friendly_aliyun_error(RuntimeError("socket closed"))


class TestPropagationLookup:
    def test_txt_strings_are_decoded(self, monkeypatch):
        class FakeAnswer:
            def __init__(self, strings):
                self.strings = strings

        class FakeResolver:
            def __init__(self, configure=False):
                self.nameservers = []
                self.timeout = 0
                self.lifetime = 0

            def resolve(self, name, rdtype):
                assert (name, rdtype) == ("_acme-challenge.example.com", "TXT")
                return [FakeAnswer([b"chunk-one", b"part-two"]), FakeAnswer([b"other"])]

        monkeypatch.setattr(alidns.dns.resolver, "Resolver", FakeResolver)
        # skip authoritative-NS discovery so the check falls back to the recursive servers
        monkeypatch.setattr(
            alidns.PropagationChecker, "_authoritative_nameservers", lambda self, fqdn: []
        )
        checker = alidns.PropagationChecker(timeout=1)
        seen, detail = checker._lookup("_acme-challenge.example.com", [])
        assert seen == {"chunk-onepart-two", "other"}
        assert "公共递归" in detail
        ok, message = checker.wait("_acme-challenge.example.com", "chunk-onepart-two")
        assert ok is True and "已生效" in message

    def test_all_nameservers_failing_is_reported(self, monkeypatch):
        class Boom:
            def __init__(self, configure=False):
                self.nameservers = []
                self.timeout = 0
                self.lifetime = 0

            def resolve(self, name, rdtype):
                raise alidns.dns.exception.DNSException("server misbehaving")

        monkeypatch.setattr(alidns.dns.resolver, "Resolver", Boom)
        checker = alidns.PropagationChecker(timeout=1)
        seen, detail = checker._lookup("x.example.com", ["1.1.1.1"])
        assert seen == set()
        assert "查询失败" in detail
