"""Aliyun Alidns OpenAPI wrapper plus dns-01 TXT propagation checks."""

from __future__ import annotations

import logging
import socket
import time
from dataclasses import dataclass

import dns.exception
import dns.resolver
from alibabacloud_alidns20150109 import models as alidns_models
from alibabacloud_alidns20150109.client import Client as AlidnsClient
from alibabacloud_tea_openapi import models as open_api_models

logger = logging.getLogger(__name__)

ENDPOINT = "alidns.aliyuncs.com"
RECURSIVE_NAMESERVERS = ["223.5.5.5", "119.29.29.29", "223.6.6.6"]
DEFAULT_TTL = 600


class AliDnsError(RuntimeError):
    pass


@dataclass
class DnsRecord:
    record_id: str
    rr: str
    type: str
    value: str
    ttl: int


class AliDns:
    def __init__(self, access_key_id: str, access_key_secret: str):
        config = open_api_models.Config(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret,
            endpoint=ENDPOINT,
            connect_timeout=10000,
            read_timeout=15000,
        )
        self._client = AlidnsClient(config)

    def _call(self, request, method: str):
        try:
            return getattr(self._client, method)(request)
        except Exception as exc:  # alibabacloud raises TeaException / ClientException
            raise AliDnsError(_friendly_aliyun_error(exc)) from exc

    def list_domains(self) -> list[dict]:
        result = []
        page = 1
        while True:
            response = self._call(
                alidns_models.DescribeDomainsRequest(page_number=page, page_size=100),
                "describe_domains",
            )
            domains = response.body.domains.domain if response.body.domains else []
            for item in domains:
                result.append(
                    {
                        "domain": item.domain_name,
                        "record_count": item.record_count,
                        "version_name": getattr(item, "version_name", "") or "",
                    }
                )
            if len(result) >= (response.body.total_count or 0) or not domains:
                break
            page += 1
        return result

    def list_records(self, domain: str, rr: str = "", record_type: str = "") -> list[DnsRecord]:
        records: list[DnsRecord] = []
        page = 1
        while True:
            request = alidns_models.DescribeDomainRecordsRequest(
                domain_name=domain,
                page_number=page,
                page_size=500,
                rrkey_word=rr or None,
                type=record_type or None,
            )
            response = self._call(request, "describe_domain_records")
            items = response.body.domain_records.record if response.body.domain_records else []
            for item in items:
                records.append(
                    DnsRecord(
                        record_id=str(item.record_id),
                        rr=item.rr or "",
                        type=item.type or "",
                        value=item.value or "",
                        ttl=int(item.ttl or DEFAULT_TTL),
                    )
                )
            if len(records) >= (response.body.total_count or 0) or not items:
                break
            page += 1
        return records

    def add_record(self, domain: str, rr: str, record_type: str, value: str, ttl: int = DEFAULT_TTL) -> str:
        request = alidns_models.AddDomainRecordRequest(
            domain_name=domain, rr=rr, type=record_type, value=value, ttl=ttl
        )
        response = self._call(request, "add_domain_record")
        return str(response.body.record_id)

    def update_record(
        self, record_id: str, rr: str, record_type: str, value: str, ttl: int = DEFAULT_TTL
    ) -> None:
        request = alidns_models.UpdateDomainRecordRequest(
            record_id=record_id, rr=rr, type=record_type, value=value, ttl=ttl
        )
        self._call(request, "update_domain_record")

    def delete_records(self, record_ids: list[str]) -> int:
        deleted = 0
        for record_id in record_ids:
            request = alidns_models.DeleteDomainRecordRequest(record_id=record_id)
            self._call(request, "delete_domain_record")
            deleted += 1
        return deleted

    def upsert_txt(self, domain: str, rr: str, value: str, ttl: int = DEFAULT_TTL) -> list[str]:
        """Create the TXT record unless an identical one already exists; returns record ids kept."""
        wanted = rr.lower().rstrip(".")
        existing = [
            record
            for record in self.list_records(domain, rr=rr, record_type="TXT")
            if record.rr.lower().rstrip(".") == wanted
        ]
        match = next((record for record in existing if record.value == value), None)
        if match:
            return [match.record_id]
        return [self.add_record(domain, rr, "TXT", value, ttl)]


_ERROR_HINTS = (
    ("invalidaccesskeyid", "AccessKeyId 不存在或填错，请到阿里云 RAM 控制台核对（注意不要带空格）。"),
    ("signaturedoesnotmatch", "AccessKeySecret 不正确；也请检查服务器系统时间是否准。"),
    ("forbidden.ram", "RAM 权限不足。请授权 alidns:AddDomainRecord / UpdateDomainRecord / DeleteDomainRecord / DescribeDomainRecords。"),
    ("accessdenied", "RAM 权限不足。请授权 alidns:AddDomainRecord / UpdateDomainRecord / DeleteDomainRecord / DescribeDomainRecords。"),
    ("nopermission", "RAM 权限不足。请授权 alidns:AddDomainRecord / UpdateDomainRecord / DeleteDomainRecord / DescribeDomainRecords。"),
    ("noauth", "RAM 权限不足。请授权 alidns:AddDomainRecord / UpdateDomainRecord / DeleteDomainRecord / DescribeDomainRecords。"),
    ("domainnotfound", "该域名不在当前阿里云账号下，或域名写错了。"),
    ("nodomainfound", "该域名不在当前阿里云账号下，或域名写错了。"),
    ("invaliddomainname", "该域名不在当前阿里云账号下，或域名写错了。"),
    ("throttling", "阿里云 API 限流，请稍后再试（不要高频重试）。"),
    ("lastreferencedresourcetype", "该 RR 与已有记录冲突，请到阿里云解析检查同名记录。"),
    ("invalidparameter", "参数不合法（域名、主机记录或记录值格式不对）。"),
    ("dnssec", "域名启用了 DNSSEC/其它解析限制，请检查阿里云解析设置。"),
)


def _friendly_aliyun_error(exc: Exception) -> str:
    code = str(getattr(exc, "code", "") or "")
    status = getattr(exc, "status_code", None)
    data = getattr(exc, "data", None) or {}
    detail = str(data.get("Message") or "").strip() or str(exc)
    needle = f"{code} {detail}".lower()

    hint = next((text for key, text in _ERROR_HINTS if key in needle), "")
    if code:
        where = f"阿里云 {code}" + (f"（HTTP {status}）" if status else "")
    else:
        where = "阿里云 DNS 接口调用失败"
    message = f"{where}：{detail[:180]}"
    return f"{hint}｜{message}" if hint else message


class PropagationChecker:
    """Checks that the dns-01 TXT record is visible to the ACME server's resolvers."""

    def __init__(self, timeout: int = 180, interval: int = 5):
        self.timeout = timeout
        self.interval = interval

    def wait(self, fqdn: str, value: str) -> tuple[bool, str]:
        deadline = time.monotonic() + self.timeout
        authoritative = self._authoritative_nameservers(fqdn)
        attempts = 0
        last = "尚未查询"
        while True:
            attempts += 1
            seen, last = self._lookup(fqdn, authoritative)
            if value in seen:
                return True, f"{fqdn} TXT 已生效（第 {attempts} 次查询，来源：{last}）"
            if time.monotonic() + self.interval > deadline:
                return False, f"等待 {self.timeout}s 后仍未查到 {fqdn} TXT={value}（最后结果：{last}）"
            time.sleep(self.interval)

    def _lookup(self, fqdn: str, nameservers: list[str]) -> tuple[set[str], str]:
        for label, servers in (("权威 NS", nameservers), ("公共递归", RECURSIVE_NAMESERVERS)):
            if not servers:
                continue
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = servers
            resolver.timeout = 5
            resolver.lifetime = 8
            try:
                answers = resolver.resolve(fqdn, "TXT")
            except (dns.exception.DNSException, socket.timeout, OSError):
                continue
            values: set[str] = set()
            for rdata in answers:
                # A TXT RDATA may be split into several character-strings; they join into one value.
                values.add(b"".join(rdata.strings).decode("utf-8", "replace"))
            return values, f"{label} {','.join(servers)} -> {sorted(values)}"
        return set(), "所有 DNS 服务器均查询失败"

    def _authoritative_nameservers(self, fqdn: str) -> list[str]:
        parts = fqdn.lower().strip(".").split(".")
        for depth in range(1, min(4, len(parts))):
            zone = ".".join(parts[-depth - 1 :])
            try:
                answers = _ns_lookup(zone)
            except (dns.exception.DNSException, OSError):
                continue
            ips: list[str] = []
            for ns in answers:
                try:
                    for host in socket.getaddrinfo(str(ns), None, socket.AF_INET):
                        ips.append(host[4][0])
                except socket.gaierror:
                    logger.debug("无法解析权威 NS %s", ns)
            if ips:
                return sorted(set(ips))
        return []


def _ns_lookup(zone: str) -> list[str]:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = RECURSIVE_NAMESERVERS
    resolver.timeout = 5
    resolver.lifetime = 8
    return [str(rdata.target).rstrip(".") for rdata in resolver.resolve(zone, "NS")]
