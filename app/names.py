"""Domain name maths: host records, FQDNs, and the dns-01 TXT record layout."""

from __future__ import annotations

import re

# Underscores are legal in real zone records (_dmarc, mail._domainkey, _acme-challenge, ...),
# so labels allow "_" while still rejecting spaces, empty labels and trailing hyphens.
LABEL = re.compile(r"^(?=.{1,63}$)[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?$")
ACME_TXT_LABEL = "_acme-challenge"

WILDCARD = "*"
APEX = "@"


def normalize_domain(text: str) -> str:
    """Turn user input (example.com, https://EXAMPLE.com/, *.example.com) into a root domain."""
    value = text.strip().lower()
    for scheme in ("http://", "https://", "ws://", "wss://"):
        if value.startswith(scheme):
            value = value[len(scheme) :]
    value = value.strip("/.").split("/")[0].split(":")[0]
    if value.startswith("*."):
        value = value[2:]
    labels = value.split(".")
    if len(labels) < 2 or not all(LABEL.match(label) for label in labels):
        raise ValueError(f"不是合法的域名：{text!r}")
    return value


def is_valid_rr(rr: str) -> bool:
    if rr in (APEX, WILDCARD):
        return True
    if not rr or rr.startswith(".") or rr.endswith("."):
        return False
    return all(LABEL.match(label) or label == WILDCARD for label in rr.split("."))


def normalize_rr(rr: str, domain: str = "") -> str:
    """Accept '@', 'www', 'api.dev', '*.example.com' or 'www.example.com' and return the host record."""
    value = (rr or "").strip().lower().rstrip(".")
    if value in ("", APEX, "apex"):
        return APEX
    if domain:
        if value == domain:
            return APEX
        if value.startswith("*.") and value[2:] == domain:
            return WILDCARD
        suffix = f".{domain}"
        if value.endswith(suffix):
            value = value[: -len(suffix)]
    if not is_valid_rr(value):
        raise ValueError(f"不是合法的主机记录：{rr!r}")
    return value


def rr_to_fqdn(domain: str, rr: str) -> str:
    rr = (rr or APEX).strip().lower().rstrip(".")
    if rr in (APEX, ""):
        return domain
    if not is_valid_rr(rr):
        raise ValueError(f"不是合法的记录值（主机记录）：{rr!r}")
    return f"{rr}.{domain}"


def fqdn_to_rr(domain: str, fqdn: str) -> str:
    fqdn = fqdn.strip().lower().rstrip(".")
    if fqdn == domain:
        return APEX
    suffix = f".{domain}"
    if not fqdn.endswith(suffix):
        raise ValueError(f"{fqdn} 不属于域名 {domain}")
    return fqdn[: -len(suffix)]


def txt_fqdn(fqdn: str) -> str:
    """dns-01 TXT name for an identifier: _acme-challenge.<name without the wildcard label>."""
    name = fqdn.strip().lower()
    if name.startswith("*."):
        name = name[2:]
    return f"{ACME_TXT_LABEL}.{name}"


def txt_rr(domain: str, fqdn: str) -> str:
    """Host record to create inside `domain` so that `txt_fqdn(fqdn)` resolves."""
    return fqdn_to_rr(domain, txt_fqdn(fqdn))


def wildcard_conflicts(sans: list[str]) -> list[tuple[str, str]]:
    """Names the CA rejects inside the same order: an immediate child of a wildcard.

    Let's Encrypt treats ``*.example.com`` as covering exactly one label, so
    ``www.example.com`` is redundant (order refused) while ``a.b.example.com`` is fine.
    """
    conflicts: list[tuple[str, str]] = []
    for wildcard in sans:
        if not wildcard.startswith("*."):
            continue
        base = wildcard[2:]
        for name in sans:
            if name in (wildcard, base):
                continue
            deeper = name.endswith(f".{base}") and name.count(".") == base.count(".") + 1
            if deeper:
                conflicts.append((name, wildcard))
    return conflicts


def build_names(domain: str, rrs: list[str]) -> list[str]:
    """Certificate SAN list from a root domain plus the chosen host records."""
    if not rrs:
        raise ValueError("请至少选择一个域名或子域名")
    names_: set[str] = set()
    for rr in rrs:
        names_.add(rr_to_fqdn(domain, rr))
    sans = sorted(names_)
    conflicts = wildcard_conflicts(sans)
    if conflicts:
        covered, wildcard = conflicts[0]
        raise ValueError(
            f"CA 会拒绝这张证书：通配符 {wildcard} 已经覆盖 {covered}，两者不能出现在同一订单里。"
            f"请取消勾选 {covered}，或去掉泛域名 {wildcard}。"
            f"（更深层的名字如 a.b.{wildcard[2:]} 不受影响，可以与泛域名共存。）"
        )
    return sans
