"""ACME dns-01 issuance built on the official python-acme library (the acme.sh equivalent)."""

from __future__ import annotations

import datetime
import pathlib
from collections.abc import Callable
from dataclasses import dataclass, field

import requests
from acme import challenges
from acme import client as acme_client
from acme import errors as acme_errors
from acme import messages
from cryptography.hazmat.primitives import serialization
from josepy import RS256, JWK

from . import alidns, certstore, names

Emitter = Callable[[str, str], None]

USER_AGENT = "py-acme-manager/1.0"
POLL_DEADLINE_SECONDS = 300
REVOKE_REASONS = {
    "unspecified": 0,
    "keyCompromise": 1,
    "superseded": 4,
    "cessationOfOperation": 5,
}

_ERROR_HINTS = {
    "dns": "DNS 验证失败。请确认域名已托管在当前阿里云账号、NS 指向 *.alidns.com，且没有别的 DNS 服务商在解析它。",
    "ratelimited": "已触发 CA 速率限制（同一批域名每周约 50 张证书）。请降低频率，测试请改用 staging 目录。",
    "caa": "域名的 CAA 记录拒绝该 CA 签发。请删除阿里云解析里的 CAA 记录，或添加 0 issue \"letsencrypt.org\"。",
    "unauthorized": "CA 拒绝了请求。请检查账号状态、联系邮箱格式，以及是否同意服务条款。",
    "malformed": "CA 认为请求不合法。常见原因：域名格式不对、同一订单里混用了 *.example.com 与 example.com 之外的非法名字。",
    "connection": "CA 与本机之间的网络请求失败。国内服务器访问 Let's Encrypt 可能不稳定，可换 CA 目录重试。",
}


class IssuerError(RuntimeError):
    pass


@dataclass
class IssuerConfig:
    directory_url: str
    contact_email: str = ""
    eab_kid: str = ""
    eab_hmac_key: str = ""
    propagation_timeout: int = 180


@dataclass
class IssueResult:
    fullchain_pem: str
    privkey_pem: bytes
    not_before: datetime.datetime
    not_after: datetime.datetime
    serial: str
    order_uri: str = ""
    names: list[str] = field(default_factory=list)


def _noop(level: str, message: str) -> None:
    return None


def load_account_key(path: pathlib.Path) -> JWK:
    """Load the ACME account key, creating a fresh RSA-2048 one on first use."""
    if not path.is_file():
        key = certstore.generate_key("rsa2048")
        path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        path.chmod(0o600)
    return JWK.load(path.read_bytes())


def get_directory(url: str) -> messages.Directory:
    try:
        response = requests.get(url, timeout=30, headers={"User-Agent": USER_AGENT})
        response.raise_for_status()
    except requests.RequestException as exc:
        raise IssuerError(f"无法访问 CA 目录 {url}：{exc}。{_ERROR_HINTS['connection']}") from exc
    return messages.Directory.from_json(response.json())


def build_client(directory: messages.Directory, account_key: JWK) -> acme_client.ClientV2:
    net = acme_client.ClientNetwork(key=account_key, alg=RS256, user_agent=USER_AGENT, timeout=45)
    return acme_client.ClientV2(directory=directory, net=net)


def register_account(
    client_v2: acme_client.ClientV2,
    account_key: JWK,
    config: IssuerConfig,
    emit: Emitter = _noop,
) -> messages.RegistrationResource:
    """Register an account, or reuse the existing one that matches this account key."""
    kwargs: dict = {"terms_of_service_agreed": True}
    if config.contact_email:
        kwargs["contact"] = (f"mailto:{config.contact_email}",)
    if config.eab_kid and config.eab_hmac_key:
        kwargs["external_account_binding"] = messages.ExternalAccountBinding.from_data(
            account_public_key=account_key.public_key(),
            kid=config.eab_kid,
            hmac_key=config.eab_hmac_key,
            directory=client_v2.directory,
        )
    try:
        regr = client_v2.new_account(messages.NewRegistration.from_data(**kwargs))
        emit("info", f"已在 CA 注册 ACME 账号：{regr.uri}")
        return regr
    except acme_errors.ConflictError as exc:
        regr = messages.RegistrationResource(
            body=messages.Registration(status=messages.STATUS_VALID), uri=exc.location
        )
        found = client_v2.query_registration(regr)
        emit("info", f"复用已有的 ACME 账号：{found.uri}")
        return found
    except messages.Error as exc:
        raise IssuerError(acme_error_text(exc)) from exc


def issue_certificate(
    dns: alidns.AliDns,
    account_key: JWK,
    config: IssuerConfig,
    domain: str,
    sans: list[str],
    key_type: str,
    emit: Emitter = _noop,
) -> IssueResult:
    """Full dns-01 flow for one certificate, equivalent to acme.sh --issue --dns dns_ali."""
    if not sans:
        raise ValueError("证书至少需要一个域名")
    emit("info", f"本次签发的域名（{len(sans)} 个）：{', '.join(sans)}")

    directory = get_directory(config.directory_url)
    client_v2 = build_client(directory, account_key)
    register_account(client_v2, account_key, config, emit)

    key = certstore.generate_key(key_type)
    csr = certstore.create_csr(key, sans)
    emit("info", f"已生成本地私钥与 CSR（{key_type}）")

    record_ids: list[str] = []
    try:
        try:
            orderr = client_v2.new_order(csr)
        except messages.Error as exc:
            raise IssuerError(acme_error_text(exc)) from exc
        emit(
            "info",
            f"CA 已受理订单（状态 {orderr.body.status}），需要验证 {len(orderr.authorizations)} 个标识符",
        )

        _present_dns01(dns, client_v2, account_key, domain, orderr, config, record_ids, emit)

        deadline = datetime.datetime.now() + datetime.timedelta(seconds=POLL_DEADLINE_SECONDS)
        try:
            client_v2.poll_authorizations(orderr, deadline)
            emit("info", "CA 校验通过，所有域名均已验证")
            finalized = client_v2.finalize_order(orderr, deadline)
        except (messages.Error, acme_errors.Error) as exc:
            raise IssuerError(acme_error_text(exc)) from exc
    finally:
        _cleanup_txt(dns, record_ids, emit)

    fullchain = finalized.fullchain_pem or ""
    certificate = certstore.load_certificate(fullchain)
    not_before, not_after = certstore.validity(certificate)
    emit(
        "info",
        f"证书签发成功，到期时间 {not_after.astimezone().isoformat(timespec='minutes')}，"
        f"指纹 {certstore.fingerprint(certificate)[:16]}…",
    )
    return IssueResult(
        fullchain_pem=fullchain,
        privkey_pem=certstore.key_pem(key),
        not_before=not_before,
        not_after=not_after,
        serial=certstore.serial(certificate),
        order_uri=finalized.uri or "",
        names=sans,
    )


def _present_dns01(
    dns: alidns.AliDns,
    client_v2: acme_client.ClientV2,
    account_key: JWK,
    domain: str,
    orderr: messages.OrderResource,
    config: IssuerConfig,
    record_ids: list[str],
    emit: Emitter,
) -> None:
    """Add every TXT record, wait until it is visible, then answer all challenges."""
    checker = alidns.PropagationChecker(timeout=config.propagation_timeout)
    answers: list[tuple[messages.ChallengeBody, str, object]] = []

    for authzr in orderr.authorizations:
        identifier = (authzr.body.identifier.value or "").lower().rstrip(".")
        base = identifier[2:] if identifier.startswith("*.") else identifier
        challenge_body = next(
            (item for item in authzr.body.challenges if isinstance(item.chall, challenges.DNS01)), None
        )
        if challenge_body is None:
            raise IssuerError(f"CA 没有为 {identifier} 提供 dns-01 验证方式")

        txt_name = challenge_body.chall.validation_domain_name(base)
        txt_value = challenge_body.chall.validation(account_key)
        rr = names.fqdn_to_rr(domain, txt_name)
        answers.append((challenge_body, txt_name, challenge_body.chall.response(account_key)))

        emit("info", f"在 {domain} 添加 TXT 记录：{rr} = {txt_value}")
        record_ids.extend(dns.upsert_txt(domain, rr, txt_value))
        ok, detail = checker.wait(txt_name, txt_value)
        if not ok:
            raise IssuerError(f"TXT 记录迟迟没有生效：{detail}")
        emit("info", detail)

    for challenge_body, txt_name, response in answers:
        client_v2.answer_challenge(challenge_body, response)  # type: ignore[arg-type]
        emit("info", f"已提交 {txt_name} 的验证响应")


def _cleanup_txt(dns: alidns.AliDns, record_ids: list[str], emit: Emitter) -> None:
    if not record_ids:
        return
    try:
        emit("info", f"已清理 {dns.delete_records(record_ids)} 条 _acme-challenge TXT 记录")
    except alidns.AliDnsError as exc:
        emit("warn", f"TXT 记录清理失败，请到阿里云解析手动删除：{exc}")


def revoke_certificate(
    account_key: JWK, config: IssuerConfig, cert_pem: bytes, reason: str = "superseded"
) -> None:
    client_v2 = build_client(get_directory(config.directory_url), account_key)
    register_account(client_v2, account_key, config)
    try:
        client_v2.revoke(certstore.load_certificate(cert_pem), REVOKE_REASONS.get(reason, 0))
    except (messages.Error, acme_errors.Error) as exc:
        raise IssuerError(acme_error_text(exc)) from exc


def test_account_connection(config: IssuerConfig, account_key: JWK, emit: Emitter = _noop) -> str:
    """Settings-page probe: proves the CA is reachable and the account key works."""
    client_v2 = build_client(get_directory(config.directory_url), account_key)
    regr = register_account(client_v2, account_key, config, emit)
    text = f"CA 可达，账号 URI：{regr.uri}"
    if client_v2.external_account_required():
        text += "（该 CA 要求 EAB，请在凭证里填写 kid 与 HMAC key）"
    return text


_BUSY_MARKERS = ("service busy", "serverinternal", "temporarily unavailable", "try again later")


def acme_error_text(exc: Exception) -> str:
    typ = str(getattr(exc, "typ", "") or "").lower()
    detail = str(getattr(exc, "detail", "") or "") or str(exc)
    haystack = f"{typ} {detail}".lower()
    # Boulder reports its own overload as rateLimited/"Service busy", which is not a quota problem.
    if any(marker in haystack for marker in _BUSY_MARKERS):
        return (
            f"CA 服务暂时不可用：{detail}。这是 CA 侧的临时过载限流，不是你的域名额度用尽"
            f"（全新账号申请不相干域名也会返回同样的话）。过几分钟点「重新申请」即可；"
            f"Staging 集群容量比生产小，更容易遇到。"
        )
    for key, hint in _ERROR_HINTS.items():
        if key in typ or key in detail.lower():
            return f"CA 错误：{detail}｜{hint}"
    return f"CA 错误：{detail}"
