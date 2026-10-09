"""Key/CSR generation, certificate files on disk, and PEM/PFX/DER export."""

from __future__ import annotations

import datetime
import pathlib
import re
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

KEY_TYPES: dict[str, str] = {
    "rsa2048": "RSA 2048（兼容最好）",
    "rsa4096": "RSA 4096（更慢）",
    "ec256": "ECDSA P-256（部分老客户端不支持）",
    "ec384": "ECDSA P-384",
}

FILE_NAMES = {
    "fullchain": "fullchain.pem",
    "cert": "cert.pem",
    "chain": "chain.pem",
    "key": "privkey.pem",
}

CERT_BLOCK_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)


def generate_key(key_type: str) -> PrivateKeyTypes:
    if key_type in ("rsa2048", "rsa4096"):
        return rsa.generate_private_key(public_exponent=65537, key_size=int(key_type[3:]))
    if key_type == "ec256":
        return ec.generate_private_key(ec.SECP256R1())
    if key_type == "ec384":
        return ec.generate_private_key(ec.SECP384R1())
    raise ValueError(f"不支持的密钥类型：{key_type}")


def key_pem(key: PrivateKeyTypes) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def create_csr(key: PrivateKeyTypes, names: Iterable[str]) -> bytes:
    ordered = sorted(set(names))
    if not ordered:
        raise ValueError("CSR 至少需要一个域名")
    common_name = next((name for name in ordered if not name.startswith("*.")), ordered[0])
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name[:64])])
    )
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(name) for name in ordered]), critical=False
    )
    algorithm = hashes.SHA256() if isinstance(key, rsa.RSAPrivateKey) else hashes.SHA384()
    csr = builder.sign(key, algorithm)
    return csr.public_bytes(serialization.Encoding.PEM)


def load_certificate(pem: bytes | str) -> x509.Certificate:
    raw = pem.encode("utf-8") if isinstance(pem, str) else pem
    return x509.load_pem_x509_certificate(raw)


def load_private_key(pem: bytes | str) -> PrivateKeyTypes:
    raw = pem.encode("utf-8") if isinstance(pem, str) else pem
    return serialization.load_pem_private_key(raw, password=None)


def split_pem_blocks(pem: str) -> list[str]:
    return [match.group(0).strip() for match in CERT_BLOCK_RE.finditer(pem or "")]


def chain_pem(fullchain: str) -> str:
    blocks = split_pem_blocks(fullchain)
    return "\n".join(blocks[1:]) + "\n" if len(blocks) > 1 else ""


def validity(cert: x509.Certificate) -> tuple[datetime.datetime, datetime.datetime]:
    return cert.not_valid_before_utc, cert.not_valid_after_utc


def serial(cert: x509.Certificate) -> str:
    return format(cert.serial_number, "X")


def fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def days_left(not_after: datetime.datetime, at: datetime.datetime | None = None) -> int:
    now = at or datetime.datetime.now(datetime.timezone.utc)
    reference = not_after if not_after.tzinfo else not_after.replace(tzinfo=datetime.timezone.utc)
    return (reference - now).days


def cert_path(cert_dir: pathlib.Path, certificate_id: int) -> pathlib.Path:
    return cert_dir / f"cert-{certificate_id}"


def save(cert_dir: pathlib.Path, certificate_id: int, privkey_pem: bytes, fullchain_pem: str) -> pathlib.Path:
    directory = cert_path(cert_dir, certificate_id)
    directory.mkdir(parents=True, exist_ok=True)
    blocks = split_pem_blocks(fullchain_pem)
    if not blocks:
        raise ValueError("CA 返回的内容里没有证书")
    payloads = {
        "fullchain": fullchain_pem.strip() + "\n",
        "cert": blocks[0] + "\n",
        "chain": (chain_pem(fullchain_pem) or ""),
        "key": privkey_pem.decode("utf-8"),
    }
    for kind, text in payloads.items():
        if not text:
            continue
        target = directory / FILE_NAMES[kind]
        target.write_text(text, encoding="utf-8", newline="\n")
        target.chmod(0o600)
    return directory


def read(directory: pathlib.Path, kind: str) -> bytes:
    if kind not in FILE_NAMES:
        raise ValueError(f"未知的下载类型：{kind}")
    target = directory / FILE_NAMES[kind]
    if not target.is_file():
        raise FileNotFoundError(f"文件还不存在：{FILE_NAMES[kind]}")
    return target.read_bytes()


def read_optional(directory: pathlib.Path, kind: str) -> bytes:
    target = directory / FILE_NAMES[kind]
    return target.read_bytes() if target.is_file() else b""


def as_der(directory: pathlib.Path) -> bytes:
    return load_certificate(read(directory, "cert")).public_bytes(serialization.Encoding.DER)


def as_pfx(directory: pathlib.Path, password: bytes) -> bytes:
    cert = load_certificate(read(directory, "cert"))
    key = load_private_key(read(directory, "key"))
    chain_raw = read_optional(directory, "chain")
    chain = [load_certificate(block) for block in split_pem_blocks(chain_raw.decode("utf-8"))]
    return pkcs12.serialize_key_and_certificates(
        name=b"certificate", key=key, cert=cert, cas=chain or None, encryption_algorithm=(
            serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
        )
    )


def parse_iso(raw: str) -> datetime.datetime | None:
    try:
        return datetime.datetime.fromisoformat(raw)
    except (TypeError, ValueError):
        return None
