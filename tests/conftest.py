"""Shared fixtures: an isolated data dir and a logged-in test client."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from app import config, db
from app.web import create_app

PASSWORD = "Test-password-123"


@pytest.fixture
def settings(tmp_path, monkeypatch):
    monkeypatch.setenv("ACME_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("ACME_MASTER_KEY", "unit-test-master-key-0123456789abcdef")
    loaded = config.load()
    db.init(loaded.db_path)
    return loaded


@pytest.fixture
def app(settings):
    return create_app(settings)


@pytest.fixture
def client(app):
    with TestClient(app) as instance:
        yield instance


@pytest.fixture
def authed(client):
    """Configure the admin password, log in, and return the client."""
    client.post("/setup", data={"password": PASSWORD, "password_confirm": PASSWORD})
    response = client.post("/login", data={"password": PASSWORD}, follow_redirects=False)
    assert response.status_code == 303, response.text
    return client


def csrf(client, path: str = "/domains") -> str:
    html = client.get(path).text
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, f"no csrf token on {path}: {html[:200]}"
    return match.group(1)


@pytest.fixture(scope="session")
def fake_fullchain() -> dict:
    """A real two-level PEM chain (root -> leaf) generated locally, for file/export tests."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    def name(text):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, text)])

    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    root = (
        x509.CertificateBuilder()
        .subject_name(name("Test Root CA"))
        .issuer_name(name("Test Root CA"))
        .public_key(root_key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(name("example.com"))
        .issuer_name(name("Test Root CA"))
        .public_key(leaf_key.public_key())
        .serial_number(12345)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=89))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("example.com"), x509.DNSName("*.example.com")]),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    def pem(cert):
        return cert.public_bytes(serialization.Encoding.PEM).decode()

    return {
        "fullchain": pem(leaf) + pem(root),
        "leaf_pem": pem(leaf),
        "root_pem": pem(root),
        "leaf_key": leaf_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ),
        "not_after": leaf.not_valid_after_utc,
        "not_before": leaf.not_valid_before_utc,
    }
