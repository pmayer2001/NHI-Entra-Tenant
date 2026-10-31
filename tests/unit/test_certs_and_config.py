from __future__ import annotations

from pathlib import Path

import pytest
from cryptography import x509

from nhigov.certs import generate_self_signed
from nhigov.config import IdentityBackendKind, load_config


def test_generate_self_signed_writes_key_and_public_cert(tmp_path: Path) -> None:
    cert = generate_self_signed("nhigov-test", tmp_path, lifetime_days=30)
    pem = cert.private_pem.read_text()
    assert "PRIVATE KEY" in pem and "CERTIFICATE" in pem
    public = cert.public_cer.read_bytes()
    assert b"PRIVATE KEY" not in public
    parsed = x509.load_pem_x509_certificate(public)
    assert parsed.subject.rfc4514_string() == "CN=nhigov-test"
    assert len(cert.thumbprint_sha1) == 40


def test_generate_refuses_to_overwrite(tmp_path: Path) -> None:
    generate_self_signed("dup", tmp_path)
    with pytest.raises(FileExistsError):
        generate_self_signed("dup", tmp_path)


def test_load_config_env_overrides_file(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(
        """
tenant_id: file-tenant
control_plane:
  provisioner: {client_id: p, cert_path: ~/p.pem}
  scanner: {client_id: s, cert_path: ~/s.pem}
""",
        encoding="utf-8",
    )
    cfg = load_config(
        path, env={"NHIGOV_TENANT_ID": "env-tenant", "NHIGOV_IDENTITY_BACKEND": "agent_id"}
    )
    assert cfg.tenant_id == "env-tenant"
    assert cfg.identity_backend is IdentityBackendKind.AGENT_ID
    assert cfg.control_plane.scanner.resolved_cert_path() == Path.home() / "s.pem"


def test_load_config_from_env_only(tmp_path: Path) -> None:
    env = {
        "NHIGOV_TENANT_ID": "t",
        "NHIGOV_PROVISIONER_CLIENT_ID": "p",
        "NHIGOV_PROVISIONER_CERT_PATH": "p.pem",
        "NHIGOV_SCANNER_CLIENT_ID": "s",
        "NHIGOV_SCANNER_CERT_PATH": "s.pem",
    }
    cfg = load_config(tmp_path / "missing.yaml", env=env)
    assert cfg.identity_backend is IdentityBackendKind.SERVICE_PRINCIPAL
