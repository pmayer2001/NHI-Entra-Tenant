"""Self-signed certificates for app-only authentication (ADR-005, P7).

Entra only ever sees the *public* certificate (uploaded to the app registration's
keyCredentials). The private key stays in ~/.nhigov/certs/ and signs the client
assertion JWT locally, so no reusable secret is ever sent to or stored in Entra.

Output for a name like "nhigov-scanner":
  <dir>/nhigov-scanner.pem  private key + certificate (what azure-identity loads)
  <dir>/nhigov-scanner.cer  public certificate only (what you upload to Entra)
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

DEFAULT_CERT_DIR = Path("~/.nhigov/certs")
DEFAULT_LIFETIME_DAYS = 180  # matches the app management policy cap (CLAUDE.md §8)


@dataclass(frozen=True)
class GeneratedCert:
    private_pem: Path
    public_cer: Path
    thumbprint_sha1: str  # what the Entra portal displays
    not_after: datetime


def generate_self_signed(
    name: str,
    cert_dir: Path = DEFAULT_CERT_DIR,
    lifetime_days: int = DEFAULT_LIFETIME_DAYS,
    overwrite: bool = False,
) -> GeneratedCert:
    cert_dir = cert_dir.expanduser()
    cert_dir.mkdir(parents=True, exist_ok=True)
    private_pem = cert_dir / f"{name}.pem"
    public_cer = cert_dir / f"{name}.cer"
    if private_pem.exists() and not overwrite:
        raise FileExistsError(f"{private_pem} already exists; rotate instead of overwriting")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    not_after = now + timedelta(days=lifetime_days)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)  # self-signed: Entra pins this exact cert, no CA chain needed
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )

    key_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)

    private_pem.write_bytes(key_bytes + cert_bytes)
    os.chmod(private_pem, 0o600)  # best effort on Windows; the user profile ACL is the real guard
    public_cer.write_bytes(cert_bytes)

    return GeneratedCert(
        private_pem=private_pem,
        public_cer=public_cer,
        thumbprint_sha1=cert.fingerprint(hashes.SHA1()).hex().upper(),  # noqa: S303
        not_after=not_after,
    )
