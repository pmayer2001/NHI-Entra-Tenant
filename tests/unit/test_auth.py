from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from azure.core.exceptions import ClientAuthenticationError

from nhigov.certs import generate_self_signed
from nhigov.config import ControlPlaneApp
from nhigov.graph.auth import CertificateTokenProvider, TokenAcquisitionError


def test_cert_not_uploaded_gives_actionable_error(tmp_path: Path) -> None:
    cert = generate_self_signed("nhigov-provisioner", tmp_path)
    provider = CertificateTokenProvider(
        "tenant",
        ControlPlaneApp(client_id="client", cert_path=cert.private_pem),
        "nhigov-provisioner",
    )
    provider._credential = MagicMock()
    provider._credential.get_token.side_effect = ClientAuthenticationError(
        message="Authentication failed: AADSTS700027: The certificate ... is not registered"
    )

    with pytest.raises(TokenAcquisitionError) as exc:
        provider()

    message = str(exc.value)
    assert "nhigov-provisioner" in message
    assert "AADSTS700027" in message
    assert "Upload the .cer" in message
    assert cert.thumbprint_sha1 in message
