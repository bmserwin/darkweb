"""Standalone leaf-certificate issuer for the simulation image.

This module mirrors ``backend/app/services/cert_issuer.py`` on purpose: the
backend and simulation images are built from separate Docker contexts, so they
cannot share an import. Keep the two in sync. Only the CA *certificate* is
needed here (no CA private key ships anywhere it is not required).

If the CA material is missing or anything fails, callers fall back to the
committed fixture leaves - this module never raises.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import os
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

UTC = dt.timezone.utc

#: Serial every fixture leaf carries; see infra_prober.EXPECTED_SHARED_SERIAL.
SHARED_SERIAL = 0x2A4F19C7D3E8B605

LEAF_TTL_DAYS = 3650
ORG = "Northgate Hosting Ltd"
OU = "Infrastructure"


def _cert_dir() -> Path:
    return Path(os.getenv("RENDER_CERT_DIR", "/app/certs"))


def _load_ca(cert_dir: Path) -> Optional[tuple[x509.Certificate, ec.EllipticCurvePrivateKey]]:
    cert_path, key_path = cert_dir / "shared.crt", cert_dir / "shared.key"
    if not (cert_path.is_file() and key_path.is_file()):
        return None
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        return cert, key
    except Exception:  # noqa: BLE001
        return None


def issue_leaf(
    common_name: str,
    san_hosts: list[str],
    *,
    cert_dir: Optional[Path] = None,
    cert_name: str = "leaf.crt",
    key_name: str = "leaf.key",
) -> Optional[tuple[Path, Path]]:
    """Mint one CA-signed leaf; ``None`` when the CA pair is unavailable."""
    base = cert_dir or _cert_dir()
    ca = _load_ca(base)
    if ca is None:
        return None
    ca_cert, ca_key = ca

    try:
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, OU),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name[:64]),
            ]
        )
        now = dt.datetime.now(UTC)
        names: list[x509.GeneralName] = []
        for host in dict.fromkeys([common_name, *san_hosts]):
            if not host:
                continue
            try:
                names.append(x509.IPAddress(ipaddress.ip_address(host)))
            except ValueError:
                names.append(x509.DNSName(host))

        leaf = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(SHARED_SERIAL)
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=LEAF_TTL_DAYS))
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )

        cert_path, key_path = base / cert_name, base / key_name
        cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        try:
            cert_path.chmod(0o644)
            key_path.chmod(0o600)
        except OSError:
            pass
        return cert_path, key_path
    except Exception:  # noqa: BLE001
        return None


def ensure_leaf_certificate(
    common_name: str,
    extra_sans: Optional[list[str]] = None,
    *,
    fallback_cert: str = "onion.crt",
    fallback_key: str = "onion.key",
) -> dict[str, str]:
    """Paths to a usable leaf pair, issuing a fresh one when the CA is present."""
    base = _cert_dir()
    issued = issue_leaf(common_name, extra_sans or [], cert_dir=base)
    if issued is not None:
        cert_path, key_path = issued
        return {"cert": str(cert_path), "key": str(key_path), "issued": "runtime"}
    return {
        "cert": str(base / fallback_cert),
        "key": str(base / fallback_key),
        "issued": "committed-fixture",
    }
