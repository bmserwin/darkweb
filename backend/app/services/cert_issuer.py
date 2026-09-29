"""Issue runtime TLS leaf certificates for the Render deployment.

On a PaaS there is no docker-compose-style `command:` override to point the
mock servers at freshly minted certificates, and Render terminates external
TLS at its edge with its own ``*.onrender.com`` certificate anyway. The
infrastructure prober still verifies endpoints against the committed fixture
CA, so the mock services need leaf certificates that:

* are signed by ``shared.crt`` / ``shared.key`` (the fixture CA),
* carry the fixture's shared serial (the prober's strongest signal),
* list their Render private hostname (``<service>.onrender.com`` and
  ``<service>-<hash>``, the name peer services actually dial) in the SAN,
* fall back to the committed fixture leaves when issuance is impossible.

Everything is best-effort: if the CA material or ``cryptography`` is missing,
:func:`ensure_leaf_certificate` returns the fallback paths and the service
starts with the committed certificates instead. The module never raises.
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

#: Serial every fixture leaf must carry; see ``infra_prober.EXPECTED_SHARED_SERIAL``.
SHARED_SERIAL = 0x2A4F19C7D3E8B605

#: How long a runtime leaf stays valid.
LEAF_TTL_DAYS = 3650

#: Human-readable subject bits shared with the committed fixtures.
ORG = "Northgate Hosting Ltd"
OU = "Infrastructure"


def _cert_dir() -> Path:
    return Path(os.getenv("RENDER_CERT_DIR", "/app/certs"))


def _load_ca(cert_dir: Path) -> Optional[tuple[x509.Certificate, ec.EllipticCurvePrivateKey]]:
    """Load the fixture CA pair, or ``None`` when unavailable."""
    cert_path, key_path = cert_dir / "shared.crt", cert_dir / "shared.key"
    if not (cert_path.is_file() and key_path.is_file()):
        return None
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        return cert, key
    except Exception:  # noqa: BLE001 - issuer must never break startup
        return None


def _write_pem(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    try:
        path.chmod(0o644 if path.suffix == ".crt" else 0o600)
    except OSError:
        pass


def issue_leaf(
    common_name: str,
    san_hosts: list[str],
    *,
    cert_dir: Optional[Path] = None,
    cert_name: str = "leaf.crt",
    key_name: str = "leaf.key",
) -> Optional[tuple[Path, Path]]:
    """Mint one CA-signed leaf; ``None`` when the CA is unavailable."""
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

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(SHARED_SERIAL)
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=LEAF_TTL_DAYS))
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        )
        leaf = builder.sign(ca_key, hashes.SHA256())

        cert_path, key_path = base / cert_name, base / key_name
        _write_pem(cert_path, leaf.public_bytes(serialization.Encoding.PEM))
        _write_pem(
            key_path,
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        return cert_path, key_path
    except Exception:  # noqa: BLE001 - issuance is best-effort by contract
        return None


def ensure_leaf_certificate(
    common_name: str,
    extra_sans: Optional[list[str]] = None,
    *,
    fallback_cert: str = "onion.crt",
    fallback_key: str = "onion.key",
) -> dict[str, str]:
    """Return ``{"cert": ..., "key": ...}`` paths, issuing a fresh leaf if possible.

    Falls back to the committed fixture pair when the CA is unavailable, the
    private key cannot be written, or issuance fails for any reason.
    """
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


__all__ = ["ensure_leaf_certificate", "issue_leaf", "SHARED_SERIAL"]
