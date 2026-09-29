"""Generate the shared, self-signed TLS material used by the testbed.

The *entire point* of this fixture is a single signing artifact reused across
two logically distinct hosts (the hidden service and its clearnet staging
domain). In a real investigation that reused serial number is a 90%-weighted
infrastructure link, because a correctly-provisioned deployment never shares a
private key across unrelated namespaces.

Outputs into ``simulation/certs/``:
    shared.key   - RSA private key (both services present this)
    shared.crt   - self-signed leaf, CN=ops-stage-clearnet.internal
    server.crt/.key - leaf issued by shared.crt, presenting the same serial
"""

from __future__ import annotations

import datetime as dt
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERT_DIR = Path(__file__).resolve().parent / "certs"
SHARED_SERIAL = 0x2A4F19C7D3E8B605  # deliberately reused across both leaves


def _name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Northgate Hosting Ltd"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Infrastructure"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def generate() -> dict[str, Path]:
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    # Fixed validity window keeps fixtures byte-stable across regenerations.
    start = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    end = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = _name("Northgate Internal CA")
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(SHARED_SERIAL)
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    def _leaf(cn: str, alt_names: list) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        san_entries = []
        for entry in alt_names:
            if isinstance(entry, str) and entry.startswith("DNS:"):
                san_entries.append(x509.DNSName(entry[4:]))
            elif isinstance(entry, str) and entry.startswith("IP:"):
                san_entries.append(x509.IPAddress(ipaddress.ip_address(entry[3:])))
        cert = (
            x509.CertificateBuilder()
            .subject_name(_name(cn))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            # Same serial as the CA itself: the deliberate misconfiguration.
            .serial_number(SHARED_SERIAL)
            .not_valid_before(start)
            .not_valid_after(end)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
            .add_extension(
                x509.AuthorityInformationAccess([
                    x509.AccessDescription(
                        x509.AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier("http://ocsp.northgate.internal/"),
                    )
                ]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        return key, cert

    def _write_key(path: Path, key) -> None:
        path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    def _write_cert(path: Path, cert) -> None:
        path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    # Clearnet staging host -- leaks internal naming.
    clearnet_key, clearnet_cert = _leaf(
        "ops-stage-clearnet.internal",
        [
            "DNS:ops-stage-clearnet.internal",
            "DNS:staging.northgate-hosting.example",
            "DNS:northgate-hosting.example",
            "DNS:admin.northgate-hosting.example",
            "IP:198.51.100.24",
        ],
    )

    # Hidden service presenting the SAME serial + SANs.
    onion_key, onion_cert = _leaf(
        "vmijjgu6ydy75cxmbj5p2ey42d7wsab6u4plz5m2kza3xkgqbnrsfktj.onion",
        [
            "DNS:vmijjgu6ydy75cxmbj5p2ey42d7wsab6u4plz5m2kza3xkgqbnrsfktj.onion",
            "DNS:ops-stage-clearnet.internal",
            "DNS:staging.northgate-hosting.example",
        ],
    )

    paths = {
        "ca_key": CERT_DIR / "shared.key",
        "ca_cert": CERT_DIR / "shared.crt",
        "clearnet_key": CERT_DIR / "server.key",
        "clearnet_cert": CERT_DIR / "server.crt",
        "onion_key": CERT_DIR / "onion.key",
        "onion_cert": CERT_DIR / "onion.crt",
    }
    _write_key(paths["ca_key"], ca_key)
    _write_cert(paths["ca_cert"], ca_cert)
    _write_key(paths["clearnet_key"], clearnet_key)
    _write_cert(paths["clearnet_cert"], clearnet_cert)
    _write_key(paths["onion_key"], onion_key)
    _write_cert(paths["onion_cert"], onion_cert)
    return paths


if __name__ == "__main__":
    for name, path in generate().items():
        print(f"{name:14s} -> {path}")
