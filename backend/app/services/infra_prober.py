"""Infrastructure-correlation probing over TLS.

Why this signal exists
----------------------
Content, wallet and timing evidence all answer "are these two personas the
same operator?". Infrastructure evidence answers a different and complementary
question: "were these two endpoints ever operated by the same deployment?".

The observation that makes the signal work is that TLS deployments leak far more
than they intend. A certificate carries a subject, an issuer, a serial number
and a set of Subject Alternative Names; a web server returns a ``Server:``
banner in every response. None of those are secrets, and in a misconfigured
deployment they are frequently *shared* between hosts that are supposed to be
unrelated. Reusing one private key across two namespaces is common in small
hosting shops and in staging estates that were cloned from production, so two
endpoints presenting the same certificate serial, or SANs that mention each
other's names, are strong evidence of common operation. This module collects
that evidence and groups it.

The fixture this ships with makes the point deliberately: the simulated hidden
service and the clearnet staging host present leaves issued by one self-signed
CA and share a single serial number, and both leak the internal name
``ops-stage-clearnet.internal``. Nothing about that is secret. It is simply
recorded.

Trust model
-----------
Verification is never disabled, not even for the self-signed fixture CA. The
fixture CA is self-signed *by design*, and that fact is itself the signal; it is
loaded as an explicit trust anchor (``shared.crt``) so the handshake completes
and the certificate contents can be parsed. No code path in this module passes
``verify=False`` or an equivalent ``CERT_NONE`` context, and the pinned serial
in :data:`EXPECTED_SHARED_SERIAL` documents what the fixture is asserting rather
than suppressing the assertion.

One consequence is worth stating plainly rather than working around. When the
handshake fails, the certificate fields come back empty, because OpenSSL and
CPython both tear the socket down before the peer certificate can be read back;
``getpeercert`` on a failed handshake raises rather than returning anything. The
open question in that case is answered by ``error.message``, which carries the
verifier's own reason ("Hostname mismatch", "unable to get local issuer
certificate"). Recovering the certificate anyway would mean a second,
trust-free handshake, and a trust-free handshake is exactly the thing this
module refuses to do: the answer to "what did this host present?" is never worth
a probe that would have accepted it. Such a probe is reported as an error, not
as a soft pass, so it cannot enter the correlation as evidence.

Offline guarantee
-----------------
The platform must never touch the public internet, so :func:`probe_target`
routes traffic itself instead of trusting ambient DNS. Only loopback literals,
the mock service names configured in ``settings``, and names reserved for local
or documentation use (``.onion``, ``.internal``, ``.example``, ``.invalid``,
``.test``, ``.localhost``) are permitted; every other host is refused with a
structured error and no socket is opened. Certificate names that resolve nowhere
are dialled on loopback, which is what a local Tor daemon or a testbed hosts
file would do, so the handshake can still be observed end to end.

Determinism
-----------
No randomness and no wall-clock read inside the classification or correlation
paths. Grouping iterates sorted keys, ``infra_score`` is computed from counts
only, and every emitted float is finite so ``json.dumps(..., allow_nan=False)``
cannot raise. :func:`probe_target` stamps an ``observed_at`` field because an
evidence record needs an acquisition time, but that field is provenance, not
input to any score, and it is the only part of a probe that varies between runs.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import math
import re
import socket
import threading
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence
from urllib.parse import urlsplit

import requests
import urllib3
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
from cryptography.x509.oid import ExtensionOID
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPSConnection
from urllib3.connectionpool import HTTPSConnectionPool

from ..config import PROJECT_ROOT, settings

__all__ = [
    "probe_target",
    "correlate",
    "analyse_certificate",
    "analyse_certificate_file",
    "certificate_authority_path",
    "certificate_corpus",
    "local_certificate_corpus",
    "classify_certificate",
    "EXPECTED_SHARED_SERIAL",
    "CA_CERT_NAME",
    "DEFAULT_MAX_BODY_BYTES",
]

#: Name of the fixture trust anchor inside the certificate directory.
CA_CERT_NAME = "shared.crt"

#: The serial the fixture reuses across the CA and both leaves. Recorded as a
#: constant so an examiner can see what the testbed asserts; the code itself
#: never treats it as a reason to trust anything.
EXPECTED_SHARED_SERIAL = 0x2A4F19C7D3E8B605

#: Bodies larger than this are hashed incrementally rather than buffered whole.
DEFAULT_MAX_BODY_BYTES = 1_048_576

#: Schemes the prober will dial.
ALLOWED_SCHEMES = frozenset({"http", "https"})

#: Suffixes reserved for documentation, private use or special use. None of them
#: can legitimately resolve on the public internet, so treating them as local is
#: both correct and the reason the module can never leak traffic off-box.
LOCAL_RESERVED_SUFFIXES = (
    ".onion",
    ".internal",
    ".example",
    ".invalid",
    ".test",
    ".localhost",
)

_USER_AGENT = "ForensicPlatform/1.0 (+infra-prober)"

_PEER_CERT_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Fixture PKI discovery
# ---------------------------------------------------------------------------


def _candidate_cert_dirs() -> list[Path]:
    """Return the candidate PKI directories, most specific first.

    The testbed keeps the PKI beside the mock services under ``simulation/``.
    Container images place the same directory at ``/app/simulation/certs``.
    """
    return [
        PROJECT_ROOT / "simulation" / "certs",
        PROJECT_ROOT / "backend" / "simulation" / "certs",
        Path("/app/simulation/certs"),
        Path("/app/certs"),
        Path("/simulation/certs"),
    ]


def certificate_directory() -> Optional[Path]:
    """Return the first candidate PKI directory that holds a CA, if any."""
    for candidate in _candidate_cert_dirs():
        if (candidate / CA_CERT_NAME).is_file():
            return candidate
    return None


def certificate_authority_path() -> Optional[Path]:
    """Return the path to the fixture CA bundle used as the trust anchor."""
    directory = certificate_directory()
    return None if directory is None else directory / CA_CERT_NAME


def _read_certificate(path: Path) -> Optional[x509.Certificate]:
    data = path.read_bytes()
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        pass
    try:
        return x509.load_der_x509_certificate(data)
    except ValueError:
        return None


def certificate_corpus(directory: Optional[Path] = None) -> list[tuple[str, x509.Certificate]]:
    """Load every certificate in the fixture PKI, sorted by file name."""
    target = directory if directory is not None else certificate_directory()
    if target is None or not target.is_dir():
        return []
    loaded: list[tuple[str, x509.Certificate]] = []
    for path in sorted(target.glob("*")):
        if path.suffix.lower() not in {".crt", ".pem", ".cer", ".der"}:
            continue
        certificate = _read_certificate(path)
        if certificate is not None:
            loaded.append((path.name, certificate))
    return loaded


def local_certificate_corpus(directory: Optional[Path] = None) -> list[tuple[str, x509.Certificate]]:
    """Alias of :func:`certificate_corpus` kept explicit at call sites."""
    return certificate_corpus(directory)


def _shared_serials(
    corpus: Sequence[tuple[str, x509.Certificate]],
) -> dict[str, int]:
    """Map serial hex to the number of distinct certificates carrying it.

    A serial present in more than one certificate is a reused serial, which is
    the misconfiguration the fixture encodes.
    """
    counts: dict[str, int] = defaultdict(int)
    seen: dict[str, set[str]] = defaultdict(set)
    for name, certificate in corpus:
        serial = f"{certificate.serial_number:032X}"
        seen[serial].add(certificate.fingerprint(hashes.SHA256()).hex())
        counts[serial] = len(seen[serial])
    return dict(counts)


# ---------------------------------------------------------------------------
# Certificate parsing
# ---------------------------------------------------------------------------


def _name_attributes(name: x509.Name) -> list[tuple[str, str]]:
    return [(attribute.oid._name, str(attribute.value)) for attribute in name]


def _name_map(name: x509.Name) -> dict[str, str]:
    """Return the last value seen for each distinguished-name attribute."""
    mapping: dict[str, str] = {}
    for oid_name, value in _name_attributes(name):
        mapping[oid_name] = value
    return mapping


def _public_key_summary(certificate: x509.Certificate) -> dict[str, Any]:
    key = certificate.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return {"algorithm": "rsa", "key_size": int(key.key_size), "curve": None}
    if isinstance(key, ec.EllipticCurvePublicKey):
        return {"algorithm": "ec", "key_size": int(key.key_size), "curve": key.curve.name}
    if isinstance(key, ed25519.Ed25519PublicKey):
        return {"algorithm": "ed25519", "key_size": 256, "curve": None}
    if isinstance(key, ed448.Ed448PublicKey):
        return {"algorithm": "ed448", "key_size": 448, "curve": None}
    return {"algorithm": type(key).__name__, "key_size": 0, "curve": None}


def _verify_self_signature(certificate: x509.Certificate) -> bool:
    """Check that the certificate's signature validates under its own key."""
    public_key = certificate.public_key()
    signature_hash = certificate.signature_hash_algorithm
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                signature_hash,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(signature_hash),
            )
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(
                certificate.signature, certificate.tbs_certificate_bytes
            )
        else:
            return False
    except Exception:
        return False
    return True


def _san_entries(certificate: x509.Certificate) -> tuple[list[str], list[str]]:
    """Return the DNS and IP Subject Alternative Names, sorted."""
    try:
        extension = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
    except x509.ExtensionNotFound:
        return [], []
    names = {str(name).lower() for name in extension.value.get_values_for_type(x509.DNSName)}
    addresses = sorted({str(address) for address in extension.value.get_values_for_type(x509.IPAddress)})
    return sorted(names), addresses


def _is_ca(certificate: x509.Certificate) -> bool:
    try:
        return bool(certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        return False


def classify_certificate(certificate: x509.Certificate) -> dict[str, Any]:
    """Reduce a parsed certificate to the facts the fusion engine consumes.

    Every value is derived from the DER structure through ``cryptography.x509``;
    nothing here pattern-matches on PEM text.
    """
    serial_hex = f"{certificate.serial_number:032X}"
    dns_names, ip_addresses = _san_entries(certificate)
    subject = _name_map(certificate.subject)
    issuer = _name_map(certificate.issuer)
    leaf_self_issued = certificate.subject == certificate.issuer
    self_signature_valid = _verify_self_signature(certificate)
    corpus = certificate_corpus()
    shared_counts = _shared_serials(corpus)

    return {
        "serial_number": int(certificate.serial_number),
        "serial_hex": serial_hex,
        "expected_fixture_serial": serial_hex == f"{EXPECTED_SHARED_SERIAL:032X}",
        "shared_cert_serial": bool(shared_counts.get(serial_hex, 0) >= 2),
        "known_serial_occurrences": int(shared_counts.get(serial_hex, 0)),
        "subject": _name_attributes(certificate.subject),
        "subject_map": subject,
        "issuer": _name_attributes(certificate.issuer),
        "issuer_map": issuer,
        "common_name": subject.get("commonName"),
        "issuer_common_name": issuer.get("commonName"),
        "organization": subject.get("organizationName"),
        "organizational_unit": subject.get("organizationalUnitName"),
        "country": subject.get("countryName"),
        "san_hosts": dns_names,
        "san_ips": ip_addresses,
        "self_signed": bool(leaf_self_issued and self_signature_valid),
        "leaf_self_issued": bool(leaf_self_issued),
        "issuer_is_local_authority": issuer.get("commonName") == "Northgate Internal CA",
        "is_ca": _is_ca(certificate),
        "version": int(certificate.version.value),
        "not_valid_before": certificate.not_valid_before_utc.isoformat(),
        "not_valid_after": certificate.not_valid_after_utc.isoformat(),
        "signature_hash": certificate.signature_hash_algorithm.name,
        "sha256_fingerprint": certificate.fingerprint(hashes.SHA256()).hex(),
        "sha1_fingerprint": certificate.fingerprint(hashes.SHA1()).hex(),
        "public_key": _public_key_summary(certificate),
        "ocsp_responders": _ocsp_responders(certificate),
    }


def _ocsp_responders(certificate: x509.Certificate) -> list[str]:
    try:
        extension = certificate.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )
    except x509.ExtensionNotFound:
        return []
    return sorted(
        {
            description.access_location.value
            for description in extension.value
            if isinstance(description.access_location, x509.UniformResourceIdentifier)
        }
    )


def analyse_certificate(data: bytes | str) -> dict[str, Any]:
    """Parse DER or PEM certificate bytes into classified evidence.

    Accepts ``bytes`` (PEM or DER) or ``str`` (PEM). Raises ``ValueError`` for
    data that is not a certificate, so callers decide how to record the failure.
    """
    if isinstance(data, str):
        payload = data.encode("utf-8")
    else:
        payload = bytes(data)
    try:
        certificate = x509.load_pem_x509_certificate(payload)
    except ValueError:
        certificate = x509.load_der_x509_certificate(payload)
    return classify_certificate(certificate)


def analyse_certificate_file(path: str | Path) -> dict[str, Any]:
    """Parse the certificate at ``path`` into classified evidence."""
    return analyse_certificate(Path(path).read_bytes())


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------


class _PeerCertCollector(threading.local):
    """Thread-local holding the DER of the most recent peer certificate."""

    der: Optional[bytes] = None
    error: Optional[str] = None


_PEER = _PeerCertCollector()


class _Route(threading.local):
    """Thread-local routing decision for the request about to be sent.

    ``dial_host`` is the address the socket connects to; ``verification_hostname``
    is the name the certificate must be valid for. They differ when a lab name
    has to be dialled on loopback, which is the case that matters for offline
    reproducibility.
    """

    dial_host: Optional[str] = None
    verification_hostname: Optional[str] = None


_ROUTE = _Route()


class _RoutedHTTPSConnection(HTTPSConnection):
    """HTTPS connection that can dial one address and verify against another.

    urllib3 already separates the two: ``_dns_host`` is used for the TCP
    connection while ``server_hostname`` drives SNI and ``assert_hostname``
    drives certificate name matching. This subclass fills in both, so a
    certificate that only names the lab host still verifies while the socket
    goes to loopback. It also records the peer certificate, because ``requests``
    returns the connection to the pool as soon as the body is read and the
    socket carrying the certificate is closed by then.
    """

    def connect(self) -> None:
        if _ROUTE.dial_host:
            self._dns_host = _ROUTE.dial_host
        if _ROUTE.verification_hostname:
            self.server_hostname = _ROUTE.verification_hostname
            self.assert_hostname = _ROUTE.verification_hostname
        try:
            super().connect()
        finally:
            self._capture_peer_certificate()

    def _capture_peer_certificate(self) -> None:
        sock = getattr(self, "sock", None)
        if sock is None:
            with _PEER_CERT_LOCK:
                _PEER.der = None
                _PEER.error = "no-socket"
            return
        try:
            der = sock.getpeercert(binary_form=True)
        except Exception as exc:  # noqa: BLE001 - reported, never raised
            with _PEER_CERT_LOCK:
                _PEER.der = None
                _PEER.error = type(exc).__name__
            return
        with _PEER_CERT_LOCK:
            _PEER.der = der
            _PEER.error = None


class _RoutedHTTPSPool(HTTPSConnectionPool):
    ConnectionCls = _RoutedHTTPSConnection


class _EvidenceAdapter(HTTPAdapter):
    """Adapter that installs the routing/capturing connection class.

    Routing state is carried in a thread-local rather than on the adapter so a
    single adapter can serve concurrent probes with different routes.
    """

    def __init__(self, *, dial_host: Optional[str] = None, verification_hostname: Optional[str] = None) -> None:
        super().__init__()
        self._dial_host = dial_host
        self._verification_hostname = verification_hostname

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):  # type: ignore[override]
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)
        self.poolmanager.pool_classes_by_scheme["https"] = _RoutedHTTPSPool

    def send(self, request, **kwargs):  # type: ignore[override]
        with _PEER_CERT_LOCK:
            _PEER.der = None
            _PEER.error = None
        _ROUTE.dial_host = self._dial_host
        _ROUTE.verification_hostname = self._verification_hostname
        try:
            return super().send(request, **kwargs)
        finally:
            _ROUTE.dial_host = None
            _ROUTE.verification_hostname = None


def _observed_host(url: str) -> str:
    """Return the name a real resolver would be asked for."""
    host = urlsplit(url).hostname or ""
    return host.rstrip(".").lower()


def _service_host(base_url: str) -> str:
    try:
        host = urlsplit(base_url).hostname or ""
    except ValueError:
        return ""
    return host.rstrip(".").lower()


def _is_loopback(host: str) -> bool:
    if host in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _resolves(host: str, port: int) -> bool:
    try:
        socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError:
        return False
    return True


def certificate_names(directory: Optional[Path] = None) -> set[str]:
    """Collect every DNS name and CN present in the fixture PKI."""
    names: set[str] = set()
    for _, certificate in certificate_corpus(directory):
        dns_names, _ = _san_entries(certificate)
        names.update(dns_names)
        common_name = _name_map(certificate.subject).get("commonName")
        if common_name:
            names.add(common_name.lower())
    return names


def route_plan(host: str, port: int, directory: Optional[Path] = None) -> dict[str, Any]:
    """Decide how to reach ``host`` without ever leaving the local machine.

    Returns a plan with an ``allowed`` flag. When the host cannot be refused it
    carries ``dial_host`` (the address to connect to) and ``server_hostname``
    (the name used for SNI and for certificate hostname verification), which
    together let a request reach a mock host under its real certificate name.
    """
    service_hosts = {
        _service_host(settings.mock_onion_base_url),
        _service_host(settings.mock_clearnet_base_url),
    }
    service_hosts.discard("")

    lab_names = certificate_names(directory)
    plan: dict[str, Any] = {
        "host": host,
        "port": port,
        "allowed": False,
        "reason": "",
        "dial_host": host,
        "server_hostname": host,
        "lab_resolved": False,
    }

    if host in service_hosts or _is_loopback(host):
        plan["allowed"] = True
        plan["reason"] = "loopback" if _is_loopback(host) else "configured-mock-service"
        if not _resolves(host, port):
            plan["dial_host"] = "127.0.0.1"
            plan["lab_resolved"] = True
            plan["reason"] += "+dialed-on-loopback"
        return plan

    reserved = host.endswith(LOCAL_RESERVED_SUFFIXES)
    if not reserved and host not in lab_names:
        plan["reason"] = "host-not-in-offline-allowlist"
        return plan

    plan["allowed"] = True
    plan["reason"] = "reserved-lab-suffix" if reserved else "fixture-certificate-name"
    if _resolves(host, port):
        plan["dial_host"] = host
    else:
        plan["dial_host"] = "127.0.0.1"
        plan["lab_resolved"] = True
    return plan


#: One DNS label: alphanumeric ends, hyphens allowed inside.
_HOST_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def _is_wellformed_host(host: str) -> bool:
    """Reject strings that could never be a host before any routing happens.

    Without this, free text such as ``"not a url"`` is prepended with a scheme
    and lands in the allowlist check, where it is refused for the wrong reason.
    Distinguishing "this is not a URL" from "this URL is not one we may contact"
    matters to a case file, because the first is a caller bug and the second is
    an evidence-handling decision.
    """
    if not host or len(host) > 253:
        return False
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        pass
    labels = host.split(".")
    if any(not label for label in labels):
        return False
    return all(_HOST_LABEL.match(label) for label in labels)


# ---------------------------------------------------------------------------
# JSON hygiene
# ---------------------------------------------------------------------------


def _json_safe(value: Any) -> Any:
    """Return ``value`` with every non-finite float and exotic type removed.

    Guards ``json.dumps(..., allow_nan=False)`` against NaN, infinities and any
    object that slipped through from a third-party library.
    """
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(item) for item in value]
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (dt.datetime, dt.date)):
        return value.isoformat()
    return str(value)


def _round(value: float, places: int = 6) -> float:
    """Round for serialisation, collapsing -0.0 and non-finite values to 0.0."""
    if not math.isfinite(value):
        return 0.0
    rounded = round(float(value), places)
    return 0.0 if rounded == 0 else rounded


# ---------------------------------------------------------------------------
# Probing
# ---------------------------------------------------------------------------

_ERROR_TAXONOMY: tuple[tuple[str, tuple[type[BaseException], ...]], ...] = (
    ("tls-verification-failed", (requests.exceptions.SSLError,)),
    ("tls-error", (urllib3.exceptions.SSLError,)),
    ("timeout", (requests.exceptions.Timeout, urllib3.exceptions.TimeoutError, socket.timeout)),
    ("connection-failed", (requests.exceptions.ConnectionError, urllib3.exceptions.HTTPError)),
    ("too-many-redirects", (requests.exceptions.TooManyRedirects,)),
    ("request-failed", (requests.exceptions.RequestException,)),
    ("dns-failure", (socket.gaierror, OSError)),
)


def _classify_exception(exc: BaseException) -> str:
    for code, types in _ERROR_TAXONOMY:
        if isinstance(exc, types):
            return code
    return "unexpected-error"


def _normalise_url(url: Any) -> str:
    if not isinstance(url, str):
        raise ValueError("url must be a string")
    candidate = url.strip()
    if not candidate:
        raise ValueError("url must not be empty")
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    return candidate


def _http_probe(
    session: requests.Session,
    url: str,
    *,
    verify: Any,
    timeout: float,
    max_body_bytes: int,
) -> tuple[Optional[requests.Response], dict[str, Any]]:
    """Perform the request and return the response plus the evidence fields."""
    response = session.get(
        url,
        verify=verify,
        timeout=timeout,
        allow_redirects=True,
        stream=True,
        headers={"User-Agent": _USER_AGENT, "Accept": "*/*"},
    )
    digest = hashlib.sha256()
    body_bytes = 0
    truncated = False
    try:
        for chunk in response.iter_content(chunk_size=65536):
            if not chunk:
                continue
            body_bytes += len(chunk)
            if body_bytes > max_body_bytes:
                truncated = True
                break
            digest.update(chunk)
    finally:
        response.close()
    return response, {
        "content_sha256": digest.hexdigest(),
        "body_bytes": body_bytes,
        "body_truncated": truncated,
    }


def probe_target(url: str, *, timeout: float = 5.0) -> dict[str, Any]:
    """Probe one endpoint over TLS and return classified evidence.

    The returned mapping always has the same shape whether the probe succeeded
    or failed, so a batch of probes can be correlated without any caller-side
    branching. Failure modes are reported through ``status`` and ``error``; no
    ``requests`` exception escapes this function.

    ``verify`` is always the explicit fixture CA bundle. The self-signed nature
    of that bundle is a property of the testbed, not a reason to skip
    verification, so no code path here disables it.
    """
    observed_at = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        normalised = _normalise_url(url)
        parts = urlsplit(normalised)
    except ValueError as exc:
        return _failed_probe(url, "invalid-url", type(exc).__name__, str(exc), observed_at)

    scheme = (parts.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        return _failed_probe(
            normalised,
            "unsupported-scheme",
            "ValueError",
            f"scheme {scheme!r} is not one of {sorted(ALLOWED_SCHEMES)}",
            observed_at,
        )

    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        return _failed_probe(
            normalised, "invalid-url", "ValueError", "url has no host", observed_at
        )
    if not _is_wellformed_host(host):
        return _failed_probe(
            normalised,
            "invalid-url",
            "ValueError",
            f"{host!r} is not a valid host name or IP literal",
            observed_at,
            host=host,
            port=0,
            scheme=scheme,
        )
    try:
        port = parts.port
    except ValueError as exc:
        return _failed_probe(normalised, "invalid-url", type(exc).__name__, str(exc), observed_at)
    port = port or (443 if scheme == "https" else 80)

    if not settings.allow_network_probes:
        return _failed_probe(
            normalised,
            "probes-disabled",
            "RuntimeError",
            "settings.allow_network_probes is disabled",
            observed_at,
        )

    plan = route_plan(host, port)
    if not plan["allowed"]:
        return _failed_probe(
            normalised,
            "host-not-allowed",
            "PermissionError",
            plan["reason"],
            observed_at,
            host=host,
            port=port,
            scheme=scheme,
        )

    verify = certificate_authority_path()

    result: dict[str, Any] = _probe_skeleton(
        normalised, host, port, scheme, observed_at, plan, verify
    )

    if verify is None:
        result["status"] = "error"
        result["error"] = {
            "code": "ca-bundle-missing",
            "type": "FileNotFoundError",
            "message": (
                f"CA bundle {CA_CERT_NAME} not found in any known certificate "
                f"directory; looked in {[str(p) for p in _candidate_cert_dirs()]}"
            ),
        }
        return result

    # The URL keeps the observed hostname so the Host header, SNI and
    # certificate name matching all reflect the target under investigation.
    # Only the TCP dial address is redirected, and only when the plan says so.
    session = requests.Session()
    session.trust_env = False
    adapter = _EvidenceAdapter(
        dial_host=plan["dial_host"] if plan["dial_host"] != host else None,
        verification_hostname=host,
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    try:
        response, body_evidence = _http_probe(
            session,
            normalised,
            verify=str(verify),
            timeout=timeout,
            max_body_bytes=DEFAULT_MAX_BODY_BYTES,
        )
    except Exception as exc:  # noqa: BLE001 - probes must never raise at the caller
        with _PEER_CERT_LOCK:
            der = _PEER.der
        certificate_evidence = _certificate_evidence(der)
        result.update(_classification_facts(certificate_evidence))
        result["status"] = "error"
        result["error"] = {
            "code": _classify_exception(exc),
            "type": type(exc).__name__,
            "message": str(exc),
        }
        return result
    finally:
        session.close()

    assert response is not None
    with _PEER_CERT_LOCK:
        der = _PEER.der

    headers = {key.lower(): value for key, value in response.headers.items()}
    result["http"] = {
        "status_code": int(response.status_code),
        "reason": str(response.reason or ""),
        "final_url": str(response.url),
        "redirect_count": len(response.history),
        "headers": headers,
        "server_banner": headers.get("server"),
        "powered_by": headers.get("x-powered-by"),
        "via": headers.get("via"),
        "content_type": headers.get("content-type"),
        "declared_content_length": _int_or_none(headers.get("content-length")),
        **body_evidence,
    }
    certificate_evidence = _certificate_evidence(der)
    result["certificate"] = certificate_evidence
    result["status"] = "ok" if certificate_evidence or scheme == "http" else "error"
    if result["status"] == "error":
        result["error"] = {
            "code": "tls-certificate-unavailable",
            "type": "ValueError",
            "message": "no peer certificate was captured for this connection",
        }
    result.update(_classification_facts(certificate_evidence, headers))
    return result


def _int_or_none(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _probe_skeleton(
    url: str,
    host: str,
    port: int,
    scheme: str,
    observed_at: str,
    plan: Mapping[str, Any],
    verify: Optional[Path],
) -> dict[str, Any]:
    return {
        "url": url,
        "scheme": scheme,
        "host": host,
        "port": int(port),
        "status": "error",
        "error": None,
        "observed_at": observed_at,
        "transport": {
            "dial_host": plan["dial_host"],
            "server_hostname": plan["server_hostname"],
            "lab_resolved": plan["lab_resolved"],
            "route_reason": plan["reason"],
        },
        "trust": {
            "ca_bundle": None if verify is None else str(verify),
            "verification": "required",
        },
        "certificate": None,
        "http": None,
        "tls_valid": False,
        "self_signed": False,
        "banner": None,
        "shared_cert_serial": False,
        "hosting_asn_hint": None,
        "san_hosts": [],
    }


def _failed_probe(
    url: Any,
    code: str,
    exc_type: str,
    message: str,
    observed_at: str,
    *,
    host: str = "",
    port: int = 0,
    scheme: str = "",
) -> dict[str, Any]:
    return {
        "url": url if isinstance(url, str) else repr(url),
        "scheme": scheme,
        "host": host,
        "port": int(port),
        "status": "error",
        "error": {"code": code, "type": exc_type, "message": message},
        "observed_at": observed_at,
        "transport": None,
        "trust": {"ca_bundle": None, "verification": "required"},
        "certificate": None,
        "http": None,
        "tls_valid": False,
        "self_signed": False,
        "banner": None,
        "shared_cert_serial": False,
        "hosting_asn_hint": None,
        "san_hosts": [],
    }


def _certificate_evidence(der: Optional[bytes]) -> Optional[dict[str, Any]]:
    """Parse captured DER into evidence, or return ``None`` when absent."""
    if not der:
        return None
    try:
        return analyse_certificate(der)
    except Exception:  # noqa: BLE001 - unparsable peer material is evidence too
        return {
            "parse_error": True,
            "sha256": hashlib.sha256(der).hexdigest(),
            "byte_length": len(der),
        }


def _hosting_hint(certificate: Optional[Mapping[str, Any]]) -> Optional[str]:
    """Build the offline hosting hint from certificate naming fields.

    The certificate chain here is trusted, not authoritative: it is evidence of
    what the operator asserted, which is exactly what an infrastructure
    correlation wants. The hint records where the assertion came from.
    """
    if not certificate:
        return None
    organisation = certificate.get("organization")
    unit = certificate.get("organizational_unit")
    country = certificate.get("country")
    issuer_cn = certificate.get("issuer_common_name")
    parts = [str(part) for part in (organisation, unit, country) if part]
    if not parts:
        return None
    return {"value": " / ".join(parts), "issuer": issuer_cn, "source": "certificate-subject"}


def _classification_facts(
    certificate: Optional[Mapping[str, Any]],
    headers: Optional[Mapping[str, str]] = None,
) -> dict[str, Any]:
    """Derive the six classified infrastructure facts."""
    certificate = certificate or {}
    banner = None
    if headers:
        banner = headers.get("server") or headers.get("x-powered-by")
    return {
        "tls_valid": bool(certificate) and bool(certificate.get("parse_error") is not True),
        "self_signed": bool(certificate.get("self_signed", False)),
        "banner": banner,
        "shared_cert_serial": bool(certificate.get("shared_cert_serial", False)),
        "hosting_asn_hint": _hosting_hint(certificate),
        "san_hosts": list(certificate.get("san_hosts", [])),
    }


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------

#: How much each kind of shared artefact is worth on its own. A shared serial is
#: the strongest artefact because it implies a shared private key; a shared
#: banner is the weakest because reverse proxies and hosting panels emit the
#: same string across thousands of unrelated sites.
_EVIDENCE_WEIGHTS = {
    "cert_serial": 0.60,
    "san": 0.25,
    "banner": 0.15,
}

#: How far below the base weight a group falls as it spreads. One shared serial
#: means one deployment; a serial shared by many hosts means a hosting panel
#: that stamped the same certificate everywhere. The decay is gentle on purpose,
#: because breadth and coverage are already rewarded separately and a strong
#: penalty here would understate a genuinely unified estate.
_GROUP_SPREAD_DECAY = 0.2


def _group_weight(kind: str, size: int) -> float:
    base = _EVIDENCE_WEIGHTS[kind]
    spread = max(0, size - 1)
    return base / (1.0 + _GROUP_SPREAD_DECAY * spread)


def _probe_identity(probe: Mapping[str, Any], index: int) -> dict[str, Any]:
    """Normalise one probe dict into the fields correlation consumes.

    Callers may hand in raw :func:`probe_target` output, a subset of it, or a
    hand-written fixture with the same key names, so every field is read
    defensively and coerced rather than trusted.
    """
    http = probe.get("http") if isinstance(probe.get("http"), Mapping) else {}
    certificate = (
        probe.get("certificate")
        if isinstance(probe.get("certificate"), Mapping)
        else {}
    )
    headers = http.get("headers") if isinstance(http.get("headers"), Mapping) else {}

    banner = probe.get("banner") or http.get("server_banner") or headers.get("server")
    san_hosts = probe.get("san_hosts")
    if not san_hosts:
        san_hosts = certificate.get("san_hosts")
    serial_hex = certificate.get("serial_hex")
    if not serial_hex:
        serial_hex = probe.get("serial_hex")

    return {
        "index": int(index),
        "label": str(probe.get("probe_id") or probe.get("url") or f"probe-{index:04d}"),
        "url": str(probe.get("url", "")),
        "status": str(probe.get("status", "unknown")),
        "error": probe.get("error") if isinstance(probe.get("error"), Mapping) else None,
        "cert_serial": str(serial_hex) if serial_hex else None,
        "san_hosts": sorted({str(name).lower() for name in (san_hosts or []) if name}),
        "banner": str(banner) if banner else None,
        "tls_valid": bool(probe.get("tls_valid", False)),
        "self_signed": bool(probe.get("self_signed", False)),
    }


def _assign_probe_ids(identities: Sequence[dict[str, Any]]) -> None:
    """Give every probe a unique id, in place.

    Ids are per input position rather than per URL, because probing the same URL
    more than once is normal work rather than a mistake: a re-probe after a
    certificate change, a second virtual host on the same address, or the same
    endpoint collected from two cases. Keying on the URL would silently merge
    those into a single subject and understate the linkage, so uniqueness wins
    over prettiness and the human-readable label is carried alongside.
    """
    used: set[str] = set()
    for identity in identities:
        index = identity["index"]
        candidate = f"probe-{index:04d}"
        if candidate in used:
            candidate = f"{identity['label']}#{index}"
        used.add(candidate)
        identity["probe_id"] = candidate


def _build_groups(
    identities: Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, list[str]]]:
    """Bucket probe identities by each shared-artefact class."""
    buckets: dict[str, dict[str, list[str]]] = {
        "cert_serial": defaultdict(list),
        "san": defaultdict(list),
        "banner": defaultdict(list),
    }
    for identity in identities:
        if identity["cert_serial"]:
            buckets["cert_serial"][identity["cert_serial"]].append(identity["probe_id"])
        for san in identity["san_hosts"]:
            buckets["san"][san].append(identity["probe_id"])
        if identity["banner"]:
            buckets["banner"][identity["banner"]].append(identity["probe_id"])
    return {kind: dict(sorted(members.items())) for kind, members in buckets.items()}


def _link_strength(
    left: Mapping[str, Any], right: Mapping[str, Any], groups: Mapping[str, Mapping[str, list[str]]]
) -> dict[str, Any]:
    """Explain why two probes are linked and how strong the link is."""
    reasons: list[str] = []
    weight = 0.0
    for kind in ("cert_serial", "san", "banner"):
        for value, members in groups[kind].items():
            if left["probe_id"] in members and right["probe_id"] in members:
                reasons.append(kind)
                weight += _group_weight(kind, len(members))
                if kind == "cert_serial":
                    reasons.append(f"cert_serial={value}")
                elif kind == "san":
                    reasons.append(f"san={value}")
                else:
                    reasons.append(f"banner={value}")
                break
    return {
        "a": left["probe_id"],
        "b": right["probe_id"],
        "linked": bool(reasons),
        "strength": _round(weight),
        "reasons": reasons,
    }


def correlate(probes: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Group probe evidence by shared certificate serial, SAN and banner.

    Tolerant by construction: failed probes, missing keys, empty input and
    non-mapping items are all handled, and only successful probes contribute
    artefacts. Output is a pure function of the input list, so identical inputs
    produce byte-identical JSON, and every float is finite.
    """
    items = [item for item in (probes or []) if isinstance(item, Mapping)]
    identities = [_probe_identity(item, index) for index, item in enumerate(items)]
    _assign_probe_ids(identities)
    usable = [identity for identity in identities if identity["status"] == "ok"]

    groups = _build_groups(usable)
    linked_groups: list[dict[str, Any]] = []
    for kind, buckets in groups.items():
        for value, members in buckets.items():
            if len(members) < 2:
                continue
            linked_groups.append(
                {
                    "group_id": f"{kind}:{value}",
                    "kind": kind,
                    "value": value,
                    "members": sorted(members),
                    "size": len(members),
                    "weight": _round(_group_weight(kind, len(members))),
                }
            )

    by_id = {identity["probe_id"]: identity for identity in usable}
    links: list[dict[str, Any]] = []
    if len(by_id) > 1:
        ordered = [by_id[key] for key in sorted(by_id)]
        for i, left in enumerate(ordered):
            for right in ordered[i + 1 :]:
                links.append(_link_strength(left, right, groups))
    linked_links = [link for link in links if link["linked"]]

    clusters = _clusters(usable, groups)
    infra_score = _infra_score(linked_links, clusters, len(usable))

    return {
        "probe_count": len(identities),
        "usable_probe_count": len(usable),
        "failed_probe_count": len(identities) - len(usable),
        "probes": [
            {
                "probe_id": identity["probe_id"],
                "label": identity["label"],
                "url": identity["url"],
                "status": identity["status"],
                "error_code": (identity["error"] or {}).get("code")
                if identity["error"]
                else None,
                "cert_serial": identity["cert_serial"],
                "san_hosts": identity["san_hosts"],
                "banner": identity["banner"],
            }
            for identity in identities
        ],
        "groups": groups,
        "linked_groups": linked_groups,
        "links": links,
        "clusters": clusters,
        "link_count": len(linked_links),
        "infra_score": infra_score,
        "rationale": _rationale(linked_groups, clusters, infra_score),
        "evidence_note": (
            "Shared certificates, SANs and banners indicate a common deployment, "
            "not a proven common operator. Common banners in particular are weak "
            "evidence because hosting panels share them widely."
        ),
    }


def _clusters(
    identities: Sequence[Mapping[str, Any]],
    groups: Mapping[str, Mapping[str, list[str]]],
) -> list[dict[str, Any]]:
    """Union-find over shared artefacts, emitted in a deterministic order."""
    parent: dict[str, str] = {identity["probe_id"]: identity["probe_id"] for identity in identities}

    def find(node: str) -> str:
        root = node
        while parent[root] != root:
            root = parent[root]
        while parent[node] != root:
            parent[node], node = root, parent[node]
        return root

    def union(a: str, b: str) -> None:
        root_a, root_b = find(a), find(b)
        if root_a != root_b:
            parent[root_b] = root_a

    for kind in ("cert_serial", "san", "banner"):
        for members in groups[kind].values():
            for other in members[1:]:
                union(members[0], other)

    buckets: dict[str, list[str]] = defaultdict(list)
    for identity in identities:
        buckets[find(identity["probe_id"])].append(identity["probe_id"])

    clusters: list[dict[str, Any]] = []
    ordered = sorted(buckets.values(), key=sorted)
    for index, members in enumerate(ordered):
        if len(members) < 2:
            continue
        member_set = set(members)
        shared = sorted(
            f"{kind}:{value}"
            for kind, buckets_by_value in groups.items()
            for value, group_members in buckets_by_value.items()
            if len(member_set & set(group_members)) > 1
        )
        clusters.append(
            {
                "cluster_id": f"infra-cluster-{index:04d}",
                "members": sorted(members),
                "size": len(members),
                "shared_artefacts": shared,
            }
        )
    return clusters


def _infra_score(
    linked_links: Sequence[Mapping[str, Any]],
    clusters: Sequence[Mapping[str, Any]],
    usable_count: int,
) -> float:
    """Score in ``[0, 1]``: how much of the set shares infrastructure.

    Three parts, because they answer different questions and disagreeing is
    informative:

    ``strength``
        the single strongest pair, capped at 1.0. Caps matter more than they
        look: a pair can share a banner *and* a SAN, which adds up past the
        total evidence weight on its own, and an uncapped sum would then report
        a shared nginx string as near-certain common ownership.
    ``coverage``
        the share of probes in the *largest* cluster. Using the dominant
        cluster rather than "probes that are in some cluster" is the point:
        four probes split into two clean pairs are two deployments, not one
        four-wide estate, and the two cases must not score alike.
    ``breadth``
        the fraction of probe pairs that are linked at all.

    No wall-clock, no set iteration order and no unbounded term: identical
    inputs give an identical score.
    """
    if usable_count < 2 or not linked_links:
        return 0.0
    strongest = min(1.0, max(link["strength"] for link in linked_links))
    dominant = max((cluster["size"] for cluster in clusters), default=0)
    coverage = min(1.0, dominant / usable_count)
    possible_pairs = usable_count * (usable_count - 1) / 2
    breadth = min(1.0, len(linked_links) / possible_pairs)
    return _round(min(1.0, 0.60 * strongest + 0.30 * coverage + 0.10 * breadth))


def _rationale(
    linked_groups: Sequence[Mapping[str, Any]],
    clusters: Sequence[Mapping[str, Any]],
    infra_score: float,
) -> str:
    """Plain-language explanation of the score, for the case file."""
    if not linked_groups:
        return (
            "No shared certificate serial, SAN or server banner was observed, so "
            "the probed endpoints show no infrastructure linkage."
        )
    kinds: dict[str, int] = defaultdict(int)
    for group in linked_groups:
        kinds[group["kind"]] += 1
    summary = ", ".join(f"{count} shared {kind}" for kind, count in sorted(kinds.items()))
    strongest = max(linked_groups, key=lambda group: (group["weight"], group["group_id"]))
    return (
        f"{len(clusters)} infrastructure cluster(s) across {len(linked_groups)} "
        f"shared artefact group(s): {summary}. Strongest evidence is "
        f"{strongest['group_id']} spanning {strongest['size']} endpoints, giving "
        f"an infrastructure score of {infra_score:.4f}."
    )
