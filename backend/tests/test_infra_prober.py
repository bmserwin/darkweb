"""Contract tests for the infrastructure prober and correlator.

Three kinds of check live here and the split is deliberate:

1. Static guarantees. The module source is inspected directly, so a later edit
   that introduces a verification bypass, or that lets the correlation path read
   ambient state, fails the suite rather than passing quietly.
2. Certificate parsing against the real testbed PKI on disk. Serials, SANs and
   self-signature results are checked against actual DER, not against a
   hand-copied expectation, so a regenerated fixture cannot silently drift away
   from the assertions.
3. Live probes against both mock servers, started as subprocesses on ports
   allocated at run time. These cover the success path, the verification-failure
   path and every structured error the public API promises.

Nothing here contacts a host outside the machine: the mock servers bind to
loopback, and the URLs under test are either loopback literals or names the
prober is required to dial on loopback.
"""

from __future__ import annotations

import ast
import contextlib
import datetime as dt
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Iterator, NamedTuple

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.config import PROJECT_ROOT, settings  # noqa: E402
from backend.app.services import infra_prober  # noqa: E402
from backend.app.services.infra_prober import (  # noqa: E402
    EXPECTED_SHARED_SERIAL,
    analyse_certificate,
    analyse_certificate_file,
    certificate_authority_path,
    certificate_directory,
    certificate_names,
    correlate,
    probe_target,
    route_plan,
)

MODULE_PATH = Path(infra_prober.__file__)
MODULE_SOURCE = MODULE_PATH.read_text(encoding="utf-8")
CERT_DIR = PROJECT_ROOT / "simulation" / "certs"
ONION_HOST = "vmijjgu6ydy75cxmbj5p2ey42d7wsab6u4plz5m2kza3xkgqbnrsfktj.onion"
CLEARNET_HOST = "ops-stage-clearnet.internal"
SHARED_SAN = "staging.northgate-hosting.example"


class Endpoints(NamedTuple):
    onion_http: int
    onion_tls: int
    clearnet_http: int
    clearnet_tls: int

    def onion_tls_url(self, path: str = "/healthz") -> str:
        return f"https://{ONION_HOST}:{self.onion_tls}{path}"

    def clearnet_tls_url(self, path: str = "/healthz") -> str:
        return f"https://{CLEARNET_HOST}:{self.clearnet_tls}{path}"


def _free_port() -> int:
    with socket.socket() as probe_socket:
        probe_socket.bind(("127.0.0.1", 0))
        return int(probe_socket.getsockname()[1])


def _tls_ready(port: int, server_hostname: str) -> bool:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(str(CERT_DIR / "shared.crt"))
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.0) as raw:
            with context.wrap_socket(raw, server_hostname=server_hostname) as tls:
                return tls.version() is not None
    except (OSError, ssl.SSLError):
        return False


def _wait_for(url: str, deadline: float = 30.0) -> None:
    end = time.monotonic() + deadline
    last_error: Exception | None = None
    while time.monotonic() < end:
        try:
            if requests.get(url, timeout=1.0).status_code == 200:
                return
        except Exception as exc:  # noqa: BLE001 - startup polling
            last_error = exc
        time.sleep(0.2)
    raise AssertionError(f"mock endpoint {url} never became ready: {last_error!r}")


def _launch(script: str, env_overrides: dict[str, str]) -> subprocess.Popen[bytes]:
    env = dict(os.environ)
    env.update(env_overrides)
    return subprocess.Popen(  # noqa: S603 - fixed interpreter and repo script
        [sys.executable, str(PROJECT_ROOT / "simulation" / script)],
        cwd=str(PROJECT_ROOT / "simulation"),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


@pytest.fixture(scope="session")
def endpoints() -> Iterator[Endpoints]:
    """Start both mock servers with TLS on ephemeral loopback ports."""
    chosen = Endpoints(
        onion_http=_free_port(),
        onion_tls=_free_port(),
        clearnet_http=_free_port(),
        clearnet_tls=_free_port(),
    )
    processes = [
        _launch(
            "mock_onion_server.py",
            {
                "MOCK_ONION_LISTEN_HOST": "127.0.0.1",
                "MOCK_ONION_HTTP_PORT": str(chosen.onion_http),
                "MOCK_ONION_TLS_PORT": str(chosen.onion_tls),
                "MOCK_ONION_TLS_CERT": str(CERT_DIR / "onion.crt"),
                "MOCK_ONION_TLS_KEY": str(CERT_DIR / "onion.key"),
            },
        ),
        _launch(
            "mock_clearnet_server.py",
            {
                "MOCK_CLEARNET_LISTEN_HOST": "127.0.0.1",
                "MOCK_CLEARNET_HTTP_PORT": str(chosen.clearnet_http),
                "MOCK_CLEARNET_TLS_PORT": str(chosen.clearnet_tls),
                "MOCK_CLEARNET_TLS_CERT": str(CERT_DIR / "server.crt"),
                "MOCK_CLEARNET_TLS_KEY": str(CERT_DIR / "server.key"),
            },
        ),
    ]
    try:
        _wait_for(f"http://127.0.0.1:{chosen.onion_http}/healthz")
        _wait_for(f"http://127.0.0.1:{chosen.clearnet_http}/healthz")
        for port, name in ((chosen.onion_tls, ONION_HOST), (chosen.clearnet_tls, CLEARNET_HOST)):
            deadline = time.monotonic() + 30.0
            while time.monotonic() < deadline and not _tls_ready(port, name):
                time.sleep(0.2)
            assert _tls_ready(port, name), f"TLS listener on {port} never became ready"
        for process in processes:
            assert process.poll() is None, "a mock server exited during startup"
        yield chosen
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)


@contextlib.contextmanager
def silent_listener() -> Iterator[int]:
    """Accept connections and never reply, so a read timeout is the outcome."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    stop = threading.Event()
    held: list[socket.socket] = []

    def accept_loop() -> None:
        listener.settimeout(0.2)
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except (socket.timeout, TimeoutError, OSError):
                continue
            held.append(connection)

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()
    try:
        yield int(listener.getsockname()[1])
    finally:
        stop.set()
        thread.join(timeout=5)
        for connection in held:
            connection.close()
        listener.close()


def _minimal_probe(url: str, **overrides: Any) -> dict[str, Any]:
    probe: dict[str, Any] = {
        "status": "ok",
        "url": url,
        "certificate": {
            "serial_hex": "0" * 32,
            "san_hosts": ["a.internal"],
        },
        "banner": "nginx",
        "tls_valid": True,
        "self_signed": False,
    }
    probe.update(overrides)
    return probe


# --- static guarantees -----------------------------------------------------


def _code_only_source(source: str) -> str:
    """Return ``source`` with comments and docstrings removed.

    The prohibition this backs is about *code*, so prose that merely names a
    forbidden API must not trip it. ``ast`` drops comments for us; docstrings
    are expression statements, so they are blanked before unparsing.
    """
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            node.value.value = ""
    return ast.unparse(tree)


def test_module_never_disables_certificate_verification() -> None:
    code_only = _code_only_source(MODULE_SOURCE)
    assert re.search(r"verify\s*=\s*False", code_only) is None
    assert "CERT_NONE" not in code_only
    assert "check_hostname=False" not in code_only.replace(" ", "")
    assert "ssl._create_unverified_context" not in code_only
    assert "load_default_certs" not in code_only


def test_correlation_path_reads_no_ambient_state() -> None:
    tree = ast.parse(MODULE_SOURCE)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert "random" not in imported, "correlation must not sample"
    assert "secrets" not in imported
    assert "os" not in imported, "no environment-dependent branching"


def test_public_api_is_declared() -> None:
    assert set(infra_prober.__all__) >= {"probe_target", "correlate"}
    for name in infra_prober.__all__:
        assert hasattr(infra_prober, name), f"{name} is exported but missing"


# --- certificate parsing against the real PKI ------------------------------


def test_ca_bundle_is_the_fixture_trust_anchor() -> None:
    assert certificate_directory() == CERT_DIR
    assert certificate_authority_path() == CERT_DIR / "shared.crt"
    anchor = analyse_certificate_file(CERT_DIR / "shared.crt")
    assert anchor["common_name"] == "Northgate Internal CA"
    assert anchor["self_signed"] is True
    assert anchor["is_ca"] is True
    assert anchor["serial_number"] == EXPECTED_SHARED_SERIAL


@pytest.mark.parametrize("leaf", ["onion.crt", "server.crt"])
def test_fixture_leaves_are_issued_by_the_local_authority(leaf: str) -> None:
    parsed = analyse_certificate_file(CERT_DIR / leaf)
    assert parsed["issuer_common_name"] == "Northgate Internal CA"
    assert parsed["issuer_is_local_authority"] is True
    assert parsed["self_signed"] is False
    assert parsed["is_ca"] is False
    assert parsed["shared_cert_serial"] is True
    assert parsed["serial_number"] == EXPECTED_SHARED_SERIAL
    assert re.fullmatch(r"[0-9A-F]{32}", parsed["serial_hex"])
    assert len(parsed["sha256_fingerprint"]) == 64


def test_san_entries_are_read_from_der_not_from_text() -> None:
    onion = analyse_certificate_file(CERT_DIR / "onion.crt")
    assert ONION_HOST in onion["san_hosts"]
    assert CLEARNET_HOST in onion["san_hosts"]
    assert SHARED_SAN in onion["san_hosts"]
    clearnet = analyse_certificate_file(CERT_DIR / "server.crt")
    assert "admin.northgate-hosting.example" in clearnet["san_hosts"]
    assert "198.51.100.24" in clearnet["san_ips"]
    assert clearnet["san_hosts"] == sorted(clearnet["san_hosts"])
    assert {ONION_HOST, CLEARNET_HOST, SHARED_SAN} <= set(certificate_names())


def test_certificate_organisation_is_available_for_the_hosting_hint() -> None:
    parsed = analyse_certificate_file(CERT_DIR / "server.crt")
    assert parsed["organization"] == "Northgate Hosting Ltd"
    assert parsed["organizational_unit"] == "Infrastructure"
    assert parsed["public_key"]["algorithm"] in {"rsa", "ec", "ed25519"}
    assert parsed["public_key"]["key_size"] > 0


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"not a certificate at all",
        b"-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n",
    ],
)
def test_unparsable_certificate_input_raises_value_error(payload: bytes) -> None:
    with pytest.raises(ValueError):
        analyse_certificate(payload)


def _self_signed_certificate(common_name: str, serial: int) -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name)])
    now = dt.datetime.now(dt.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(minutes=5))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )


def test_der_and_pem_inputs_agree() -> None:
    pem = analyse_certificate_file(CERT_DIR / "onion.crt")
    loaded = x509.load_pem_x509_certificate((CERT_DIR / "onion.crt").read_bytes())
    assert analyse_certificate(loaded.public_bytes(Encoding.DER))["serial_hex"] == pem["serial_hex"]


def test_a_foreign_certificate_is_not_flagged_as_shared() -> None:
    certificate = _self_signed_certificate("unrelated-host.example", 0x1122334455667788)
    parsed = analyse_certificate(certificate.public_bytes(Encoding.DER))
    assert parsed["serial_number"] == 0x1122334455667788
    assert parsed["shared_cert_serial"] is False
    assert parsed["expected_fixture_serial"] is False
    assert parsed["self_signed"] is True
    assert parsed["issuer_is_local_authority"] is False
    assert parsed["san_hosts"] == []


# --- live probes -----------------------------------------------------------


def test_onion_probe_reads_the_leaf_certificate(endpoints: Endpoints) -> None:
    probe = probe_target(endpoints.onion_tls_url())
    assert probe["status"] == "ok", probe["error"]
    assert probe["error"] is None
    assert probe["scheme"] == "https"
    assert probe["host"] == ONION_HOST
    assert probe["tls_valid"] is True
    assert probe["self_signed"] is False
    assert probe["shared_cert_serial"] is True
    assert probe["banner"] == "uvicorn"
    assert probe["san_hosts"] == sorted(probe["san_hosts"])
    assert ONION_HOST in probe["san_hosts"]
    assert CLEARNET_HOST in probe["san_hosts"]
    certificate = probe["certificate"]
    assert certificate["serial_number"] == EXPECTED_SHARED_SERIAL
    assert certificate["common_name"] == ONION_HOST
    assert certificate["issuer_common_name"] == "Northgate Internal CA"
    assert probe["hosting_asn_hint"]["issuer"] == "Northgate Internal CA"
    assert "Northgate Hosting Ltd" in probe["hosting_asn_hint"]["value"]
    assert probe["http"]["status_code"] == 200
    assert probe["http"]["final_url"] == endpoints.onion_tls_url()
    assert probe["trust"]["verification"] == "required"
    assert probe["trust"]["ca_bundle"] == str(CERT_DIR / "shared.crt")


def test_unresolvable_lab_name_is_dialled_on_loopback_but_verified_by_name(
    endpoints: Endpoints,
) -> None:
    probe = probe_target(endpoints.onion_tls_url())
    assert probe["transport"]["dial_host"] == "127.0.0.1"
    assert probe["transport"]["server_hostname"] == ONION_HOST
    assert probe["transport"]["lab_resolved"] is True
    assert probe["url"] == endpoints.onion_tls_url()


def test_clearnet_probe_exposes_the_upstream_apache_banner(endpoints: Endpoints) -> None:
    probe = probe_target(endpoints.clearnet_tls_url("/server-status"))
    assert probe["status"] == "ok", probe["error"]
    assert "Apache/2.4.41" in probe["banner"]
    assert probe["shared_cert_serial"] is True
    assert "northgate-hosting.example" in probe["san_hosts"]


def test_both_leaves_present_one_reused_serial(endpoints: Endpoints) -> None:
    onion = probe_target(endpoints.onion_tls_url())
    clearnet = probe_target(endpoints.clearnet_tls_url())
    assert onion["certificate"]["serial_hex"] == clearnet["certificate"]["serial_hex"]
    assert set(onion["san_hosts"]) & set(clearnet["san_hosts"]) == {CLEARNET_HOST, SHARED_SAN}
    assert onion["http"]["content_sha256"] != clearnet["http"]["content_sha256"]


def test_plaintext_probe_succeeds_without_a_certificate(endpoints: Endpoints) -> None:
    probe = probe_target(f"http://127.0.0.1:{endpoints.onion_http}/healthz")
    assert probe["status"] == "ok", probe["error"]
    assert probe["certificate"] is None
    assert probe["tls_valid"] is False
    assert probe["banner"] == "uvicorn"
    assert probe["http"]["status_code"] == 200


def test_hostname_mismatch_is_rejected_rather_than_downgraded(endpoints: Endpoints) -> None:
    probe = probe_target(f"https://127.0.0.1:{endpoints.clearnet_tls}/healthz")
    assert probe["status"] == "error"
    assert probe["error"]["code"] == "tls-verification-failed"
    assert probe["error"]["type"] == "SSLError"
    assert probe["tls_valid"] is False
    assert probe["certificate"] is None


def test_closed_port_is_reported_as_a_connection_failure() -> None:
    probe = probe_target(f"https://{CLEARNET_HOST}:{_free_port()}/healthz", timeout=5.0)
    assert probe["status"] == "error"
    assert probe["error"]["code"] == "connection-failed"
    assert probe["certificate"] is None


def test_a_silent_listener_is_reported_as_a_timeout() -> None:
    with silent_listener() as port:
        probe = probe_target(f"https://{CLEARNET_HOST}:{port}/healthz", timeout=1.0)
    assert probe["status"] == "error"
    assert probe["error"]["code"] == "timeout"


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/",
        "https://8.8.8.8/",
        "https://northgate-hosting.com/",
        "http://169.254.169.254/latest/meta-data/",
    ],
)
def test_public_targets_are_refused_without_dialling(url: str) -> None:
    probe = probe_target(url, timeout=5.0)
    assert probe["status"] == "error"
    assert probe["error"]["code"] == "host-not-allowed"
    assert probe["transport"] is None
    assert probe["certificate"] is None


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("", "invalid-url"),
        ("   ", "invalid-url"),
        ("not a url", "invalid-url"),
        ("https://exa mple.com/", "invalid-url"),
        ("https://", "invalid-url"),
        ("ftp://ops-stage-clearnet.internal/x", "unsupported-scheme"),
        ("file:///etc/passwd", "unsupported-scheme"),
    ],
)
def test_malformed_input_is_classified_not_attempted(url: str, code: str) -> None:
    probe = probe_target(url, timeout=5.0)
    assert probe["status"] == "error"
    assert probe["error"]["code"] == code


@pytest.mark.parametrize("url", [None, 42, 3.5, [], {}, object()])
def test_probe_target_never_raises_for_hostile_input(url: Any) -> None:
    probe = probe_target(url, timeout=5.0)
    assert isinstance(probe, dict)
    assert probe["status"] == "error"
    json.dumps(probe, allow_nan=False)


def test_probes_can_be_disabled_by_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "allow_network_probes", False)
    probe = probe_target(f"https://{CLEARNET_HOST}/healthz", timeout=5.0)
    assert probe["error"]["code"] == "probes-disabled"


def test_missing_ca_bundle_is_reported_rather_than_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(infra_prober, "certificate_authority_path", lambda: None)
    probe = probe_target(f"https://{CLEARNET_HOST}/healthz", timeout=5.0)
    assert probe["status"] == "error"
    assert probe["error"]["code"] == "ca-bundle-missing"


def test_probe_without_a_scheme_defaults_to_https(endpoints: Endpoints) -> None:
    probe = probe_target(f"{CLEARNET_HOST}:{endpoints.clearnet_tls}/healthz", timeout=10.0)
    assert probe["scheme"] == "https"
    assert probe["status"] == "ok", probe["error"]
    assert probe["tls_valid"] is True


def test_route_plan_refuses_public_hosts_and_permits_the_testbed() -> None:
    assert route_plan("example.com", 443)["allowed"] is False
    assert route_plan("198.51.100.7", 443)["allowed"] is False
    assert route_plan(ONION_HOST, 8443)["allowed"] is True
    assert route_plan(CLEARNET_HOST, 9443)["allowed"] is True
    assert route_plan("127.0.0.1", 8080)["allowed"] is True
    assert route_plan("mock-onion", 8080)["allowed"] is True
    assert route_plan("mock-clearnet", 8081)["allowed"] is True
    assert route_plan("192.0.2.4", 80)["allowed"] is False


def test_observed_metadata_matches_the_request(endpoints: Endpoints) -> None:
    probe = probe_target(endpoints.onion_tls_url())
    assert probe["url"] == endpoints.onion_tls_url()
    assert probe["port"] == endpoints.onion_tls
    assert probe["host"] == ONION_HOST
    observed = dt.datetime.fromisoformat(probe["observed_at"].replace("Z", "+00:00"))
    assert observed.tzinfo is not None
    assert abs((dt.datetime.now(dt.timezone.utc) - observed).total_seconds()) < 300


# --- correlation -----------------------------------------------------------


def test_live_probes_cluster_on_the_reused_certificate(endpoints: Endpoints) -> None:
    probes = [
        probe_target(endpoints.onion_tls_url()),
        probe_target(endpoints.clearnet_tls_url("/server-status")),
    ]
    result = correlate(probes)
    assert result["probe_count"] == 2
    assert result["usable_probe_count"] == 2
    assert result["failed_probe_count"] == 0
    assert result["infra_score"] > 0.5
    assert result["link_count"] == 1
    assert len(result["clusters"]) == 1
    cluster = result["clusters"][0]
    assert cluster["size"] == 2
    serial_hex = f"{EXPECTED_SHARED_SERIAL:032X}"
    assert f"cert_serial:{serial_hex}" in cluster["shared_artefacts"]
    assert result["groups"]["cert_serial"][serial_hex] == ["probe-0000", "probe-0001"]
    assert result["groups"]["san"][CLEARNET_HOST] == ["probe-0000", "probe-0001"]
    assert result["groups"]["san"][ONION_HOST] == ["probe-0000"]
    assert result["links"][0]["linked"] is True
    assert "cert_serial" in result["links"][0]["reasons"]
    json.dumps(result, allow_nan=False)


def test_correlation_is_deterministic(endpoints: Endpoints) -> None:
    probes = [
        probe_target(endpoints.onion_tls_url()),
        probe_target(endpoints.clearnet_tls_url()),
    ]
    first = json.dumps(correlate(probes), sort_keys=True)
    second = json.dumps(correlate(probes), sort_keys=True)
    assert first == second


def test_correlation_ignores_input_order_but_keeps_probes_distinct(
    endpoints: Endpoints,
) -> None:
    onion = probe_target(endpoints.onion_tls_url())
    clearnet = probe_target(endpoints.clearnet_tls_url())
    forward = correlate([onion, clearnet])
    backward = correlate([clearnet, onion])
    for result in (forward, backward):
        assert result["probe_count"] == 2
        assert result["link_count"] == 1
        assert len(result["clusters"]) == 1
        assert result["infra_score"] == forward["infra_score"]
        assert result["rationale"] == forward["rationale"]
        assert result["groups"]["cert_serial"] == forward["groups"]["cert_serial"]
    assert {entry["url"] for entry in forward["probes"]} == {entry["url"] for entry in backward["probes"]}
    assert {entry["probe_id"] for entry in forward["probes"]} == {"probe-0000", "probe-0001"}


def test_identical_urls_remain_distinct_subjects() -> None:
    probe = _minimal_probe("https://a.internal/x")
    result = correlate([probe, dict(probe)])
    assert result["probe_count"] == 2
    assert result["link_count"] == 1
    assert result["infra_score"] > 0.0
    assert result["clusters"][0]["size"] == 2
    assert len({entry["probe_id"] for entry in result["probes"]}) == 2


def test_unrelated_endpoints_score_zero() -> None:
    first = _minimal_probe(
        "https://a.internal/x",
        certificate={"serial_hex": "A" * 32, "san_hosts": ["a.internal"]},
        banner="nginx/1.0",
    )
    second = _minimal_probe(
        "https://b.internal/x",
        certificate={"serial_hex": "B" * 32, "san_hosts": ["b.internal"]},
        banner="caddy",
    )
    result = correlate([first, second])
    assert result["infra_score"] == 0.0
    assert result["link_count"] == 0
    assert result["clusters"] == []
    assert "no infrastructure linkage" in result["rationale"]


def test_a_shared_banner_alone_ranks_below_a_shared_certificate() -> None:
    banner_only = correlate(
        [
            _minimal_probe(
                "https://a.internal/x",
                certificate={"serial_hex": "A" * 32, "san_hosts": ["a.internal"]},
            ),
            _minimal_probe(
                "https://b.internal/y",
                certificate={"serial_hex": "B" * 32, "san_hosts": ["b.internal"]},
            ),
        ]
    )
    full = correlate(
        [
            _minimal_probe("https://a.internal/x"),
            _minimal_probe("https://a.internal/y"),
        ]
    )
    assert banner_only["link_count"] == 1
    assert list(banner_only["groups"]["cert_serial"].values()) == [["probe-0000"], ["probe-0001"]]
    assert full["groups"]["cert_serial"] == {
        "0" * 32: ["probe-0000", "probe-0001"],
    }
    assert 0.0 < banner_only["infra_score"] < full["infra_score"]


def test_breadth_of_linkage_raises_the_score() -> None:
    linked_probe = _minimal_probe("https://a.internal/x")
    unrelated = _minimal_probe(
        "https://z.internal/z",
        certificate={"serial_hex": "F" * 32, "san_hosts": ["z.internal"]},
        banner="caddy",
    )
    half = correlate([linked_probe, dict(linked_probe), unrelated, dict(unrelated)])
    whole = correlate([dict(linked_probe) for _ in range(4)])
    assert whole["infra_score"] > half["infra_score"]


def test_failed_probes_are_counted_but_never_linked(endpoints: Endpoints) -> None:
    good = probe_target(endpoints.onion_tls_url())
    bad = probe_target("https://example.com/", timeout=5.0)
    result = correlate([good, bad])
    assert result["probe_count"] == 2
    assert result["usable_probe_count"] == 1
    assert result["failed_probe_count"] == 1
    assert result["infra_score"] == 0.0
    assert result["probes"][1]["error_code"] == "host-not-allowed"


def test_group_members_are_sorted_and_scores_are_bounded() -> None:
    probes = [_minimal_probe(f"https://a.internal/{index}") for index in range(5)]
    result = correlate(probes)
    serial_members = next(iter(result["groups"]["cert_serial"].values()))
    assert serial_members == sorted(serial_members)
    assert result["link_count"] == 10
    assert result["clusters"][0]["size"] == 5
    assert 0.5 < result["infra_score"] <= 1.0
    assert correlate([dict(probe) for probe in probes])["infra_score"] == result["infra_score"]


@pytest.mark.parametrize(
    "probes",
    [
        [],
        None,
        (),
        ["not a mapping", 7, None],
        [{}],
        [{"status": "error", "url": "https://a.internal/", "error": {"code": "timeout"}}],
        [{"status": "ok"}, {"status": "ok", "certificate": None}],
        [{"status": "ok", "san_hosts": ["a.internal"], "banner": 12.5}],
    ],
)
def test_correlate_tolerates_degenerate_input(probes: Any) -> None:
    result = correlate(probes)
    assert isinstance(result, dict)
    assert 0.0 <= result["infra_score"] <= 1.0
    json.dumps(result, allow_nan=False)


def test_failed_probe_detail_is_summarised_without_raising() -> None:
    result = correlate(
        [
            {"status": "error", "url": "https://a.internal/", "error": "plain string"},
            {"status": "error", "url": "https://b.internal/", "error": None},
        ]
    )
    assert result["failed_probe_count"] == 2
    assert [entry["error_code"] for entry in result["probes"]] == [None, None]
    assert result["infra_score"] == 0.0


def test_probe_serialisation_survives_strict_json(endpoints: Endpoints) -> None:
    probe = probe_target(endpoints.onion_tls_url())
    encoded = json.dumps(probe, allow_nan=False, sort_keys=True)
    assert json.loads(encoded)["certificate"]["serial_number"] == EXPECTED_SHARED_SERIAL
    assert isinstance(probe["observed_at"], str)


def test_probe_result_carries_no_non_finite_numbers(endpoints: Endpoints) -> None:
    probe = probe_target(endpoints.clearnet_tls_url())
    result = correlate([probe, probe_target(endpoints.onion_tls_url())])
    for value in (probe, result):
        json.dumps(value, allow_nan=False)
        assert "NaN" not in json.dumps(value)
        assert "Infinity" not in json.dumps(value)


def test_ip_literals_in_san_are_parsed_as_addresses() -> None:
    clearnet = analyse_certificate_file(CERT_DIR / "server.crt")
    assert "198.51.100.24" in clearnet["san_ips"]
    assert all(ipaddress.ip_address(value) for value in clearnet["san_ips"])
