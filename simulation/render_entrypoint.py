"""Render entrypoint for the mock simulation services.

Render routes public traffic to the port bound at ``$PORT`` and terminates
external TLS at its edge, so each mock service binds its plain-HTTP listener
to ``$PORT`` and parks the unused TLS listener on a loopback port. The service
presents a leaf certificate signed by the committed fixture CA, so the
backend's infrastructure prober - which verifies TLS against that CA and never
disables verification - succeeds against the mock services' Render hostnames.

Selected via the ``MOCK_ROLE`` environment variable (``onion`` or
``clearnet``); defaults to ``onion``.
"""

from __future__ import annotations

import os

from cert_issuer import ensure_leaf_certificate

ONION_HOST = "vmijjgu6ydy75cxmbj5p2ey42d7wsab6u4plz5m2kza3xkgqbnrsfktj.onion"
CLEARNET_HOST = "staging.northgate-hosting.example"


def _private_names(service: str) -> list[str]:
    """The Render DNS names peer services dial, from the environment."""
    names = []
    for var in (f"RENDER_EXTERNAL_URL", f"{service.upper().replace('-', '_')}_PRIVATE_HOST"):
        value = os.getenv(var)
        if value:
            names.append(value.replace("https://", "").replace("http://", "").rstrip("/"))
    # Render always injects the service's own name; the internal hostname is
    # <service-name> or <service-name>-<hash>. Both are covered by SANs.
    for var in ("RENDER_SERVICE_NAME",):
        value = os.getenv(var)
        if value:
            names.append(value)
            names.append(f"{value}.onrender.com")
    return names


def main() -> None:
    role = os.getenv("MOCK_ROLE", "onion").strip().lower()
    port = int(os.getenv("PORT", "8080"))
    park_port = int(os.getenv("MOCK_TLS_PARK_PORT", "18443"))

    if role == "clearnet":
        host, fallback_cert, fallback_key = CLEARNET_HOST, "server.crt", "server.key"
        tls_cert_env, tls_key_env = "MOCK_CLEARNET_TLS_CERT", "MOCK_CLEARNET_TLS_KEY"
    else:
        host, fallback_cert, fallback_key = ONION_HOST, "onion.crt", "onion.key"
        tls_cert_env, tls_key_env = "MOCK_ONION_TLS_CERT", "MOCK_ONION_TLS_KEY"

    # Mint a fresh leaf signed by the fixture CA when possible so the prober's
    # hostname and serial checks pass against the Render private hostnames.
    leaf = ensure_leaf_certificate(
        host,
        _private_names(role),
        fallback_cert=fallback_cert,
        fallback_key=fallback_key,
    )
    os.environ[tls_cert_env] = leaf["cert"]
    os.environ[tls_key_env] = leaf["key"]

    # Bind $PORT as the primary HTTP listener; park the second listener where
    # it cannot collide with anything on the host.
    if role == "clearnet":
        os.environ["MOCK_CLEARNET_HTTP_PORT"] = str(port)
        os.environ["MOCK_CLEARNET_TLS_PORT"] = str(park_port)
    else:
        os.environ["MOCK_ONION_HTTP_PORT"] = str(port)
        os.environ["MOCK_ONION_TLS_PORT"] = str(park_port)

    module = "mock_clearnet_server" if role == "clearnet" else "mock_onion_server"
    imported = __import__(module)
    imported.serve()


if __name__ == "__main__":
    main()
