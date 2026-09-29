"""Simulated clearnet hosting server with deliberate misconfiguration.

Three leaks make this host worth scanning in the graph:

1. ``/server-status``  - Apache-style status page leaking the hidden service's
   internal IP and the reverse-proxy hostname.
2. Banner disclosure   - ``Server:`` header + an explicit version banner.
3. Shared TLS material - presents the same certificate serial as the hidden
   service, plus SANs naming clearnet staging domains.

Lab fixture only; serves no real content and makes no outbound requests.

Listeners
---------
As with the hidden service, the ASGI app is exposed twice: plain HTTP on
``8081`` for ingestion and HTTPS on ``9443`` using ``certs/server.crt``.
The TLS leaf presents the same certificate serial as the onion leaf, so the
infrastructure-correlation signal has a real handshake to observe instead of
an advertised-but-absent port.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import os
from pathlib import Path

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, PlainTextResponse, Response

app = FastAPI(
    title="Mock Clearnet Host",
    description="Intentionally misconfigured shared-hosting node (lab fixture).",
    version="1.0.0",
)

SERVER_BANNER = os.getenv("MOCK_SERVER_BANNER", "Apache/2.4.41 (Ubuntu) OpenSSL/3.0.2")
HIDDEN_SERVICE_IP = os.getenv("MOCK_HIDDEN_SERVICE_IP", "10.13.37.41")
HIDDEN_SERVICE_VHOST = os.getenv("MOCK_HIDDEN_SERVICE_VHOST", "hs2.northgate-hosting.example")
UPSTREAM = os.getenv("MOCK_UPSTREAM", "10.13.37.41:8080")


def _status_page() -> str:
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    return f"""<!doctype html>
<html><head><title>Apache Server Status for northgate-hosting.example</title></head>
<body>
<h1>Apache Server Status for northgate-hosting.example</h1>
<p>Server Version: {SERVER_BANNER}</p>
<p>Server MPM: event<br>
Server uptime: 41 days, 3 hours, 7 minutes<br>
Server load: 0.02 0.04 0.01</p>
<table>
<tr><th>PID</th><th>PPID</th><th>Server</th><th>VHost</th><th>Request</th></tr>
<tr><td>2187</td><td>1</td><td>{UPSTREAM}</td><td>{HIDDEN_SERVICE_VHOST}</td><td>GET /listings</td></tr>
<tr><td>2201</td><td>1</td><td>{UPSTREAM}</td><td>{HIDDEN_SERVICE_VHOST}</td><td>POST /checkout</td></tr>
<tr><td>2219</td><td>1</td><td>{UPSTREAM}</td><td>{HIDDEN_SERVICE_VHOST}</td><td>GET /vendor/darkfox77</td></tr>
</table>
<p>Server uptime at {now}</p>
</body></html>"""


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    return HTMLResponse(
        "<h1>Northgate Hosting</h1><p>Shared hosting. Reverse proxy on port 443.</p>"
    )


@app.get("/server-status")
@app.get("/.status")
@app.get("/server-info")
def server_status() -> Response:
    """The high-value leak: reverse-proxy topology + internal hidden-service IP."""
    return Response(
        _status_page(),
        media_type="text/html",
        headers={"Server": SERVER_BANNER},
    )


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "service": "mock-clearnet", "banner": SERVER_BANNER}


@app.get("/.well-known/security.txt", response_class=PlainTextResponse)
def security_txt() -> str:
    return (
        "Contact: mailto:abuse@northgate-hosting.example\n"
        "Expires: 2030-01-01T00:00:00.000Z\n"
    )


# --- TLS listener ---------------------------------------------------------
LISTEN_HOST = os.getenv("MOCK_CLEARNET_LISTEN_HOST", "0.0.0.0")
HTTP_PORT = int(os.getenv("MOCK_CLEARNET_HTTP_PORT", "8081"))
TLS_PORT = int(os.getenv("MOCK_CLEARNET_TLS_PORT", "9443"))
CERT_DIR = Path(os.getenv("MOCK_CLEARNET_CERT_DIR", "/app/certs"))
TLS_CERT = Path(os.getenv("MOCK_CLEARNET_TLS_CERT", str(CERT_DIR / "server.crt")))
TLS_KEY = Path(os.getenv("MOCK_CLEARNET_TLS_KEY", str(CERT_DIR / "server.key")))


def tls_material() -> tuple[str, str]:
    """Resolve and validate the TLS keypair, failing loudly if unusable."""
    if not TLS_CERT.is_file() or not TLS_KEY.is_file():
        raise FileNotFoundError(
            f"TLS material missing: expected {TLS_CERT} and {TLS_KEY}"
        )
    certificate = x509.load_pem_x509_certificate(TLS_CERT.read_bytes())
    private_key = serialization.load_pem_private_key(TLS_KEY.read_bytes(), password=None)
    if private_key.public_key().public_numbers() != certificate.public_key().public_numbers():
        raise ValueError(f"{TLS_KEY} does not match the public key in {TLS_CERT}")
    return str(TLS_CERT), str(TLS_KEY)


def _tls_config() -> uvicorn.Config:
    cert_file, key_file = tls_material()
    return uvicorn.Config(
        app,
        host=LISTEN_HOST,
        port=TLS_PORT,
        log_level=os.getenv("MOCK_CLEARNET_LOG_LEVEL", "info"),
        ssl_certfile=cert_file,
        ssl_keyfile=key_file,
    )


def _http_config() -> uvicorn.Config:
    return uvicorn.Config(
        app,
        host=LISTEN_HOST,
        port=HTTP_PORT,
        log_level=os.getenv("MOCK_CLEARNET_LOG_LEVEL", "info"),
    )


def serve() -> None:
    """Run the plain-HTTP and TLS listeners concurrently for the process life."""
    servers = [uvicorn.Server(_http_config()), uvicorn.Server(_tls_config())]

    async def _run() -> None:
        await asyncio.gather(*(server.serve() for server in servers))

    try:
        asyncio.run(_run())
    finally:
        for server in servers:
            server.should_exit = True


if __name__ == "__main__":
    serve()
