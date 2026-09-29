"""Single-process deployment: API + both testbeds + dashboard on one port.

Why this exists
---------------
Render's free tier (and any tiny PaaS allocation) fits one small service far
better than four. This entrypoint runs the entire platform inside one
container bound to a single ``$PORT``:

* the FastAPI application (REST API + dashboard) on ``0.0.0.0:$PORT``,
* the mock hidden-service and mock clearnet host running their *TLS*
  listeners on loopback ports in a background thread, so the infrastructure
  prober still performs real TLS handshakes against real fixture-CA-signed
  certificates without a second container,
* the same mock apps also mounted as plain-HTTP ASGI sub-apps under
  ``/testbed/onion`` and ``/testbed/clearnet`` for browser inspection.

How the prober reaches the testbeds
-----------------------------------
``infra_prober.route_plan`` allowlists reserved suffixes (``.onion``,
``.example``, ...) and fixture certificate names, then dials ``127.0.0.1``
with the correct SNI when the hostname does not resolve in DNS. Inside this
single container the loopback TLS listeners are therefore reachable under
their real certificate names with zero DNS trickery:

* ``https://vmijjgu...onion:18443``  -> loopback onion testbed (TLS),
* ``https://staging.northgate-hosting.example:19443`` -> clearnet testbed.

``FORENSIC_MOCK_*_BASE_URL`` are set accordingly before ``app.main`` imports
its settings. Evidence stays honest: certificates presented over those
handshakes genuinely are the fixture material, so the shared-serial and SAN
findings remain real observations, not canned output.
"""

from __future__ import annotations

import asyncio
import os
import threading
from pathlib import Path

import uvicorn

BACKEND_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_ROOT.parent

#: Mock-server sources. Defaults to the repo layout; the single-container
#: image overrides via ``SIMULATION_DIR``.
SIMULATION_ROOT = Path(os.getenv("SIMULATION_DIR", str(PROJECT_ROOT / "simulation")))

#: Certificate directory. On Render the repo checkout is the build context, so
#: the committed fixtures are present; locally the same default works.
CERT_DIR = Path(os.getenv("RENDER_CERT_DIR", str(SIMULATION_ROOT / "certs")))

#: Built dashboard. Defaults to the repo layout; the image overrides via
#: ``DASHBOARD_DIST``.
DASHBOARD_DIST = Path(os.getenv("DASHBOARD_DIST", str(PROJECT_ROOT / "frontend" / "dist")))

#: Loopback ports for the embedded testbed TLS listeners. High, unlikely to
#: collide; overridable for constrained environments.
ONION_TLS_PORT = int(os.getenv("EMBEDDED_ONION_TLS_PORT", "18443"))
CLEARNET_TLS_PORT = int(os.getenv("EMBEDDED_CLEARNET_TLS_PORT", "19443"))


def _simulation_module(name: str):
    """Import a mock server module from the simulation directory."""
    import sys

    if str(SIMULATION_ROOT) not in sys.path:
        sys.path.insert(0, str(SIMULATION_ROOT))
    return __import__(name)


def _tls_server(app, port: int, cert_file: Path, key_file: Path, log_level: str) -> uvicorn.Server:
    """One loopback TLS uvicorn server for a testbed app."""
    if not cert_file.is_file() or not key_file.is_file():
        raise FileNotFoundError(
            f"Embedded testbed TLS material missing: {cert_file}, {key_file}"
        )
    return uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level=log_level,
            ssl_certfile=str(cert_file),
            ssl_keyfile=str(key_file),
            lifespan="off",
        )
    )


def _run_testbed_tls() -> None:
    """Thread target: serve both testbeds' TLS listeners until process exit."""
    onion = _simulation_module("mock_onion_server")
    clearnet = _simulation_module("mock_clearnet_server")

    servers = [
        _tls_server(
            onion.app,
            ONION_TLS_PORT,
            CERT_DIR / "onion.crt",
            CERT_DIR / "onion.key",
            os.getenv("MOCK_ONION_LOG_LEVEL", "warning"),
        ),
        _tls_server(
            clearnet.app,
            CLEARNET_TLS_PORT,
            CERT_DIR / "server.crt",
            CERT_DIR / "server.key",
            os.getenv("MOCK_CLEARNET_LOG_LEVEL", "warning"),
        ),
    ]

    async def _serve_all() -> None:
        await asyncio.gather(*(server.serve() for server in servers))

    asyncio.run(_serve_all())


def _configure_environment() -> None:
    """Point the platform at the embedded testbed before app import."""
    os.environ.setdefault("FORENSIC_ENVIRONMENT", "embedded")
    os.environ.setdefault("FORENSIC_ALLOW_NETWORK_PROBES", "true")
    os.environ.setdefault(
        "FORENSIC_MOCK_ONION_BASE_URL", f"https://vmijjgu6ydy75cxmbj5p2ey42d7wsab6u4plz5m2kza3xkgqbnrsfktj.onion:{ONION_TLS_PORT}"
    )
    os.environ.setdefault(
        "FORENSIC_MOCK_CLEARNET_BASE_URL", f"https://staging.northgate-hosting.example:{CLEARNET_TLS_PORT}"
    )
    os.environ.setdefault("MOCK_ONION_HTTP_PORT", "19901")
    os.environ.setdefault("MOCK_ONION_TLS_PORT", str(ONION_TLS_PORT))
    os.environ.setdefault("MOCK_CLEARNET_HTTP_PORT", "19902")
    os.environ.setdefault("MOCK_CLEARNET_TLS_PORT", str(CLEARNET_TLS_PORT))
    os.environ.setdefault("MOCK_ONION_CERT_DIR", str(CERT_DIR))
    os.environ.setdefault("MOCK_CLEARNET_CERT_DIR", str(CERT_DIR))


def _mount_extras() -> None:
    """Attach namespaced testbed sub-apps and the dashboard to the API app."""
    from fastapi.responses import FileResponse
    from starlette.staticfiles import StaticFiles

    from app.main import app

    app.mount(
        "/testbed/onion",
        _simulation_module("mock_onion_server").app,
        name="testbed-onion",
    )
    app.mount(
        "/testbed/clearnet",
        _simulation_module("mock_clearnet_server").app,
        name="testbed-clearnet",
    )

    dist = DASHBOARD_DIST
    if (dist / "index.html").is_file():
        app.mount("/", StaticFiles(directory=str(dist), html=True), name="dashboard")

        # Vite emits content-hashed asset filenames, so they are safe to cache
        # hard; index.html must stay revalidatable so deploys propagate.
        @app.middleware("http")
        async def _asset_cache_headers(request, call_next):  # noqa: ANN001
            response = await call_next(request)
            path = request.url.path
            if path.startswith("/assets/"):
                response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
            elif path == "/" or path.endswith(".html"):
                response.headers["Cache-Control"] = "no-cache"
            return response
    else:

        @app.get("/", include_in_schema=False)
        def _root() -> dict:
            return {
                "service": "Evidence-First Forensic Platform",
                "mode": "embedded-single-container",
                "hint": "API under /api (docs at /docs), testbeds under /testbed/*",
            }


def main() -> None:
    _configure_environment()

    # Import app.main *after* the environment is configured so pydantic-settings
    # sees the embedded-mode base URLs.
    import app.main  # noqa: F401 - registers routes on import
    from app.main import app

    _mount_extras()

    # Start the loopback TLS testbeds before uvicorn takes over the main loop.
    threading.Thread(target=_run_testbed_tls, name="embedded-testbeds", daemon=True).start()

    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level=os.getenv("LOG_LEVEL", "info"),
    )


if __name__ == "__main__":
    main()
