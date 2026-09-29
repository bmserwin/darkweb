"""Simulated hidden service: a mock dark-web marketplace.

Serves vendor listings (``darkfox77``, ``shadowbyte``) with Bitcoin wallets and
PGP public key blocks embedded in the page text, exactly as a real escrow-market
scrape would expose them. Bind-mounted into the Docker testbed so the ingestion
pipeline has realistic, repeatable evidence to consume offline.

This is a *lab fixture* against locally generated vendor personas. It performs no
real-world requests and hosts no real illicit content.

Listeners
---------
Two listeners share one ASGI app so the TLS port advertised by the compose file
is actually served rather than merely published:

* plain HTTP on ``8080`` - the ingestion path, which speaks no TLS.
* HTTPS on ``8443`` using ``certs/onion.crt`` + ``certs/onion.key`` - the
  evidence path. That leaf is issued by the shared self-signed CA and carries
  the same serial number as the clearnet leaf, which is the deliberate
  misconfiguration the infrastructure-correlation signal keys on.

Run as ``python mock_onion_server.py`` to bring both listeners up, or point
uvicorn at ``mock_onion_server:app`` for the HTTP listener alone.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import os
from pathlib import Path

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse

app = FastAPI(
    title="Mock Hidden Service",
    description="Simulated dark-web marketplace for offline forensic exercises.",
    version="1.0.0",
)

ONION_DOMAIN = os.getenv("MOCK_ONION_DOMAIN", "vmijjgu6ydy75cxmbj5p2ey42d7wsab6u4plz5m2kza3xkgqbnrsfktj.onion")
INTERNAL_IP = os.getenv("MOCK_ONION_INTERNAL_IP", "10.13.37.41")
LISTING_SEED = os.getenv("MOCK_ONION_SEED", "phase1-forensic-testbed")


# --- Deterministic fixture material ---------------------------------------
# Real GPG-exported armored public key blocks. Their SHA-1 fingerprints are
# canonical 40-char values, so the extractor's PGP path is exercised against
# genuine OpenPGP packet encoding rather than a hand-written approximation.
_PGP_BLOCKS = {
    "darkfox77": """-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBGq7rnwBCADH8pNNWNvOrqGKUqG+SrOB9RVCy3DpnEWWe/MquscbO2ebZ/+L
JYCPAa+g2bJKiW8AmOYvYIMV2mEehfbpUKXOmGhquEzW2KbPUPnpOsSLsj+mSL2r
p3m6BxG6CaFxzVK1p2k584z1qnuOoJRjkX4m5LtoL1UVRMUilPrZDkXskM1OynDF
uLCkjWBsQvigtntvFZTWPI+Q2dVVCJ0wzk1vRudMeLcM28UX9y25akmf6SYGEW5z
Qj9ARYvHnXS+GlZO1V4+mH/i4VYUUWQjrgVlyzqUSThyZaIr9ihQO1rbFZ6/JVpT
r6Lm2Sg1EISoegWzfOHNwmOFb8pOaOjhjmdPABEBAAG0N0ZvcmVuc2ljcyBGaXh0
dXJlIDxkYXJrZm94NzdAbm9ydGhnYXRlLWhvc3RpbmcuZXhhbXBsZT6JAVcEEwEK
AEEWIQQiVvKAsqXzeJFphhk+qTlpyQe2qAUCaruufAIbAwUJAeEzgAULCQgHAgIi
AgYVCgkICwIEFgIDAQIeBwIXgAAKCRA+qTlpyQe2qP/0CACVfURctOxcjE9Ux4mg
7ca4NpiaziTOtz2v9fB7JiD/ySuaQ+Vuhz9CwkI76oYaakYElrVHHhCppimCQb3x
+JMJI9WcKx6WwbGFTkMMp5HcleRDQyURxwY2z4goVspVujPrEPnwtSLPn/HFf5zs
IHAM2sJpNsoeSRnYmjTCApu/bqPRKqUWWO3Qrt0nLRtmVFgNaEhHZzrlTMhs22ds
ReOdereh3u1oLyWr/xogW/0rdnDJpsnbXxhtZy9mslttToHElxKv1hG1H2a9mr5i
BhSXFaTbL1FfMQrcjaGc7nfFJbJY/bscq/nj6jbzlWaHAa17BybRgu3TLt3AhyGV
jPOY
=IhZR
-----END PGP PUBLIC KEY BLOCK-----""",
    "shadowbyte": """-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBGq7rn0BCADI2r80248+FrNnGRyFEUHt0NR/0H5T2QOp3U4xRJ1We6qw2au1
feU0DjfhxTBP/qf4y+quTCgIJulBxEJtlB2rFzl3gMgDmfEh+zMFjvGsAXg8Suq/
/WqPs/vMP96NcxAErKnxObqiiOzga7sh9kjgamIIwAJtTNOWluU1FwOsvpR7kx0M
gd+vP4RcMtNRvdpPV16Qpd7BiO63bBOHgrtr/faHS5iXAGqea/kJMxG15JFyY8hl
vJTGyGzStvGEIxrpWO1NIbXNY+zyacIh+DJ/uGrItk+bKtTF2feRSkLnp0Jtu3+8
WzD+fc3LgVcYzdhMthqAvNaaJeRRRay/URYrABEBAAG0OEZvcmVuc2ljcyBGaXh0
dXJlIDxzaGFkb3dieXRlQG5vcnRoZ2F0ZS1ob3N0aW5nLmV4YW1wbGU+iQFXBBMB
CgBBFiEE12KrGeaI6ZWVS3USx/DQdBpBRHcFAmq7rn0CGwMFCQHhM4AFCwkIBwIC
IgIGFQoJCAsCBBYCAwECHgcCF4AACgkQx/DQdBpBRHeo8ggAnCuVmX4fo4yhukd5
tSQiYEWS+KJ2GATcLmG1HtsmxD+W4VsnU9qqwE/6mBAbmQoj/rZLPUgNef11GZpQ
FdW4+sFPvhkr3zR8AE+UgSABTuLfTUEryNmLnRpDD2ckkKdOSvZ1AcDuiyuBRiZ9
oHxAK2IbCHxfQkCaB2OWOu3N8SBBzCf5+wCxdqdr5GCFVfN05STphCGQmNa2xAhJ
FvIldY7hqTdEw9wDef/1MVy1t+6F4Swx2Eh8y5cE2jsA7japNLVny+SkzJWJMFVo
YG3JwHLMLV5ueDfFVeM1ZUeHV5bNVo4Q0mG8ColgZX6t7lBK8PWMfdbrvmiSyxkO
KS81UQ==
=mG4L
-----END PGP PUBLIC KEY BLOCK-----""",
}

# Wallet values are checksum-valid (Base58Check / Bech32 verified) so the
# extractor accepts them rather than silently dropping them as noise.
_VENDORS = [
    {
        "handle": "darkfox77",
        "title": "RAT builder access + exclusive loader",
        "price_btc": "0.85 BTC",
        "wallet": "bc1q2ndw34j75rjnum85xevj262ux9h37ng8cp0wzp",
        "legacy_wallet": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "pgp": _PGP_BLOCKS["darkfox77"],
        "contact": "@darkfox77_ops",
        "note": "Escrow only. No samples over clearnet. Key rotated after 2023 leak.",
    },
    {
        "handle": "shadowbyte",
        "title": "Full database dumps (gov + finance)",
        "price_btc": "4.20 BTC",
        "wallet": "bc1qteajweclzd40egr5kcaqmxhmrjz34f86wnne8q",
        "legacy_wallet": "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
        "pgp": _PGP_BLOCKS["shadowbyte"],
        "contact": "@shadowbyte_sell",
        "note": "Payment to same cluster as darkfox77. Session ID on request.",
    },
    {
        "handle": "nullroute_v2",
        "title": "SIM cards + burner identities",
        "price_btc": "0.20 BTC",
        "wallet": "bc1qkgfnv999p2q0wmnmkv0jfgyxc9c7k9tqjk63cf",
        "legacy_wallet": "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
        "pgp": _PGP_BLOCKS["shadowbyte"],
        "contact": "@nullroute_simshop",
        "note": "Reuses shadowbyte PGP block. Strong common-key contradiction signal.",
    },
]


def _render_listing(vendor: dict, index: int) -> str:
    """Render one vendor page as plaintext-ish HTML for scraping."""
    base = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(hours=index * 37)
    posted = base.isoformat().replace("+00:00", "Z")
    return f"""<article class="vendor-listing" id="listing-{index}">
  <h2 class="handle">{vendor['handle']}</h2>
  <div class="title">{vendor['title']}</div>
  <div class="price">Price: {vendor['price_btc']}</div>
  <div class="posted">Posted (UTC): {posted}</div>
  <div class="wallet">Bitcoin: {vendor['wallet']}</div>
  <div class="wallet-legacy">Alt wallet: {vendor['legacy_wallet']}</div>
  <div class="contact">Contact: {vendor['contact']}</div>
  <pre class="pgp">{vendor['pgp']}</pre>
  <p class="notes">{vendor['note']}</p>
</article>
"""


_LISTINGS_HTML = "\n".join(_render_listing(v, i) for i, v in enumerate(_VENDORS))


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    return HTMLResponse(f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>GhostLedger Market</title></head>
<body>
<h1>GhostLedger Market :: Vendor Board</h1>
<p>Mirror of onion service. Escrow enforced. All negotiations via PGP.</p>
<hr>
{_LISTINGS_HTML}
<hr>
<footer>Hidden service: {ONION_DOMAIN} &mdash; internal {INTERNAL_IP}</footer>
</body></html>""")


@app.get("/listings", response_class=HTMLResponse)
def listings() -> HTMLResponse:
    """Plain-text scrape target: one vendor per block, easy to diff."""
    parts = []
    for i, v in enumerate(_VENDORS):
        parts.append(
            f"handle={v['handle']}\n"
            f"price={v['price_btc']}\n"
            f"wallet={v['wallet']}\n"
            f"wallet_alt={v['legacy_wallet']}\n"
            f"contact={v['contact']}\n"
            f"{v['pgp']}\n"
            f"notes={v['note']}\n"
            + "-" * 60
        )
    return HTMLResponse("\n".join(parts))


@app.get("/vendor/{handle}", response_class=HTMLResponse)
def vendor(handle: str) -> HTMLResponse:
    for i, v in enumerate(_VENDORS):
        if v["handle"] == handle:
            return HTMLResponse(_render_listing(v, i))
    return HTMLResponse("<h1>404 - vendor not found</h1>", status_code=404)


@app.get("/robots.txt")
def robots() -> Response:
    return Response(
        "User-agent: *\nDisallow: /\nDisallow: /vendor/\n"
        "Crawl-delay: 60\n# Shadowbyte orders dir blocked for crawlers\n",
        media_type="text/plain",
    )


@app.get("/.well-known/pgp-key.txt")
def pgp_key() -> Response:
    """Market-wide key, deliberately distinct from per-vendor keys."""
    return Response(_PGP_BLOCKS["darkfox77"] + "\n", media_type="text/plain")


@app.get("/healthz")
def healthz() -> dict:
    return {
        "status": "ok",
        "service": "mock-onion",
        "onion_domain": ONION_DOMAIN,
        "internal_ip": INTERNAL_IP,
        "listing_count": len(_VENDORS),
    }


# --- TLS listener ---------------------------------------------------------
# The leaf is issued by the shared CA and reuses the shared serial, so an
# examiner who correlates this endpoint with the clearnet host sees a single
# signing artifact spanning two logically distinct namespaces.
LISTEN_HOST = os.getenv("MOCK_ONION_LISTEN_HOST", "0.0.0.0")
HTTP_PORT = int(os.getenv("MOCK_ONION_HTTP_PORT", "8080"))
TLS_PORT = int(os.getenv("MOCK_ONION_TLS_PORT", "8443"))
CERT_DIR = Path(os.getenv("MOCK_ONION_CERT_DIR", "/app/certs"))
TLS_CERT = Path(os.getenv("MOCK_ONION_TLS_CERT", str(CERT_DIR / "onion.crt")))
TLS_KEY = Path(os.getenv("MOCK_ONION_TLS_KEY", str(CERT_DIR / "onion.key")))


def tls_material() -> tuple[str, str]:
    """Resolve and validate the TLS keypair, failing loudly if unusable.

    A certificate without its key, or a key that does not match the
    certificate, must stop the container at startup rather than silently fall
    back to plaintext on a port that promises TLS.
    """
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
        log_level=os.getenv("MOCK_ONION_LOG_LEVEL", "info"),
        ssl_certfile=cert_file,
        ssl_keyfile=key_file,
    )


def _http_config() -> uvicorn.Config:
    return uvicorn.Config(
        app,
        host=LISTEN_HOST,
        port=HTTP_PORT,
        log_level=os.getenv("MOCK_ONION_LOG_LEVEL", "info"),
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
