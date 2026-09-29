# Render deployment kit

Two supported paths, depending on budget.

## Status (2026-09-29)

Deployment is **blocked by Render, not by this repo**: service creation via the
API returns

> `Payment information is required to complete this request. To add a card, visit https://dashboard.render.com/billing`

Render requires a payment method on the workspace even for free-tier services.
Add a card (or prepay credits) at the link above, then run either script below.

## Free tier — one service, whole platform (recommended)

`Dockerfile.single` packs the FastAPI backend, **both simulated testbeds**
(loopback TLS with the real fixture certificates) and the built React dashboard
into **one process on one port** — exactly what the free plan permits.

```bash
RENDER_API_KEY=rnd_xxx \
RENDER_OWNER_ID=tea_xxx \
./render/deploy_render_free.sh
```

Inside the container:

* `/` — the dashboard, same origin as the API (the frontend calls `/api`
  relatively in production builds),
* `/api/*` — the forensic API (`/docs` for Swagger),
* `/testbed/onion/...`, `/testbed/clearnet/...` — testbeds over plain HTTP,
* the prober dials the testbeds' **loopback TLS** listeners under their real
  certificate names (`infra_prober.route_plan` allowlists reserved suffixes
  like `.onion` and dials `127.0.0.1` with correct SNI when DNS does not
  resolve), so the shared-serial and SAN findings remain genuine observations
  made over real TLS handshakes, not canned output.

## Paid tier — four services (production-ish)

The original topology: separate mock-onion, mock-clearnet, backend and static
frontend services with private networking between them.

```bash
RENDER_API_KEY=rnd_xxx \
RENDER_OWNER_ID=tea_xxx \
./render/deploy_render.sh
```

The script creates the two mock services first, reads back their real
`<id>.onrender.com` hostnames, wires the backend to them via
`FORENSIC_MOCK_*_BASE_URL`, then creates the static frontend pointed at the
backend's public URL. `simulation/render_entrypoint.py` (the image `CMD` on
Render) mints runtime leaf certificates signed by the committed fixture CA
with the Render hostnames in the SAN, keeping the probe chain honest in a
multi-container layout.

## Caveats on the free tier

* Services sleep after ~15 minutes idle; the first request pays a spin-up
  delay (the prober's 5-second timeout may need raising).
* The case database (SQLite) lives on the instance's ephemeral disk and
  **resets on redeploy**. Attach a Render Disk at `/app/data` (paid) for
  persistence across deploys.
