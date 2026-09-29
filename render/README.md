# Render deployment kit

Everything needed to put the platform on Render in one command — **once the
workspace has billing configured**.

## Status (2026-09-29)

Deployment is **blocked by Render, not by this repo**: service creation via the
API returns

> `Payment information is required to complete this request. To add a card, visit https://dashboard.render.com/billing`

Render requires a payment method on the workspace even for free-tier services.
Add a card (or prepay credits) at the link above, then run the script below.

## One-command deploy

```bash
RENDER_API_KEY=rnd_xxx \
RENDER_OWNER_ID=tea_xxx \
./render/deploy_render.sh
```

The script:

1. creates `forensic-mock-onion` (Docker, `simulation/Dockerfile.simulation`,
   `MOCK_ROLE=onion`, binds `$PORT`),
2. creates `forensic-mock-clearnet` (same image, `MOCK_ROLE=clearnet`),
3. reads back both services' real `<id>.onrender.com` hostnames and creates
   `forensic-backend` wired to them via `FORENSIC_MOCK_*_BASE_URL`,
4. creates the `forensic-frontend` static site (`VITE_API_BASE_URL` baked at
   build time to the backend's public URL).

## How the forensic TLS story survives a PaaS

Render terminates public TLS with its own `*.onrender.com` certificates, but
the infrastructure prober deliberately never disables certificate verification
— it trusts only the committed fixture CA (`shared.crt`). So:

* `backend/app/services/cert_issuer.py` mints fresh leaf certificates at
  service startup, signed by the fixture CA, carrying the fixture's shared
  serial and the service's Render hostnames in the SAN. Only `shared.crt`
  (the public CA cert) ships inside the backend image; private keys stay with
  the mock services.
* `simulation/render_entrypoint.py` is the Docker `CMD` on Render: it sets
  `MOCK_ROLE`, binds `$PORT` for the edge router, mints the leaf, then starts
  the selected mock server with both listeners.
* The backend's `FORENSIC_MOCK_*_BASE_URL` env vars point at the mocks'
  private hostnames, so probes stay inside the workspace network.

## Caveats on the free tier

* Services sleep after ~15 minutes idle; the first request pays a spin-up
  delay (the prober's 5-second timeout may need raising).
* Free Postgres is not used — the case database is SQLite on the service's
  local disk, which is **ephemeral on redeploy**. Attach a Render Disk (paid)
  at `/app/data` for persistence across deploys.
