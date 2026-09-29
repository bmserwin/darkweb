# Evidence-First Dark-Web Forensic Platform

An offline, evidence-first threat-intelligence platform for attributing dark-web
personas. Every piece of ingested evidence is anchored into an append-only
SHA-256 Merkle ledger **before** anything is analysed, and no attribution is
ever automatic: correlation engines propose, a human analyst disposes.

> **Simulation only.** The "dark web" here is a local mock: the onion and
> clearnet testbed servers run in Docker on your machine. Nothing in this
> repository contacts the real Tor network or the real internet. For lawful
> digital-forensics training, red-team infrastructure analysis and CTI tooling
> development only.

## Architecture

```
backend/     FastAPI + SQLAlchemy/SQLite. Merkle ledger, deterministic
             extractors, four correlation engines, fusion + adjudication,
             Section 65B PDF dossier and STIX 2.1 export.
simulation/  Mock hidden-service marketplace and mock hosting server with an
             exposed /server-status and a shared self-signed TLS fixture.
frontend/    React 18 + Vite + Tailwind v4 investigator dashboard with a
             force-directed temporal graph and a time-scrubber.
```

## The six phases

1. **Docker sandbox & schema** - `docker-compose.yml` orchestrates the backend,
   the two mock servers and the frontend; Pydantic/SQLAlchemy models define
   Actor, Identifier, ObservationEvent and the ledger.
2. **Immutable ingestion** - every payload is hashed into
   `H_n = SHA256(H_{n-1} + ISO_timestamp + payload)` first; extraction is
   deterministic regex over BTC (Base58/Bech32), PGP blocks (real
   fingerprint parsing), v3 onions, handles and clearnet IPs.
3. **Multi-signal engines** - UTXO common-input clustering, Burrows' Delta
   authorship verification, 24-hour circadian sleep-window profiling, and a
   passive TLS/status-page infrastructure prober.
4. **Temporal graph & API** - the bipartite evidence graph replays at any
   `cutoff_time`; fusion weights are `0.40 crypto / 0.25 infra / 0.20 temporal
   / 0.15 stylometry`, with first-class contradiction detection and downgrade.
5. **Investigator dashboard** - five tabs: Triage & Ingestion, Infrastructure
   Scanner, Temporal Knowledge Graph (time-scrubber), Adjudication Console
   (human-in-the-loop) and Legal Audit & Dossier (tamper demo).
6. **Court-ready exports** - ReportLab PDF dossier styled for print with a
   formal Section 65B (BSA 2023) certificate, plus a spec-valid STIX 2.1
   bundle (`threat-actor`, `identity`, `indicator`, `infrastructure`,
   `relationship`).

## Quickstart (Docker)

```bash
docker compose up --build
# backend    http://localhost:8000/api  (docs at /docs)
# frontend   http://localhost:5173
# mock onion http://localhost:8080 (HTTP) / 8443 (TLS)
# mock host  http://localhost:8081 (HTTP) / 9443 (TLS)
```

## Quickstart (local, no Docker)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r backend/requirements.txt
cd backend && uvicorn app.main:app --reload          # terminal 1
cd frontend && npm install && npm run dev            # terminal 2
pytest backend/tests                                 # 271 tests
```

## API surface

| Method | Path | Purpose |
| ------ | ---- | ------- |
| GET  | `/api/health` | Liveness + embedded ledger status |
| POST | `/api/ingest` | Anchor text to the ledger, extract identifiers |
| GET  | `/api/ingest/observations` | Recent anchored captures |
| GET  | `/api/graph` | Force-graph snapshot, optional `cutoff_time` |
| GET  | `/api/graph/summary` | Stats + top entities |
| GET  | `/api/graph/neighbourhood/{node_id}` | BFS ball around a node |
| GET  | `/api/actors` / `/api/actors/{handle}` | Persona dossiers |
| GET  | `/api/adjudication/queue` | Pending fusion candidates |
| POST | `/api/adjudication/action` | APPROVE / REJECT with notes |
| POST | `/api/infra/scan` | Passive probe of a `.onion` / fixture host |
| GET  | `/api/audit/verify` | Re-verify the whole hash chain |
| GET  | `/api/audit/ledger` | Block explorer payload |
| POST | `/api/audit/tamper` | Corrupt a block to demo detection |
| POST | `/api/audit/restore` | Undo the demo tamper |
| GET  | `/api/reports/pdf/{actor}` | Section 65B PDF dossier |
| GET  | `/api/reports/stix/{actor}` | STIX 2.1 bundle |

## TLS fixtures

`simulation/certs/` contains self-signed laboratory certificates whose shared
serial and `staging.northgate-hosting.example` SAN are the correlation
evidence the infra engine detects. They are regenerated automatically inside
the Docker build (`generate_certs.py`) and are trusted only by the prober's
explicit fixture CA bundle - never disable TLS verification elsewhere.

## Legal notice

This project simulates all targets locally. Do not point the prober at systems
you are not explicitly authorised to examine. Attribution outputs are
decision-support for trained analysts, not evidence of guilt; the Section 65B
certificate in the dossier must be completed and signed by a real examiner
before any evidentiary use.
