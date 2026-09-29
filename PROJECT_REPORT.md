# Project Report — Evidence-First Dark-Web Forensic Platform

**Repository:** https://github.com/bmserwin/darkweb (private)
**Report date:** 2026-09-29 · **Status:** Feature-complete, locally verified, Render deployment pending billing setup

---

## 1. Executive summary

An offline, evidence-first threat-intelligence platform for attributing dark-web
personas across three proof layers:

1. **Deterministic identifiers** — regex extraction of Bitcoin addresses (Base58 +
   Bech32), real PGP fingerprints, v3 `.onion` hostnames, handles and clearnet IPs.
2. **Behavioural signals** — UTXO co-spend clustering, Burrows' Delta authorship
   stylometry, circadian sleep-window timezone estimation, passive TLS/status-page
   infrastructure probing.
3. **A cryptographic chain of custody** — every raw payload is anchored into an
   append-only SHA-256 Merkle ledger *before* analysis; any byte flipped anywhere
   in the store is detected at the exact block.

No attribution is ever automatic: the fusion engine proposes candidate links, a
human analyst approves or rejects each one in the adjudication console, and the
case can be exported as a court-ready Section 65B (BSA 2023) PDF dossier or a
STIX 2.1 bundle.

**Everything is simulated locally.** The "dark web" is a mock marketplace and a
mock hosting server running in Docker; nothing contacts the real Tor network.

### Key verification results (this session)

| Check | Result |
|---|---|
| Backend unit/integration tests | **271 / 271 pass** |
| Frontend production build | ✅ 2,611 modules, ~360 KB bundle |
| `docker compose up --build` | ✅ all 4 containers **healthy** |
| Infra prober over TLS | ✅ found shared cert serial (90%), SAN staging-host leak (90%), banner (70%) |
| Full pipeline | ✅ ingest (4 identifiers) → graph (10 nodes/10 links) → adjudication (contradiction flagged, analyst action) → PDF (9.3 KB, `%PDF`) → STIX (18 objects) |
| Merkle tamper demo | ✅ mutation detected at exact block; restore verified |
| Render deployment | ⚠️ blocked — workspace requires a payment method on file |

---

## 2. Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│  frontend (React 18 + Vite + Tailwind v4)          :5173               │
│  5 tabs: Triage · Infra Scanner · Time-Graph · Adjudication · Legal    │
└──────────────────────────────┬─────────────────────────────────────────┘
                               │ REST (JSON)
┌──────────────────────────────▼─────────────────────────────────────────┐
│  backend (FastAPI + SQLAlchemy/SQLite)             :8000               │
│  /api/ingest · /api/graph · /api/adjudication · /api/infra/scan        │
│  /api/audit/* · /api/reports/{pdf,stix}                                │
│                                                                        │
│  Services:                                                             │
│   merkle_ledger      append-only H_n = SHA256(H_{n-1}+ts+payload)      │
│   extractor          deterministic regex identifiers                  │
│   ingest_service     anchor-first pipeline                             │
│   crypto_engine      UTXO common-input clustering                     │
│   stylometry_engine  Burrows' Delta (50 function words, z-scores)     │
│   circadian_engine   24-h histogram → sleep window → UTC offset       │
│   infra_prober       TLS/status-page passive scanner (fixture CA)     │
│   fusion_engine      0.40 crypto + 0.25 infra + 0.20 temporal         │
│                      + 0.15 stylometry, contradiction downgrade        │
│   graph_engine       replayable bipartite evidence graph (networkx)   │
│   report_generator   ReportLab 65B dossier + STIX 2.1 bundle          │
└───────────┬──────────────────────────────────┬─────────────────────────┘
            │                                  │
┌───────────▼──────────┐            ┌──────────▼──────────┐
│ mock-onion   :8080   │            │ mock-clearnet :8081 │
│  (TLS :8443)         │            │  (TLS :9443)        │
│  fake market:        │            │  /server-status     │
│  vendors, PGP, BTC   │            │  leaks onion IP     │
└──────────────────────┘            └─────────────────────┘
```

### Why evidence-first matters

- **Anchor-then-analyse:** if extraction crashes, the payload is still preserved
  and auditable. Re-ingesting overlapping evidence strengthens links instead of
  duplicating nodes.
- **Missing signals are excluded, not zeroed.** An actor judged on wallet
  evidence alone is scored on wallet evidence alone; weight redistributes
  pro-rata and is reported in the audit trail.
- **Contradiction is first-class.** A high stylometry match combined with
  disjoint circadian rhythms *downgrades* confidence (×0.65 penalty) and raises
  a visible OPSEC anomaly rather than averaging the disagreement away.

---

## 3. Component inventory

| Path | Purpose | Status |
|---|---|---|
| `backend/app/main.py` | FastAPI app, CORS, lifespan | ✅ |
| `backend/app/api/endpoints.py` | 17 REST routes | ✅ new this session |
| `backend/app/models/` | SQLAlchemy entities + Pydantic schemas | ✅ |
| `backend/app/services/merkle_ledger.py` | Append-only ledger, verify/tamper/restore | ✅ |
| `backend/app/services/extractor.py` | BTC / PGP / onion / handle / IP extractors | ✅ |
| `backend/app/services/ingest_service.py` | Anchor-first ingestion pipeline | ✅ |
| `backend/app/services/crypto_engine.py` | UTXO co-spend clustering | ✅ |
| `backend/app/services/stylometry_engine.py` | Burrows' Delta + syntactic profile | ✅ |
| `backend/app/services/circadian_engine.py` | Sleep-window timezone profiler | ✅ |
| `backend/app/services/infra_prober.py` | Offline-allowlisted TLS prober | ✅ |
| `backend/app/services/fusion_engine.py` | 4-signal fusion + contradiction rules | ✅ |
| `backend/app/services/graph_engine.py` | Temporal bipartite graph replay | ✅ |
| `backend/app/services/report_generator.py` | 65B PDF + STIX 2.1 | ✅ new this session |
| `backend/app/services/cert_issuer.py` | Runtime leaf certs (for Render TLS) | ✅ new (Render prep) |
| `backend/tests/` | 271 tests across 4 engine suites | ✅ all pass |
| `frontend/src/` | Dashboard (App + 5 panels + API client) | ✅ new this session |
| `simulation/` | Mock onion market + clearnet host + PKI fixtures | ✅ |
| `docker-compose.yml` | 4-service orchestration | ✅ verified |

---

## 4. The six build phases

| Phase | Deliverable | Verified by |
|---|---|---|
| 1 — Skeleton & testbed | Docker compose, models, mock servers | containers healthy |
| 2 — Ledger & ingestion | Merkle chain, deterministic extractors | tamper detection test |
| 3 — Four engines | crypto / stylometry / circadian / infra | 271 unit tests |
| 4 — Graph & API | fusion + adjudication + REST | live curl smoke tests |
| 5 — Dashboard | React UI, time-scrubber, tamper demo | production build |
| 6 — Legal exports | 65B PDF, STIX 2.1 | rendered PDF inspected |

---

## 5. Local runbook

### Docker (verified end-to-end)

```bash
docker compose up --build -d
# backend    http://localhost:8000/api   (Swagger at /docs)
# frontend   http://localhost:5173
# mock onion :18080 (HTTP) / :8443 (TLS)   ← host port moved; see override file
# mock host  :8081 (HTTP) / :9443 (TLS)
```

> **Note (this machine):** host port 8080 is occupied by an unrelated process,
> so `docker-compose.override.yml` (git-ignored, local-only) maps the mock
> onion to host port 18080, adds compose-network aliases for the fake
> hostnames, and runs the mocks via their module entrypoints so the TLS
> listeners start (the base file's uvicorn command serves plain HTTP only).

### Without Docker

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r backend/requirements.txt
cd backend && uvicorn app.main:app --reload        # terminal 1
cd frontend && npm install && npm run dev          # terminal 2
pytest backend/tests                               # 271 pass
```

### Quick API tour

```bash
curl localhost:8000/api/health
curl -X POST localhost:8000/api/ingest -H 'Content-Type: application/json' \
  -d '{"text":"PGP block + bc1q... + http://<56>.onion","source":"demo","actor_handle":"darkfox77"}'
curl localhost:8000/api/graph
curl localhost:8000/api/adjudication/queue
curl -X POST localhost:8000/api/audit/tamper -H 'Content-Type: application/json' -d '{"block_index":0}'
```

---

## 6. Forensic integrity guarantees

1. **Contiguity:** block indices are gapless from genesis; a reordered or
   deleted row fails verification immediately.
2. **Linkage:** every `previous_hash` must match its predecessor's
   `current_hash` — any insertion in the middle breaks the chain forward.
3. **Content:** each hash recomputes over the stored payload, so a mutated
   payload is detected *at that block*.
4. **Tamper demo:** `POST /api/audit/tamper {"block_index":N}` flips one byte
   without rehashing; `GET /api/audit/verify` then reports
   `TAMPERED / corrupted_block_index: N` — the red flashing banner in the UI.
   `POST /api/audit/restore?block_index=N` reverts the exercise.

---

## 7. Legal-use notice

This project simulates all targets locally. Do not point the prober at systems
you are not explicitly authorised to examine. Attribution outputs are
decision-support for trained analysts, not proof of guilt. The Section 65B
certificate in the dossier must be completed and signed by a real forensic
examiner before any evidentiary use.

---

## 8. Known limitations & next steps

| Item | Detail |
|---|---|
| **Render deployment ready** | Full enablement kit in `render/` (one-command deploy script + runtime cert issuer). Creation is blocked only by workspace billing: Render requires a card on file even for free services (see `render/README.md`). |
| SQLite at scale | Fine for a case-sized store; swap to Postgres for multi-analyst concurrency. |
| Circadian estimate | Probabilistic (verdict + confidence), not a legal claim of location. |
| Stylometry corpus | Needs ≥ a few hundred words per side for a meaningful Delta. |
| Free-tier cold starts | When deployed, Render free services sleep after 15 min idle; first request pays a spin-up delay. |
