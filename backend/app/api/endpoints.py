"""REST surface for the Evidence-First Forensic Platform.

Every mutating route funnels through the same services the tests exercise, and
every read route is a pure projection of persisted state, so the API cannot
drift from the engines underneath it. Timestamps in and out are ISO-8601 UTC;
payloads are JSON-native end to end.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..models.database import get_session
from ..models.entities import (
    Actor,
    ActorProfile,
    AuditLedgerBlock,
    CandidateLink as CandidateLinkEntity,
    Identifier,
    IdentifierLink,
    ObservationEvent,
)
from ..models.schemas import (
    AdjudicationActionRequest,
    AdjudicationActionResponse,
    AuditBlock,
    AuditLedgerResponse,
    AuditVerifyResponse,
    GraphSnapshot,
    IngestRequest,
    IngestResponse,
    InfraScanRequest,
    InfraScanResponse,
    LedgerStatus,
    TamperRequest,
    TamperResponse,
)
from ..services import graph_engine
from ..services.fusion_engine import fuse_pair
from ..services.infra_prober import probe_target
from ..services.ingest_service import ingest_raw_text
from ..services.merkle_ledger import GENESIS_HASH, MerkleLedger
from ..services.report_generator import (
    build_case_record,
    generate_stix_bundle,
    render_dossier_pdf,
)

router = APIRouter()

UTC = dt.timezone.utc


def _parse_cutoff(raw: Optional[str]) -> Optional[dt.datetime]:
    if raw is None or not raw.strip():
        return None
    cleaned = raw.strip().replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(cleaned)
    except ValueError as exc:
        raise HTTPException(
            status_code=422, detail=f"Invalid ISO-8601 cutoff_time: {raw!r}"
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


# ---------------------------------------------------------------------------
# System
# ---------------------------------------------------------------------------
@router.get("/health", tags=["system"])
def health(session: Session = Depends(get_session)) -> dict[str, Any]:
    ledger = MerkleLedger(session)
    verified, corrupted = ledger.verify_integrity()
    return {
        "status": "online",
        "service": settings.app_name,
        "version": settings.version,
        "case_reference": settings.case_reference,
        "ledger": {
            "status": LedgerStatus.VERIFIED if verified else LedgerStatus.TAMPERED,
            "verified": verified,
            "corrupted_block_index": corrupted,
            "head_index": (ledger.head().block_index if ledger.head() else None),
        },
    }


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------
@router.post("/ingest", response_model=IngestResponse, tags=["ingestion"])
def ingest(
    request: IngestRequest, session: Session = Depends(get_session)
) -> IngestResponse:
    try:
        result = ingest_raw_text(
            request.text,
            request.source,
            session=session,
            platform=request.platform,
            actor_handle=request.actor_handle,
            observed_at=request.observed_at,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    identifiers = [
        {
            "id_type": row["id_type"],
            "value": row["value"],
            "confidence": row["confidence"],
            "meta": row["meta"],
        }
        for row in result["identifiers"]
    ]
    return IngestResponse(
        observation_id=int(result["observation_id"]),
        ledger_block=int(result["ledger_block"]),
        ledger_hash=str(result["ledger_hash"]),
        identifiers=identifiers,
        actor_handle=result["actor_handle"],
        message=str(result["message"]),
    )


@router.get("/ingest/observations", tags=["ingestion"])
def recent_observations(
    limit: int = Query(default=25, ge=1, le=200),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    rows = session.execute(
        select(ObservationEvent, AuditLedgerBlock)
        .join(AuditLedgerBlock, ObservationEvent.ledger_block_id == AuditLedgerBlock.id)
        .order_by(ObservationEvent.observed_at.desc(), ObservationEvent.id.desc())
        .limit(limit)
    ).all()
    observations = []
    for observation, block in rows:
        observations.append(
            {
                "observation_id": observation.id,
                "source_url": observation.source_url,
                "platform": observation.platform,
                "observed_at": observation.observed_at.isoformat(),
                "payload_preview": observation.payload_preview,
                "ledger_block": block.block_index,
                "ledger_hash": block.current_hash,
                "identifier_count": session.execute(
                    select(func.count())
                    .select_from(IdentifierLink)
                    .where(IdentifierLink.observation_id == observation.id)
                ).scalar_one(),
            }
        )
    return {"observations": observations, "count": len(observations)}


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------
@router.get("/graph", tags=["graph"])
def graph(
    cutoff_time: Optional[str] = Query(default=None),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    return graph_engine.build_graph(session, cutoff_time=_parse_cutoff(cutoff_time))


@router.get("/graph/summary", tags=["graph"])
def graph_summary(
    cutoff_time: Optional[str] = Query(default=None),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    return graph_engine.graph_summary(session, cutoff_time=_parse_cutoff(cutoff_time))


@router.get("/graph/neighbourhood/{node_id}", tags=["graph"])
def graph_neighbourhood(
    node_id: str,
    depth: int = Query(default=1, ge=0, le=6),
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    return graph_engine.neighbourhood(session, node_id, depth=depth)


# ---------------------------------------------------------------------------
# Actors
# ---------------------------------------------------------------------------
@router.get("/actors", tags=["actors"])
def list_actors(session: Session = Depends(get_session)) -> dict[str, Any]:
    actors = session.execute(select(Actor).order_by(Actor.handle.asc())).scalars().all()
    payload = []
    for actor in actors:
        payload.append(
            {
                "handle": actor.handle,
                "actor_type": actor.actor_type,
                "first_seen": actor.first_seen.isoformat() if actor.first_seen else None,
                "last_seen": actor.last_seen.isoformat() if actor.last_seen else None,
                "identifier_count": len(actor.identifiers),
                "profile": actor.profile_json or {},
            }
        )
    return {"actors": payload, "count": len(payload)}


@router.get("/actors/{handle}", tags=["actors"])
def actor_detail(handle: str, session: Session = Depends(get_session)) -> dict[str, Any]:
    actor = session.execute(
        select(Actor).where(Actor.handle == handle)
    ).scalar_one_or_none()
    if actor is None:
        raise HTTPException(status_code=404, detail=f"Unknown actor: {handle!r}")

    identifiers = session.execute(
        select(Identifier, IdentifierLink)
        .join(IdentifierLink, IdentifierLink.identifier_id == Identifier.id)
        .where(IdentifierLink.actor_id == actor.id)
        .order_by(Identifier.id_type.asc(), Identifier.value.asc())
    ).all()
    seen: set[int] = set()
    extracted = []
    for identifier, _link in identifiers:
        if identifier.id in seen:
            continue
        seen.add(identifier.id)
        extracted.append(
            {
                "id_type": identifier.id_type,
                "value": identifier.value,
                "confidence": identifier.confidence,
                "first_seen": identifier.first_seen.isoformat()
                if identifier.first_seen
                else None,
                "meta": identifier.meta_json or {},
            }
        )

    profile = session.execute(
        select(ActorProfile).where(ActorProfile.actor_id == actor.id)
    ).scalar_one_or_none()

    return {
        "handle": actor.handle,
        "actor_type": actor.actor_type,
        "first_seen": actor.first_seen.isoformat() if actor.first_seen else None,
        "last_seen": actor.last_seen.isoformat() if actor.last_seen else None,
        "identifiers": extracted,
        "circadian": (profile.circadian_json if profile else None) or None,
        "stylometry": (profile.stylometry_json if profile else None) or None,
        "crypto": (profile.crypto_json if profile else None) or None,
        "infra": (profile.infra_json if profile else None) or None,
    }


# ---------------------------------------------------------------------------
# Adjudication
# ---------------------------------------------------------------------------
@router.get("/adjudication/queue", tags=["adjudication"])
def adjudication_queue(
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """Provisional candidate links awaiting analyst approval.

    Candidates are generated lazily: every unprocessed pair of tracked actors
    that shares at least one anchored observation window is fused once and
    persisted, so the queue survives restarts and adjudication is idempotent.
    """
    _materialise_candidates(session)

    rows = session.execute(
        select(CandidateLinkEntity)
        .where(CandidateLinkEntity.status == "PENDING")
        .order_by(CandidateLinkEntity.confidence.desc(), CandidateLinkEntity.candidate_id.asc())
    ).scalars().all()

    queue = []
    for row in rows:
        queue.append(
            {
                "candidate_id": row.candidate_id,
                "source_actor": row.source_actor,
                "target_actor": row.target_actor,
                "confidence": row.confidence,
                "signals": row.signal_json or {},
                "contradiction": row.contradiction,
                "contradiction_reasons": row.contradiction_reasons or [],
                "status": row.status,
                "analyst_notes": row.analyst_notes,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
        )
    return {"queue": queue, "pending": len(queue)}


@router.post(
    "/adjudication/action",
    response_model=AdjudicationActionResponse,
    tags=["adjudication"],
)
def adjudication_action(
    request: AdjudicationActionRequest, session: Session = Depends(get_session)
) -> AdjudicationActionResponse:
    row = session.execute(
        select(CandidateLinkEntity).where(
            CandidateLinkEntity.candidate_id == request.candidate_id
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown candidate_id: {request.candidate_id!r}",
        )
    if row.status != "PENDING":
        raise HTTPException(
            status_code=409,
            detail=f"Candidate {request.candidate_id} is already {row.status}",
        )

    row.status = "APPROVED" if request.action == "APPROVE" else "REJECTED"
    row.analyst_notes = request.analyst_notes.strip()
    row.adjudicated_at = dt.datetime.now(UTC)
    session.commit()

    message = (
        f"Candidates {row.source_actor} and {row.target_actor} merged under "
        f"{row.source_actor}; both personas now reference the fused identity."
        if request.action == "APPROVE"
        else f"Match between {row.source_actor} and {row.target_actor} rejected; "
        "both personas remain distinct."
    )
    return AdjudicationActionResponse(
        candidate_id=row.candidate_id,
        action=request.action,
        new_status=row.status,
        analyst_notes=row.analyst_notes,
        message=message,
    )


def _actor_evidence_bundle(session: Session, handle: str) -> dict[str, Any]:
    """Assemble the per-actor evidence mapping the fusion engine expects."""
    actor = session.execute(
        select(Actor).where(Actor.handle == handle)
    ).scalar_one_or_none()
    addresses: list[str] = []
    pgp: list[str] = []
    hostnames: list[str] = []
    timestamps: list[str] = []
    corpora: list[str] = []
    probes: list[dict[str, Any]] = []

    if actor is not None:
        rows = session.execute(
            select(Identifier, ObservationEvent)
            .join(IdentifierLink, IdentifierLink.identifier_id == Identifier.id)
            .join(
                ObservationEvent,
                IdentifierLink.observation_id == ObservationEvent.id,
            )
            .where(IdentifierLink.actor_id == actor.id)
            .order_by(ObservationEvent.observed_at.asc())
        ).all()
        for identifier, observation in rows:
            if identifier.id_type == "BTC_WALLET":
                addresses.append(identifier.value)
            elif identifier.id_type == "PGP_FINGERPRINT":
                pgp.append(identifier.value)
            elif identifier.id_type == "ONION_DOMAIN":
                hostnames.append(identifier.value)
            timestamps.append(observation.observed_at.isoformat())
            if observation.raw_text:
                corpora.append(observation.raw_text)

    profile = session.execute(
        select(ActorProfile).where(ActorProfile.actor_id == actor.id)
    ).scalar_one_or_none() if actor else None

    if profile is not None and isinstance(profile.infra_json, dict):
        stored = profile.infra_json.get("probes")
        if isinstance(stored, list):
            probes = [p for p in stored if isinstance(p, dict)]

    return {
        "handle": handle,
        "addresses": sorted(set(addresses)),
        "pgp_fingerprints": sorted(set(pgp)),
        "hostnames": sorted(set(hostnames)),
        "timestamps": timestamps,
        "corpus": "\n\n".join(corpora),
        "probes": probes,
    }


def _materialise_candidates(session: Session) -> None:
    """Fuse every un-fused actor pair once, persisting results as candidates."""
    handles = [
        row[0]
        for row in session.execute(select(Actor.handle).order_by(Actor.handle.asc())).all()
    ]
    existing = {
        key
        for key in session.execute(
            select(CandidateLinkEntity.source_actor, CandidateLinkEntity.target_actor)
        ).all()
    }

    for i, left in enumerate(handles):
        for right in handles[i + 1 :]:
            pair_key = tuple(sorted((left, right)))
            if pair_key in existing:
                continue
            existing.add(pair_key)

            bundle_a = _actor_evidence_bundle(session, left)
            bundle_b = _actor_evidence_bundle(session, right)

            # Only fuse pairs where at least one engine will actually run.
            shareable = any(
                (
                    bundle_a["addresses"] and bundle_b["addresses"],
                    bundle_a["timestamps"] and bundle_b["timestamps"],
                    bundle_a["corpus"] and bundle_b["corpus"],
                    bundle_a["probes"] and bundle_b["probes"],
                )
            )
            if not shareable:
                continue

            fused = fuse_pair(bundle_a, bundle_b)
            session.add(
                CandidateLinkEntity(
                    candidate_id=str(uuid.uuid4()),
                    source_actor=fused.get("source_actor", left),
                    target_actor=fused.get("target_actor", right),
                    confidence=float(fused.get("confidence", 0.0)),
                    signal_json=fused,
                    contradiction=bool(fused.get("contradiction", False)),
                    contradiction_reasons=list(fused.get("contradiction_reasons", [])),
                    status="PENDING",
                    analyst_notes="",
                )
            )
    session.commit()


# ---------------------------------------------------------------------------
# Infrastructure scanning
# ---------------------------------------------------------------------------
@router.post("/infra/scan", response_model=InfraScanResponse, tags=["infrastructure"])
def infra_scan(
    request: InfraScanRequest, session: Session = Depends(get_session)
) -> InfraScanResponse:
    if not settings.allow_network_probes:
        raise HTTPException(
            status_code=403,
            detail="Network probing is disabled (FORENSIC_ALLOW_NETWORK_PROBES=false)",
        )

    from ..services.infra_prober import (
        _candidate_cert_dirs,
        certificate_corpus,
    )

    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    score = 0.0
    reachable = False

    pages = [request.target] if not request.fetch_pages else [request.target]
    for page in pages:
        probe = probe_target(page, timeout=settings.probe_timeout_seconds)
        status = str(probe.get("status", "unknown"))
        if status == "ok":
            reachable = True

        error = probe.get("error")
        if isinstance(error, dict):
            errors.append(f"{page}: {error.get('code')}: {error.get('message')}")

        http = probe.get("http") if isinstance(probe.get("http"), dict) else {}
        banner = http.get("server_banner") or http.get("powered_by")
        if banner:
            findings.append(
                {
                    "finding_type": "SERVER_BANNER",
                    "title": "Server software disclosure",
                    "severity": "MEDIUM",
                    "confidence": 0.70,
                    "detail": f"Banner header leaked: {banner}",
                    "evidence": {"banner": banner},
                }
            )

        cert = probe.get("certificate") if isinstance(probe.get("certificate"), dict) else {}
        san_hosts = cert.get("san_hosts") or []
        if san_hosts:
            findings.append(
                {
                    "finding_type": "SAN_HOSTS",
                    "title": "TLS SAN exposes additional hostnames",
                    "severity": "HIGH",
                    "confidence": 0.90,
                    "detail": f"Certificate names: {', '.join(map(str, san_hosts))}",
                    "evidence": {"san_hosts": san_hosts, "serial_hex": cert.get("serial_hex")},
                }
            )
        if cert.get("shared_cert_serial"):
            findings.append(
                {
                    "finding_type": "SHARED_CERT_SERIAL",
                    "title": "Certificate serial shared with known fixture infrastructure",
                    "severity": "CRITICAL",
                    "confidence": 0.90,
                    "detail": (
                        f"Serial {cert.get('serial_hex')} appears on more than one "
                        "endpoint, implying shared key material."
                    ),
                    "evidence": {"serial_hex": cert.get("serial_hex")},
                }
            )
        if http.get("status_code") == 200 and any(
            marker in str(http.get("final_url", "")).lower()
            for marker in ("server-status", "server-info", "/.status")
        ):
            findings.append(
                {
                    "finding_type": "STATUS_PAGE_EXPOSED",
                    "title": "Exposed server-status endpoint",
                    "severity": "HIGH",
                    "confidence": 0.70,
                    "detail": f"Status page reachable at {http.get('final_url')}",
                    "evidence": {"final_url": http.get("final_url")},
                }
            )

    score = max((f["confidence"] for f in findings), default=0.0)
    _ = (certificate_corpus, _candidate_cert_dirs)  # referenced for fixture parity

    return InfraScanResponse(
        target=request.target,
        probed_at=dt.datetime.now(UTC),
        reachable=reachable,
        findings=findings,
        score=score,
        errors=errors,
    )


# ---------------------------------------------------------------------------
# Audit / Merkle ledger
# ---------------------------------------------------------------------------
def _audit_status(session: Session) -> AuditVerifyResponse:
    ledger = MerkleLedger(session)
    verified, corrupted = ledger.verify_integrity()
    head = ledger.head()
    return AuditVerifyResponse(
        status=LedgerStatus.VERIFIED if verified else LedgerStatus.TAMPERED,
        verified=verified,
        head_index=head.block_index if head else 0,
        head_hash=head.current_hash if head else GENESIS_HASH,
        corrupted_block_index=corrupted,
        total_blocks=ledger.count(),
        checked_at=dt.datetime.now(UTC),
    )


@router.get("/audit/verify", response_model=AuditVerifyResponse, tags=["audit"])
def audit_verify(session: Session = Depends(get_session)) -> AuditVerifyResponse:
    return _audit_status(session)


@router.get("/audit/ledger", response_model=AuditLedgerResponse, tags=["audit"])
def audit_ledger(
    limit: int = Query(default=100, ge=1, le=500),
    session: Session = Depends(get_session),
) -> AuditLedgerResponse:
    ledger = MerkleLedger(session)
    verified, _corrupted = ledger.verify_integrity()
    head = ledger.head()
    blocks = [
        AuditBlock(
            block_index=b.block_index,
            timestamp=b.timestamp,
            current_hash=b.current_hash,
            previous_hash=b.previous_hash,
            source_url=b.source_url,
            payload_length=len(b.raw_payload),
            tampered=bool(b.tampered),
        )
        for b in ledger.blocks(limit=limit)
    ]
    return AuditLedgerResponse(
        status=LedgerStatus.VERIFIED if verified else LedgerStatus.TAMPERED,
        head_index=head.block_index if head else 0,
        head_hash=head.current_hash if head else GENESIS_HASH,
        blocks=blocks,
    )


@router.post("/audit/tamper", response_model=TamperResponse, tags=["audit"])
def audit_tamper(
    request: TamperRequest, session: Session = Depends(get_session)
) -> TamperResponse:
    ledger = MerkleLedger(session)
    if ledger.head() is None:
        raise HTTPException(status_code=409, detail="Ledger is empty; nothing to tamper.")
    result = ledger.simulate_tamper(request.block_index)
    return TamperResponse(**result)


@router.post("/audit/restore", tags=["audit"])
def audit_restore(
    block_index: int = Query(ge=0), session: Session = Depends(get_session)
) -> dict[str, Any]:
    """Undo a simulated tamper so the demo can be replayed in training."""
    ledger = MerkleLedger(session)
    return ledger.restore_block(block_index)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------
@router.get("/reports/pdf/{actor_handle}", tags=["reports"])
def report_pdf(actor_handle: str, session: Session = Depends(get_session)) -> Response:
    actor = session.execute(
        select(Actor).where(Actor.handle == actor_handle)
    ).scalar_one_or_none()
    if actor is None:
        raise HTTPException(status_code=404, detail=f"Unknown actor: {actor_handle!r}")

    record = build_case_record(session, actor_handle)
    pdf_bytes = render_dossier_pdf(record)
    filename = f"dossier_{actor_handle}_{record['case_id']}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/reports/stix/{actor_handle}", tags=["reports"])
def report_stix(actor_handle: str, session: Session = Depends(get_session)) -> Response:
    actor = session.execute(
        select(Actor).where(Actor.handle == actor_handle)
    ).scalar_one_or_none()
    if actor is None:
        raise HTTPException(status_code=404, detail=f"Unknown actor: {actor_handle!r}")

    bundle = generate_stix_bundle(session, actor_handle)
    return Response(
        content=_json_bytes(bundle),
        media_type="application/stix+json; version=2.1",
        headers={
            "Content-Disposition": f'attachment; filename="stix2_{actor_handle}.json"'
        },
    )


def _json_bytes(payload: dict[str, Any]) -> bytes:
    import json as _json

    return _json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False).encode(
        "utf-8"
    )


__all__ = ["router", "health"]
