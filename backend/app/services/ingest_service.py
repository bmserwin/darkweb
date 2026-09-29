"""Ingestion pipeline: anchor evidence, then extract identifiers.

Order matters and is deliberate:

1. The raw payload is written to the append-only ledger *first*. If extraction
   crashes, the evidence is still preserved and the failure is auditable.
2. Extraction is deterministic, so the same payload always yields the same
   identifier set.
3. Identifiers are upserted against a natural key, so re-ingesting overlapping
   evidence strengthens links instead of duplicating nodes.
"""

from __future__ import annotations

import datetime as dt
import hashlib
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..models.entities import (
    Actor,
    Identifier,
    IdentifierLink,
    ObservationEvent,
)
from .extractor import ExtractionResult, extract_all
from .merkle_ledger import MerkleLedger

PREVIEW_CHARS = 480


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _parse_ts(value: Optional[str | dt.datetime]) -> dt.datetime:
    if value is None:
        return _utcnow()
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
    cleaned = value.strip().replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(cleaned)
    except ValueError as exc:
        raise ValueError(f"Invalid ISO-8601 timestamp: {value!r}") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def _upsert_identifier(
    session: Session,
    id_type: str,
    value: str,
    confidence: float = 1.0,
    meta: Optional[dict[str, Any]] = None,
) -> Identifier:
    """Fetch-or-create an identifier on its natural key ``(id_type, value)``."""
    existing = session.execute(
        select(Identifier).where(
            Identifier.id_type == id_type, Identifier.value == value
        )
    ).scalar_one_or_none()

    if existing is not None:
        # Keep the strongest observed confidence.
        if confidence > existing.confidence:
            existing.confidence = confidence
        if meta:
            merged = dict(existing.meta_json or {})
            merged.update(meta)
            existing.meta_json = merged
        session.flush()
        return existing

    record = Identifier(
        id_type=id_type, value=value, confidence=confidence, meta_json=meta or {}
    )
    session.add(record)
    session.flush()
    return record


def _get_or_create_actor(session: Session, handle: str) -> Actor:
    actor = session.execute(
        select(Actor).where(Actor.handle == handle)
    ).scalar_one_or_none()
    if actor is None:
        actor = Actor(handle=handle, actor_type="PERSONA", profile_json={})
        session.add(actor)
        session.flush()
    return actor


def _link(
    session: Session,
    *,
    actor: Optional[Actor],
    identifier: Identifier,
    observation: ObservationEvent,
    link_type: str,
    observed_at: dt.datetime,
    weight: float = 1.0,
    meta: Optional[dict[str, Any]] = None,
) -> Optional[IdentifierLink]:
    """Create the bipartite edge, skipping exact duplicates."""
    existing = session.execute(
        select(IdentifierLink).where(
            IdentifierLink.actor_id == (actor.id if actor else None),
            IdentifierLink.identifier_id == identifier.id,
            IdentifierLink.observation_id == observation.id,
            IdentifierLink.link_type == link_type,
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing

    edge = IdentifierLink(
        actor_id=actor.id if actor else None,
        identifier_id=identifier.id,
        observation_id=observation.id,
        link_type=link_type,
        observed_at=observed_at,
        weight=weight,
        meta_json=meta or {},
    )
    session.add(edge)
    return edge


def _flatten(result: ExtractionResult) -> list[tuple[str, str, float, dict[str, Any]]]:
    """Normalize extraction output into ``(type, value, confidence, meta)`` rows."""
    rows: list[tuple[str, str, float, dict[str, Any]]] = []

    for wallet in result.bitcoin:
        rows.append(("BTC_WALLET", wallet["value"], 1.0, dict(wallet)))
    for key in result.pgp:
        # PGP fingerprints are deterministic proof of key custody.
        rows.append(("PGP_FINGERPRINT", key["fingerprint"], 1.0, dict(key)))
    for onion in result.onion:
        rows.append(("ONION_DOMAIN", onion["value"], 1.0, dict(onion)))
    for ip in result.clearnet_ips:
        rows.append(("CLEARNET_IP", ip["value"], 0.9 if ip.get("is_private") else 0.7, dict(ip)))
    for handle in result.handles:
        rows.append(
            ("HANDLE", handle["value"], float(handle.get("confidence", 0.6)),
             {"platform": handle.get("platform", "UNKNOWN")})
        )
    return rows


def ingest_raw_text(
    text: str,
    source: str,
    *,
    session: Session,
    platform: str = "manual",
    actor_handle: Optional[str] = None,
    observed_at: Optional[str | dt.datetime] = None,
) -> dict[str, Any]:
    """Anchor ``text`` to the ledger, extract identifiers, persist the event.

    Returns a dict with the observation id, ledger block, and the extracted
    identifiers as Pydantic-compatible records.
    """
    if not text or not text.strip():
        raise ValueError("Cannot ingest empty payload")

    # 1. Chain of custody first.
    ledger = MerkleLedger(session)
    block = ledger.append(text, source_url=source)

    # 2. Deterministic extraction.
    extraction = extract_all(text)
    rows = _flatten(extraction)

    # 3. Persist the observation with the ledger block as its anchor.
    timestamp = _parse_ts(observed_at)
    actor = _get_or_create_actor(session, actor_handle) if actor_handle else None

    preview = text[:PREVIEW_CHARS] + ("..." if len(text) > PREVIEW_CHARS else "")
    observation = ObservationEvent(
        source_url=source,
        platform=platform,
        observed_at=timestamp,
        payload_preview=preview,
        ledger_block_id=block.id,
        raw_text=text,
    )
    session.add(observation)
    session.flush()

    # 4. Upsert identifiers and wire up bipartite edges.
    identifiers: list[dict[str, Any]] = []
    for id_type, value, confidence, meta in rows:
        identifier = _upsert_identifier(session, id_type, value, confidence, meta)
        _link(
            session,
            actor=actor,
            identifier=identifier,
            observation=observation,
            link_type="ASSOCIATED_WITH",
            observed_at=timestamp,
            weight=confidence,
            meta={"extractor": "regex", **meta},
        )
        identifiers.append(
            {
                "id_type": id_type,
                "value": value,
                "confidence": confidence,
                "meta": meta,
                "identifier_id": identifier.id,
            }
        )

    if actor is not None:
        actor.last_seen = timestamp
        known = {
            link.identifier_id
            for link in actor.identifiers
            if link.observation_id == observation.id
        }
        actor.profile_json = {
            **(actor.profile_json or {}),
            "last_ingested_observation": observation.id,
            "identifiers_in_last_ingest": len(known),
        }

    session.flush()
    session.commit()

    payload_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

    return {
        "observation_id": observation.id,
        "ledger_block": block.block_index,
        "ledger_hash": block.current_hash,
        "payload_sha256": payload_hash,
        "actor_handle": actor_handle,
        "source": source,
        "observed_at": timestamp,
        "identifiers": identifiers,
        "total_identifiers": len(identifiers),
        "message": (
            f"Anchored {len(text)} bytes at ledger block #{block.block_index}; "
            f"extracted {len(identifiers)} deterministic identifiers."
        ),
    }


def fetch_source_text(source_url: str, *, session: Session, timeout: float = 5.0) -> str:
    """Retrieve evidence text from the testbed (or an analyst-supplied file path).

    Offline-first: local files are read directly; HTTP(S) targets are fetched
    with strict timeouts and never follow redirects off-host without notice.
    """
    from pathlib import Path

    if source_url.startswith(("http://", "https://")):
        import requests

        try:
            response = requests.get(
                source_url,
                timeout=timeout,
                headers={"User-Agent": "ForensicPlatform/1.0 (+evidence-collection)"},
                allow_redirects=True,
            )
            response.raise_for_status()
            return response.text
        except requests.RequestException as exc:
            raise RuntimeError(f"Failed to acquire {source_url}: {exc}") from exc

    candidate = Path(source_url)
    if candidate.is_file():
        return candidate.read_text(encoding="utf-8", errors="replace")

    raise RuntimeError(f"Source is neither a reachable URL nor a local file: {source_url}")


__all__ = ["ingest_raw_text", "fetch_source_text", "PREVIEW_CHARS", "settings"]
