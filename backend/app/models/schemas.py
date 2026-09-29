"""Pydantic API contracts for the forensic platform."""

from __future__ import annotations

import datetime as dt
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class IdentifierType(str, Enum):
    PGP_FINGERPRINT = "PGP_FINGERPRINT"
    BTC_WALLET = "BTC_WALLET"
    HANDLE = "HANDLE"
    ONION_DOMAIN = "ONION_DOMAIN"
    CLEARNET_IP = "CLEARNET_IP"


class LedgerStatus(str, Enum):
    GENESIS = "GENESIS"
    VERIFIED = "VERIFIED"
    TAMPERED = "TAMPERED"


# ---------------------------------------------------------------------------
# Core entities
# ---------------------------------------------------------------------------


class Identifier(BaseModel):
    id_type: IdentifierType
    value: str
    confidence: float = 1.0
    meta: dict[str, Any] = Field(default_factory=dict)


class Actor(BaseModel):
    handle: str
    actor_type: str = "PERSONA"
    profile: dict[str, Any] = Field(default_factory=dict)


class ObservationEvent(BaseModel):
    source_url: str
    platform: str = "unknown"
    observed_at: dt.datetime
    payload_preview: str = ""
    raw_text: str = ""
    identifiers: list[Identifier] = Field(default_factory=list)

    @field_validator("observed_at")
    @classmethod
    def _ensure_utc(cls, value: dt.datetime) -> dt.datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=dt.timezone.utc)
        return value.astimezone(dt.timezone.utc)


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------


class IngestRequest(BaseModel):
    text: str = Field(min_length=1, description="Raw dark-web payload to anchor")
    source: str = Field(default="manual://analyst", description="Provenance URL/label")
    platform: str = "manual"
    actor_handle: Optional[str] = Field(
        default=None, description="Optional persona to bind extracted identifiers to"
    )
    observed_at: Optional[dt.datetime] = None


class IngestResponse(BaseModel):
    observation_id: int
    ledger_block: int
    ledger_hash: str
    identifiers: list[Identifier]
    actor_handle: Optional[str] = None
    message: str


# ---------------------------------------------------------------------------
# Infrastructure probing
# ---------------------------------------------------------------------------


class InfraScanRequest(BaseModel):
    target: str = Field(description="URL or bare .onion hostname to probe")
    fetch_pages: bool = True


class InfraFinding(BaseModel):
    finding_type: str
    title: str
    severity: str = "INFO"
    confidence: float = 0.0
    detail: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)


class InfraScanResponse(BaseModel):
    target: str
    probed_at: dt.datetime
    reachable: bool
    findings: list[InfraFinding]
    score: float = 0.0
    errors: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------


class GraphNode(BaseModel):
    id: str
    label: str
    type: str
    group: str
    first_seen: Optional[dt.datetime] = None
    detail: dict[str, Any] = Field(default_factory=dict)


class GraphLink(BaseModel):
    source: str
    target: str
    type: str
    observed_at: dt.datetime
    weight: float = 1.0
    contradiction: bool = False


class GraphSnapshot(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    links: list[GraphLink] = Field(default_factory=list)
    cutoff_time: Optional[dt.datetime] = None
    stats: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Adjudication
# ---------------------------------------------------------------------------


class SignalBreakdown(BaseModel):
    crypto_score: float = 0.0
    infra_score: float = 0.0
    temporal_score: float = 0.0
    stylometry_score: float = 0.0
    weights: dict[str, float] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)


class CandidateLink(BaseModel):
    candidate_id: str
    source_actor: str
    target_actor: str
    confidence: float
    signals: SignalBreakdown
    contradiction: bool = False
    contradiction_reasons: list[str] = Field(default_factory=list)
    status: str = "PENDING"
    analyst_notes: str = ""
    created_at: dt.datetime
    adjudicated_at: Optional[dt.datetime] = None


class AdjudicationActionRequest(BaseModel):
    candidate_id: str
    action: str = Field(pattern="^(APPROVE|REJECT)$")
    analyst_notes: str = ""


class AdjudicationActionResponse(BaseModel):
    candidate_id: str
    action: str
    new_status: str
    analyst_notes: str
    message: str


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


class AuditVerifyResponse(BaseModel):
    status: LedgerStatus
    verified: bool
    head_index: int
    head_hash: str
    corrupted_block_index: Optional[int] = None
    total_blocks: int
    checked_at: dt.datetime


class AuditBlock(BaseModel):
    block_index: int
    timestamp: str
    current_hash: str
    previous_hash: str
    source_url: str
    payload_length: int
    tampered: bool = False


class AuditLedgerResponse(BaseModel):
    status: LedgerStatus
    head_index: int
    head_hash: str
    blocks: list[AuditBlock] = Field(default_factory=list)


class TamperRequest(BaseModel):
    block_index: int = Field(ge=0)


class TamperResponse(BaseModel):
    block_index: int
    tampered: bool
    verified: bool
    status: LedgerStatus
    corrupted_block_index: Optional[int] = None
    message: str


class DossierMeta(BaseModel):
    case_id: str
    generated_by: str
    generated_at: dt.datetime
    classification: str
    merkle_root: str
    actor_handle: str
    confidence: float
