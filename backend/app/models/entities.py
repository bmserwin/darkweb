"""SQLAlchemy ORM entities backing the forensic record of truth.

Design notes
------------
* ``audit_ledger`` is append-only in application logic; the service layer is the
  only writer and refuses to mutate entries outside of ``simulate_tamper``.
* ``identifier`` rows are deduplicated on a natural key so that correlation is
  stable across repeated ingestion of the same evidence.
* Every link table carries the observation timestamp it was derived from, which
  is what makes the graph replayable through time (Phase 4/5 time-scrubber).
"""

from __future__ import annotations

import datetime as dt
from typing import Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Actor(Base):
    """A candidate persona/handle tracked by the platform."""

    __tablename__ = "actor"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    handle: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    actor_type: Mapped[str] = mapped_column(String(32), default="PERSONA", nullable=False)
    profile_json: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)
    first_seen: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    identifiers: Mapped[list["IdentifierLink"]] = relationship(
        back_populates="actor", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<Actor {self.handle!r}>"


class Identifier(Base):
    """A deterministic artifact: PGP key, BTC wallet, handle, onion, IP."""

    __tablename__ = "identifier"
    __table_args__ = (
        UniqueConstraint("id_type", "value", name="uq_identifier_natural_key"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    id_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    meta_json: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)
    first_seen: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )

    links: Mapped[list["IdentifierLink"]] = relationship(
        back_populates="identifier", cascade="all, delete-orphan"
    )


class ObservationEvent(Base):
    """An immutable capture of source material plus extraction results."""

    __tablename__ = "observation_event"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_url: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    platform: Mapped[str] = mapped_column(String(64), default="unknown")
    observed_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    payload_preview: Mapped[str] = mapped_column(Text, default="")
    ledger_block_id: Mapped[int] = mapped_column(
        ForeignKey("audit_ledger.id"), nullable=False
    )
    raw_text: Mapped[str] = mapped_column(Text, default="")

    identifiers: Mapped[list["IdentifierLink"]] = relationship(
        back_populates="observation", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_observation_time_platform", "observed_at", "platform"),
    )


class IdentifierLink(Base):
    """Bipartite edge: an identifier was observed attached to an actor/observation.

    This table *is* the temporal bipartite graph. Replaying it under a
    ``cutoff_time`` reconstructs the graph state at that instant.
    """

    __tablename__ = "identifier_link"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_id: Mapped[Optional[int]] = mapped_column(ForeignKey("actor.id"), index=True)
    identifier_id: Mapped[int] = mapped_column(ForeignKey("identifier.id"), index=True)
    observation_id: Mapped[int] = mapped_column(ForeignKey("observation_event.id"), index=True)
    link_type: Mapped[str] = mapped_column(String(32), default="ASSOCIATED_WITH")
    observed_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    weight: Mapped[float] = mapped_column(Float, default=1.0)
    meta_json: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)

    actor: Mapped[Optional["Actor"]] = relationship(back_populates="identifiers")
    identifier: Mapped["Identifier"] = relationship(back_populates="links")
    observation: Mapped["ObservationEvent"] = relationship(back_populates="identifiers")

    __table_args__ = (
        UniqueConstraint(
            "actor_id", "identifier_id", "observation_id", "link_type",
            name="uq_link_edge",
        ),
    )


class AuditLedgerBlock(Base):
    """Append-only SHA-256 hash chain: the chain of custody.

    ``block_index`` is contiguous and monotonically increasing from 0. The
    integrity verifier relies on both that contiguity and the linkage of
    ``previous_hash`` -> ``current_hash``.
    """

    __tablename__ = "audit_ledger"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    block_index: Mapped[int] = mapped_column(
        Integer, nullable=False, unique=True, index=True
    )
    timestamp: Mapped[str] = mapped_column(String(32), nullable=False)
    raw_payload: Mapped[str] = mapped_column(Text, nullable=False)
    source_url: Mapped[str] = mapped_column(String(512), default="")
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    current_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    tampered: Mapped[bool] = mapped_column(Boolean, default=False)


class CandidateLink(Base):
    """A provisional attribution decision awaiting human adjudication."""

    __tablename__ = "candidate_link"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    candidate_id: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    source_actor: Mapped[str] = mapped_column(String(128), nullable=False)
    target_actor: Mapped[str] = mapped_column(String(128), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    signal_json: Mapped[dict] = mapped_column(JSON, default=dict)
    contradiction: Mapped[bool] = mapped_column(Boolean, default=False)
    contradiction_reasons: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(16), default="PENDING", index=True)
    analyst_notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    adjudicated_at: Mapped[Optional[dt.datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class ActorProfile(Base):
    """Derived analytics: stylometry + circadian, persisted per actor."""

    __tablename__ = "actor_profile"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey("actor.id"), unique=True, index=True)
    stylometry_json: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)
    circadian_json: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)
    infra_json: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)
    crypto_json: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


__all__ = [
    "Actor",
    "Identifier",
    "ObservationEvent",
    "IdentifierLink",
    "AuditLedgerBlock",
    "CandidateLink",
    "ActorProfile",
]
