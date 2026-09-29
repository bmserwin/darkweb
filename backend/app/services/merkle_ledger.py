"""Append-only SHA-256 chain-of-custody ledger (Merkle-style hash chain).

Hash construction (fixed by the evidentiary specification)::

    H_n = SHA256( H_{n-1} || ISO_TIMESTAMP || RAW_PAYLOAD )

* ``H_0`` chains from the genesis constant, so block 0 is still verifiable.
* Timestamps are stored in UTC ISO-8601 with microsecond precision and are
  derived from the committed row, never from wall clock at verify time.
* The ledger never rewrites a block through the normal API. ``simulate_tamper``
  is the single sanctioned escape hatch and exists solely to demonstrate that
  ``verify_integrity`` detects out-of-band modification.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import threading
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..models.database import session_scope
from ..models.entities import AuditLedgerBlock

GENESIS_HASH = "0" * 64


def utc_timestamp() -> str:
    """Canonical ledger timestamp: UTC, microsecond precision, Z-suffixed."""
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def compute_block_hash(previous_hash: str, timestamp: str, raw_payload: str) -> str:
    """H_n = SHA256(H_{n-1} + ISO_Timestamp + Raw_Payload)."""
    material = f"{previous_hash}{timestamp}{raw_payload}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


class MerkleLedger:
    """Thread-safe, append-only hash chain persisted in SQLite."""

    def __init__(self, session: Optional[Session] = None) -> None:
        self._session = session
        self._ctx = None
        self._lock = threading.Lock()

    # -- context management ------------------------------------------------
    def __enter__(self) -> "MerkleLedger":
        if self._session is None:
            self._ctx = session_scope()
            self._session = self._ctx.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool | None:
        if self._session is None:
            return None
        session, ctx = self._session, getattr(self, "_ctx", None)
        self._session, self._ctx = None, None
        if ctx is not None:
            return ctx.__exit__(exc_type, exc, tb)
        return None

    # -- helpers -----------------------------------------------------------
    def _db(self) -> Session:
        if self._session is None:
            raise RuntimeError("MerkleLedger used outside of a session context")
        return self._session

    def _head(self, session: Session) -> Optional[AuditLedgerBlock]:
        return session.execute(
            select(AuditLedgerBlock)
            .order_by(AuditLedgerBlock.block_index.desc())
            .limit(1)
        ).scalar_one_or_none()

    # -- public API --------------------------------------------------------
    def append(self, raw_payload: str, source_url: str = "") -> AuditLedgerBlock:
        """Anchor ``raw_payload`` as the next block. Returns the persisted block."""
        if raw_payload is None:
            raise ValueError("raw_payload must not be None")

        session = self._db()
        with self._lock:
            head = self._head(session)
            block_index = 0 if head is None else head.block_index + 1
            previous_hash = GENESIS_HASH if head is None else head.current_hash
            timestamp = utc_timestamp()
            current_hash = compute_block_hash(previous_hash, timestamp, raw_payload)

            block = AuditLedgerBlock(
                block_index=block_index,
                timestamp=timestamp,
                raw_payload=raw_payload,
                source_url=source_url or "",
                previous_hash=previous_hash,
                current_hash=current_hash,
                tampered=False,
            )
            session.add(block)
            session.commit()
            session.refresh(block)
            return block

    def head(self) -> Optional[AuditLedgerBlock]:
        return self._head(self._db())

    def count(self) -> int:
        return int(self._db().execute(select(func.count()).select_from(AuditLedgerBlock)).scalar_one())

    def blocks(self, limit: Optional[int] = None) -> list[AuditLedgerBlock]:
        stmt = select(AuditLedgerBlock).order_by(AuditLedgerBlock.block_index.asc())
        if limit is not None:
            stmt = stmt.limit(limit)
        return list(self._db().execute(stmt).scalars())

    def merkle_root(self) -> str:
        """Current head hash: the value embedded in a court-ready dossier."""
        head = self.head()
        return head.current_hash if head is not None else GENESIS_HASH

    # -- integrity ---------------------------------------------------------
    def verify_integrity(self) -> tuple[bool, int | None]:
        """Recompute every block from genesis to head.

        Returns ``(True, None)`` when the chain is intact, otherwise
        ``(False, corrupted_block_index)`` for the *first* block whose recomputed
        hash disagrees with its stored ``current_hash`` or whose
        ``previous_hash`` does not match its predecessor.
        """
        session = self._db()
        blocks = list(
            session.execute(
                select(AuditLedgerBlock).order_by(AuditLedgerBlock.block_index.asc())
            ).scalars()
        )
        if not blocks:
            return True, None

        expected_previous = GENESIS_HASH
        for position, block in enumerate(blocks):
            # 1. Contiguity: no gaps, no reordering.
            if block.block_index != position:
                return False, position

            # 2. Link integrity: predecessor linkage must be exact.
            if block.previous_hash != expected_previous:
                return False, block.block_index

            # 3. Content integrity: recompute over the stored payload.
            recomputed = compute_block_hash(
                block.previous_hash, block.timestamp, block.raw_payload
            )
            if recomputed != block.current_hash:
                return False, block.block_index

            expected_previous = block.current_hash

        return True, None

    def simulate_tamper(self, block_index: int) -> dict:
        """Deliberately corrupt a block's payload *without* rehashing it.

        This is the demonstration path for evidentiary integrity: the row still
        claims its original ``current_hash``, so ``verify_integrity`` immediately
        reports a mismatch at this index.
        """
        session = self._db()
        block = session.execute(
            select(AuditLedgerBlock).where(AuditLedgerBlock.block_index == block_index)
        ).scalar_one_or_none()

        if block is None:
            return {
                "block_index": block_index,
                "tampered": False,
                "verified": True,
                "status": "VERIFIED",
                "corrupted_block_index": None,
                "message": f"Block #{block_index} does not exist; nothing to tamper.",
            }

        original = block.raw_payload
        # Flip one byte: append a marker, guaranteeing the payload changes
        # while leaving the stored hash untouched.
        block.raw_payload = original + "\x00TAMPERED-BY-EXERCISE"
        block.tampered = True
        session.commit()

        verified, corrupted = self.verify_integrity()
        return {
            "block_index": block_index,
            "tampered": True,
            "verified": verified,
            "status": "VERIFIED" if verified else "TAMPERED",
            "corrupted_block_index": corrupted,
            "message": (
                f"Payload of block #{block_index} was modified out-of-band. "
                f"Recomputation now diverges at block #{corrupted}."
                if not verified
                else "Tamper did not affect hash integrity (unexpected)."
            ),
        }

    def restore_block(self, block_index: int) -> dict:
        """Undo a simulated tamper by truncating the injected marker.

        Deliberately *not* a general repair tool: it exists so the demo can be
        replayed in a training session.
        """
        session = self._db()
        block = session.execute(
            select(AuditLedgerBlock).where(AuditLedgerBlock.block_index == block_index)
        ).scalar_one_or_none()
        if block is None:
            return {"restored": False, "message": f"Block #{block_index} not found."}

        marker = "\x00TAMPERED-BY-EXERCISE"
        if block.raw_payload.endswith(marker):
            block.raw_payload = block.raw_payload[: -len(marker)]
            block.tampered = False
            session.commit()

        verified, corrupted = self.verify_integrity()
        return {
            "restored": True,
            "block_index": block_index,
            "verified": verified,
            "corrupted_block_index": corrupted,
        }


def get_ledger(session: Optional[Session] = None) -> MerkleLedger:
    return MerkleLedger(session)


__all__ = [
    "MerkleLedger",
    "GENESIS_HASH",
    "compute_block_hash",
    "get_ledger",
    "settings",
]
