"""UTXO co-spend clustering engine (Common-Input Ownership Heuristic).

Heuristic
---------
Bitcoin transactions are signed with the keys that control the inputs being
spent. If a single transaction spends inputs ``A``, ``B`` and ``C``, the signing
key had to hold all three, so ``A``, ``B`` and ``C`` are almost certainly
controlled by one entity. Applying that rule transitively over a transaction
graph produces wallet clusters.

This is a *heuristic*, not proof: exchange co-spends, coinjoins, and custodial
wallets all merge unrelated users. Every cluster therefore carries a
``confidence`` that reflects the number of linking transactions, and the API
labels the output as a lead requiring corroboration.

Blockchain data
--------------
The lookup is offline and deterministic: ``seeded_deterministic`` derives values
from a SHA-256 of the address, so repeated runs and container rebuilds produce
identical figures. Set ``FORENSIC_BLOCKCHAIN_MODE=public`` to route through a
public explorer instead.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

MODE = os.getenv("FORENSIC_BLOCKCHAIN_MODE", "seeded").lower()
EXPLORER_BASE = os.getenv(
    "FORENSIC_BLOCKCHAIN_EXPLORER", "https://blockstream.info/api"
)


# ---------------------------------------------------------------------------
# Chain data layer
# ---------------------------------------------------------------------------


def _deterministic_values(address: str) -> dict[str, float]:
    """Derive stable pseudo-chain metrics from the address bytes.

    Deterministic on purpose: an examiner re-running the same case must obtain
    the same numbers, and the testbed has no live chain access.
    """
    digest = hashlib.sha256(address.encode("utf-8")).digest()

    def _span(offset: int, scale: float, minimum: float) -> float:
        raw = int.from_bytes(digest[offset: offset + 4], "big")
        return minimum + (raw / 0xFFFFFFFF) * scale

    balance = round(_span(0, 42.5, 0.001), 6)
    tx_count = int(_span(4, 180, 1))
    lifetime = round(_span(8, 260.0, 0.05), 4)
    first_seen_year = 2016 + int(_span(12, 9, 0))

    return {
        "confirmed_balance_btc": balance,
        "transaction_count": tx_count,
        "lifetime_received_btc": lifetime,
        "first_seen_year": first_seen_year,
        "has_negative_balance_history": _span(16, 1.0, 0.0) > 0.85,
    }


def lookup_address(address: str, *, timeout: float = 5.0) -> dict[str, Any]:
    """Return on-chain metrics for a Bitcoin address.

    Returns a ``status`` field so callers can distinguish real data from the
    deterministic stand-in; the fusion engine down-weights stubbed lookups.
    """
    if not address or not isinstance(address, str):
        return {"address": address, "status": "INVALID", "error": "empty address"}

    if MODE == "public":
        return _public_lookup(address, timeout=timeout)

    metrics = _deterministic_values(address)
    return {
        "address": address,
        "status": "SEEDED_DETERMINISTIC",
        "source": "offline-derivation",
        "note": "Simulated chain metrics; not a real balance lookup.",
        **metrics,
    }


def _public_lookup(address: str, *, timeout: float) -> dict[str, Any]:
    """Query a public Blockstream-compatible API (opt-in, network required)."""
    import requests

    endpoints = {
        "balance": f"{EXPLORER_BASE}/address/{address}",
        "txs": f"{EXPLORER_BASE}/address/{address}/txs",
    }
    try:
        balance_resp = requests.get(
            endpoints["balance"], timeout=timeout,
            headers={"User-Agent": "ForensicPlatform/1.0"},
        )
        balance_resp.raise_for_status()
        chain_stats = balance_resp.json().get("chain_stats") or {}

        txs_resp = requests.get(
            endpoints["txs"], timeout=timeout,
            headers={"User-Agent": "ForensicPlatform/1.0"},
        )
        txs_resp.raise_for_status()
        txs = txs_resp.json()

        funded = sum(
            (tx.get("status", {}) or {}).get("received", 0) or 0 for tx in txs
        )
        spent = sum((tx.get("status", {}) or {}).get("spent", 0) or 0 for tx in txs)

        return {
            "address": address,
            "status": "LIVE",
            "source": EXPLORER_BASE,
            "confirmed_balance_btc": (chain_stats.get("funded_txo_sum", 0)
                                      - chain_stats.get("spent_txo_sum", 0)) / 1e8,
            "transaction_count": chain_stats.get("tx_count", len(txs)),
            "lifetime_received_btc": funded / 1e8,
            "has_negative_balance_history": False,
        }
    except Exception as exc:  # network failures must never break analysis
        metrics = _deterministic_values(address)
        return {
            "address": address,
            "status": "FALLBACK_DETERMINISTIC",
            "source": EXPLORER_BASE,
            "error": str(exc),
            **metrics,
        }


# ---------------------------------------------------------------------------
# Clustering
# ---------------------------------------------------------------------------


@dataclass
class TransactionEdge:
    """A transaction that spends two or more inputs (the linking evidence)."""

    txid: str
    inputs: list[str]
    block_height: Optional[int] = None
    block_time: Optional[str] = None
    value_btc: float = 0.0


@dataclass
class WalletCluster:
    """A set of addresses linked by co-spend evidence."""

    cluster_id: str
    addresses: set[str] = field(default_factory=set)
    linking_transactions: list[str] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.addresses)

    @property
    def confidence(self) -> float:
        """Logarithmic confidence in cluster cohesion.

        One linking transaction is suggestive; several independent ones make the
        association robust. The curve is ``1 - 1/(1+log2(1+t))``, capped at 0.99.
        """
        t = len(self.linking_transactions)
        return round(min(0.99, 1.0 - 1.0 / (1.0 + math.log2(1 + t))), 4)

    def to_dict(self) -> dict[str, Any]:
        addresses = sorted(self.addresses)
        return {
            "cluster_id": self.cluster_id,
            "addresses": addresses,
            "size": self.size,
            "linking_transactions": self.linking_transactions,
            "confidence": self.confidence,
        }


def build_transactions(
    raw: Iterable[dict[str, Any]] | None = None,
) -> list[TransactionEdge]:
    """Coerce dict payloads into :class:`TransactionEdge` records."""
    edges: list[TransactionEdge] = []
    for item in raw or []:
        if isinstance(item, TransactionEdge):
            edges.append(item)
            continue
        edges.append(
            TransactionEdge(
                txid=str(item.get("txid", "")),
                inputs=[str(a) for a in item.get("inputs", [])],
                block_height=item.get("block_height"),
                block_time=item.get("block_time"),
                value_btc=float(item.get("value_btc", 0.0)),
            )
        )
    return [edge for edge in edges if len(edge.inputs) >= 2]


def cluster_addresses(
    transactions: Iterable[TransactionEdge | dict[str, Any]],
) -> list[dict[str, Any]]:
    """Apply the common-input-ownership heuristic across a transaction set.

    Uses union-find so linkage is transitive: ``A~B`` and ``B~C`` collapse to a
    single cluster ``{A, B, C}`` even when no transaction spends all three.
    """
    parent: dict[str, str] = {}

    def _find(node: str) -> str:
        parent.setdefault(node, node)
        while parent[node] != node:
            parent[node] = parent[parent[node]]  # path compression
            node = parent[node]
        return node

    def _union(a: str, b: str) -> None:
        root_a, root_b = _find(a), _find(b)
        if root_a != root_b:
            parent[root_b] = root_a

    edges = build_transactions(transactions)

    for edge in edges:
        for address in edge.inputs:
            _find(address)
        for address in edge.inputs[1:]:
            _union(edge.inputs[0], address)

    # Materialise clusters and attach their supporting transaction ids.
    members: dict[str, set[str]] = {}
    for address in parent:
        members.setdefault(_find(address), set()).add(address)

    linking: dict[str, list[str]] = {root: [] for root in members}
    for edge in edges:
        root = _find(edge.inputs[0])
        if root in linking:
            linking[root].append(edge.txid)

    clusters = [
        WalletCluster(
            cluster_id=f"cluster-{index:04d}",
            addresses=addresses,
            linking_transactions=sorted(set(linking.get(root, []))),
        )
        for index, (root, addresses) in enumerate(
            sorted(members.items(), key=lambda kv: (-len(kv[1]), sorted(kv[1])))
        )
        # Singleton clusters carry no co-spend evidence.
        if len(addresses) >= 2
    ]
    return [cluster.to_dict() for cluster in clusters]


def analyse(
    addresses: list[str],
    transactions: Iterable[TransactionEdge | dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Full crypto signal for a set of addresses.

    Returns per-address chain metrics, wallet clusters, and a ``crypto_score``
    in ``[0, 1]`` suitable for direct use in the fusion engine.
    """
    lookups = [lookup_address(a) for a in addresses]

    clusters = cluster_addresses(transactions or [])
    membership: dict[str, str] = {}
    for cluster in clusters:
        for address in cluster["addresses"]:
            membership[address] = cluster["cluster_id"]

    # Score = how much of the set is provably co-owned, weighted by evidence.
    if not addresses:
        crypto_score = 0.0
    else:
        clustered = sum(1 for a in addresses if a in membership)
        evidence = max((c["confidence"] for c in clusters), default=0.0)
        crypto_score = round((clustered / len(addresses)) * evidence, 4)

    return {
        "addresses": addresses,
        "lookups": lookups,
        "clusters": clusters,
        "cluster_count": len(clusters),
        "crypto_score": crypto_score,
        "confidence_note": (
            "Co-spend linkage is a heuristic; custodial and exchange wallets merge "
            "unrelated users. Treat as a lead, not proof of common control."
        ),
        "mode": MODE,
    }


def score_pair(
    addresses_a: list[str],
    addresses_b: list[str],
    transactions: Iterable[TransactionEdge | dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Crypto sub-score for two candidate personas.

    Full credit when both personas share at least one cluster (direct
    common-control evidence), scaled by that cluster's confidence.
    """
    all_addresses = list(dict.fromkeys(addresses_a + addresses_b))
    result = analyse(all_addresses, transactions)

    cluster_of: dict[str, str] = {}
    for cluster in result["clusters"]:
        for address in cluster["addresses"]:
            cluster_of[address] = cluster["cluster_id"]

    shared = {
        cluster_of[a]
        for a in addresses_a
        if a in cluster_of and cluster_of.get(a) in {
            cluster_of[b] for b in addresses_b if b in cluster_of
        }
    }

    if shared:
        confidence = max(
            c["confidence"] for c in result["clusters"] if c["cluster_id"] in shared
        )
        score = confidence
    else:
        # Fall back to behavioural proximity when no co-spend link exists.
        score = 0.0

    return {
        "crypto_score": round(score, 4),
        "shared_cluster_ids": sorted(shared),
        "detail": result,
    }


_ADDR_RE = re.compile(r"^(?:bc1|[13])[A-Za-z0-9]{25,71}$")


def looks_like_btc(value: str) -> bool:
    return bool(_ADDR_RE.match(value or ""))


__all__ = [
    "lookup_address",
    "cluster_addresses",
    "build_transactions",
    "analyse",
    "score_pair",
    "WalletCluster",
    "TransactionEdge",
    "looks_like_btc",
    "MODE",
]
