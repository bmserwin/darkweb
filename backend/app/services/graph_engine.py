"""Replayable temporal bipartite graph over the forensic record.

What this module is
-------------------
``identifier_link`` rows are the edges of a bipartite graph. One side is
:class:`~app.models.entities.Actor` - the persona a commodity appears under -
and the other is :class:`~app.models.entities.Identifier`, a deterministic
artifact: a BTC address, a PGP fingerprint, an onion, a clearnet IP. Nothing in
the platform owns a graph table, because the graph does not need one: it *is* a
projection of the evidence, and it can be recomputed for any instant.

Why replay matters
------------------
An actor's identifier set is never static. A vendor rotates wallets, an
operator re-keys, a handle is sold to the next tenant, and infrastructure is
abandoned the moment it is burned. Every one of those events changes what the
graph *should* look like, and a graph built from "everything we know today"
silently asserts that a correlation discovered last month always held. This
module therefore takes a ``cutoff_time``: only edges with
``observed_at <= cutoff_time`` participate, and nodes left with no surviving
edge disappear entirely rather than floating as an isolated island. Dragging a
slider from one end of the timeline to the other therefore replays the
investigation, and an analyst can point at the moment a wallet entered or left
an actor's neighbourhood.

Node identity
-------------
Node IDs are stable, human-readable strings, never database primary keys:

* ``actor:<handle>`` for actors, e.g. ``actor:darkfox77``
* ``<type>:<value>`` for identifiers, e.g. ``btc:1A1zP1eP5QGefi...``

``Identifier`` rows are unique on ``(id_type, value)`` and ``actor`` handles are
the analyst-visible name of an actor, so both are stable across re-ingestion of
overlapping evidence. A defensive uniquifier appends ``#<pk>`` to the rare
candidates that would otherwise collide, so the mapping can never merge two
distinct records into one node. The reserved id ``actor:__unattributed__``
represents links with no actor - an identifier that was extracted and anchored
but never bound to a persona. It keeps the graph strictly bipartite (every edge
still runs actor-side to identifier-side) while keeping unattributed artifacts
visible, which is where the interesting ones usually are.

Edge aggregation
----------------
The same actor/identifier pair is usually observed many times, once per
capture. Rendering all of them would hide the structure under duplicates, so
edges are folded per ``(actor, identifier, link_type)``: ``weight`` becomes the
*mean* of the underlying confidences (a sum would make edge weight a function
of how many times we happened to scrape the same forum), ``observed_at``
becomes the most recent observation in the fold, and the underlying row count
is exposed as ``observation_count`` in the node ``detail`` maps, since
``GraphLink`` is a fixed contract and cannot carry the field itself. Any folded
edge whose ``meta_json`` marks a conflict raises ``GraphLink.contradiction``,
which is how the UI distinguishes "seen twice" from "seen twice, contradictorily".

Timezone discipline
-------------------
``DateTime(timezone=True)`` is a promise SQLite does not keep: it stores a naive
string and returns a naive ``datetime``. Every timestamp read back here is
therefore re-tagged as UTC before it is compared or emitted, because the
comparison is what decides whether an edge existed at the cutoff. Emitted
timestamps are ISO-8601 strings with a ``Z`` suffix, which keeps the payload
strictly JSON-serialisable while still validating against
:class:`~app.models.schemas.GraphSnapshot`, whose datetime fields coerce
ISO-8601 text on the way in.

Determinism
-----------
This is forensic software and the graph is rendered by a force-directed
simulation that animates on every redraw: two identical requests must produce
byte-identical payloads or the picture jitters for no reason. Nothing here
consults the wall clock, iterates an unordered collection or uses randomness.
Nodes are sorted by id, links by ``(source, target, observed_at, type)``, and
every float is rounded before it leaves the module. Every number is finite, so
``json.dumps(payload, allow_nan=False)`` always succeeds.
"""

from __future__ import annotations

import datetime as dt
import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Optional

import networkx as nx
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.entities import Actor, Identifier, IdentifierLink
from ..models.schemas import GraphSnapshot

UTC = dt.timezone.utc

#: Node-id namespace prefix for the actor side of the bipartition.
ACTOR_PREFIX = "actor"

#: Handle used for links that carry no actor. ``IdentifierLink.actor_id`` is
#: nullable: an identifier extracted from a payload that named no persona still
#: has to land somewhere, and an extracted-but-unattributed artifact is exactly
#: the kind of lead an analyst wants on the canvas.
UNATTRIBUTED_HANDLE = "__unattributed__"
UNATTRIBUTED_NODE_ID = f"{ACTOR_PREFIX}:{UNATTRIBUTED_HANDLE}"

#: ``GraphNode.type`` values. These two constants *are* the bipartition; every
#: link runs from a node whose ``type`` is ``actor`` to one whose ``type`` is
#: ``identifier``.
NODE_TYPE_ACTOR = "actor"
NODE_TYPE_IDENTIFIER = "identifier"

#: ``IdentifierType`` -> node-id prefix. Short, stable and readable, because the
#: node id travels to the browser and into analyst-facing reports.
IDENTIFIER_PREFIXES: dict[str, str] = {
    "BTC_WALLET": "btc",
    "PGP_FINGERPRINT": "pgp",
    "HANDLE": "handle",
    "ONION_DOMAIN": "onion",
    "CLEARNET_IP": "ip",
}

#: ``meta_json`` keys whose truthiness marks a link as contradictory.
CONTRADICTION_META_KEYS: tuple[str, ...] = (
    "contradiction",
    "contradicts",
    "conflict",
    "conflicting",
    "has_conflict",
)

#: ``meta_json`` keys holding a collection of conflict explanations. A non-empty
#: list is as good a conflict marker as a bare boolean.
CONTRADICTION_REASON_KEYS: tuple[str, ...] = (
    "contradiction_reasons",
    "conflict_reasons",
    "conflicts",
)

#: Entities reported individually by :func:`graph_summary`.
SUMMARY_ENTITY_LIMIT = 10

#: Decimal places every emitted float is rounded to. Python's float addition is
#: not associative, so rounding the aggregates - rather than only the input -
#: is what makes repeated requests bit-identical across runs.
WEIGHT_DECIMALS = 6

#: Guard against pathological ``meta_json`` nesting when sanitising for JSON.
MAX_META_DEPTH = 8

#: Fallback confidence for an identifier row whose stored value is unusable.
DEFAULT_CONFIDENCE = 1.0

_SLUG_RE = re.compile(r"[^a-z0-9]+")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _as_utc(value: Optional[dt.datetime]) -> Optional[dt.datetime]:
    """Tag a naive datetime as UTC; convert an aware one to UTC.

    Naive values *are* UTC in this codebase: ``ingest_service._parse_ts``
    normalises before writing and SQLite drops the offset on the way out, so a
    naive datetime coming back from the driver is already UTC and re-tagging it
    is the only correct reading. Getting this wrong shifts an edge by the
    machine's offset, which silently changes which edges a cutoff admits.
    """
    if value is None:
        return None
    if not isinstance(value, dt.datetime):
        raise TypeError(f"Expected a datetime, got {type(value).__name__}")
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _iso(value: Optional[dt.datetime]) -> Optional[str]:
    """Render a UTC datetime as ISO-8601 with a ``Z`` suffix.

    ISO text rather than a ``datetime`` object is what keeps the payload
    JSON-serialisable; the ``Z`` keeps it unambiguously UTC. ``GraphSnapshot``
    parses either form back into an aware datetime.
    """
    moment = _as_utc(value)
    if moment is None:
        return None
    return moment.isoformat().replace("+00:00", "Z")


def _finite(value: Any, default: float = 0.0) -> float:
    """Coerce any value to a finite float, mapping ``None``/NaN/inf to ``default``."""
    if isinstance(value, bool) or value is None:
        return default
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if math.isfinite(number) else default


def _identifier_prefix(id_type: Any) -> str:
    """Node-id prefix for an identifier type, slugged when unmapped."""
    key = str(id_type or "").strip().upper()
    known = IDENTIFIER_PREFIXES.get(key)
    if known is not None:
        return known
    slug = _SLUG_RE.sub("_", key.lower()).strip("_")
    return slug or "identifier"


def _json_safe(value: Any, depth: int = 0) -> Any:
    """Recursively coerce ``meta_json`` into something ``json.dumps`` accepts.

    ``meta_json`` is a ``JSON`` column, but nothing stops a future writer from
    putting a ``datetime`` or a ``float('nan')`` in it, and the graph payload is
    rendered straight into an HTTP response. Unknown scalars degrade to their
    string form; the depth cap stops a self-referential structure from
    recursing without bound.
    """
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, dt.datetime):
        return _iso(value)
    if isinstance(value, dt.date):
        return value.isoformat()
    if depth >= MAX_META_DEPTH:
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item, depth + 1) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item, depth + 1) for item in value]
    if isinstance(value, (set, frozenset)):
        return [_json_safe(item, depth + 1) for item in sorted(value, key=repr)]
    return str(value)


def _meta_contradiction(meta: Optional[Mapping[str, Any]]) -> bool:
    """True when an edge's ``meta_json`` marks it as conflicting with other evidence."""
    if not isinstance(meta, Mapping):
        return False
    for key in CONTRADICTION_META_KEYS:
        if meta.get(key):
            return True
    for key in CONTRADICTION_REASON_KEYS:
        value = meta.get(key)
        if isinstance(value, (list, tuple, set, frozenset)) and len(value) > 0:
            return True
        if isinstance(value, str) and value.strip():
            return True
    return False


def _unique_node_ids(
    entries: Iterable[tuple[str, tuple[str, int]]],
) -> dict[tuple[str, int], str]:
    """Assign a collision-free node id per ``(kind, primary_key)`` record.

    Candidate ids are natural (``actor:darkfox77``, ``btc:1A1z...``) and unique
    for every well-formed record, so the normal path simply claims the candidate.
    The uniquifier is insurance: should two distinct records ever slug to the
    same candidate - a mixed-case duplicate type, a future identifier type whose
    value collides with an actor handle - the loser is renamed with its primary
    key rather than being silently merged into the winner's node. Iteration is
    over a sorted sequence, so which record keeps the clean id is deterministic.
    """
    mapping: dict[tuple[str, int], str] = {}
    taken: set[str] = set()
    for candidate, key in sorted(entries, key=lambda item: (item[0], item[1])):
        chosen = candidate
        if chosen in taken:
            chosen = f"{candidate}#{key[1]}"
            attempt = 1
            while chosen in taken:
                attempt += 1
                chosen = f"{candidate}#{key[1]}.{attempt}"
        taken.add(chosen)
        mapping[key] = chosen
    return mapping


# ---------------------------------------------------------------------------
# Internal model
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class _RawEdge:
    """One ``identifier_link`` row, normalised and ready to fold."""

    link_id: int
    actor_key: tuple[str, int]
    actor_candidate: str
    identifier_key: tuple[str, int]
    identifier_candidate: str
    link_type: str
    observed_at: dt.datetime
    weight: float
    meta: Mapping[str, Any]
    meta_extra: Mapping[str, Any]
    handle: Optional[str]
    actor_type: Optional[str]
    id_type: Optional[str]
    value: Optional[str]
    confidence: float


@dataclass(slots=True)
class _EdgeAcc:
    """A folded edge between one node pair under one link type."""

    observation_count: int = 0
    total_weight: float = 0.0
    first_observed_at: Optional[dt.datetime] = None
    last_observed_at: Optional[dt.datetime] = None
    contradiction: bool = False

    def absorb(self, edge: _RawEdge) -> None:
        """Fold one observation into this accumulator."""
        self.observation_count += 1
        self.total_weight += edge.weight
        if self.first_observed_at is None or edge.observed_at < self.first_observed_at:
            self.first_observed_at = edge.observed_at
        if self.last_observed_at is None or edge.observed_at > self.last_observed_at:
            self.last_observed_at = edge.observed_at
        if edge.meta and _meta_contradiction(edge.meta):
            self.contradiction = True

    @property
    def mean_weight(self) -> float:
        if self.observation_count <= 0:
            return 0.0
        return round(self.total_weight / self.observation_count, WEIGHT_DECIMALS)


@dataclass(slots=True)
class _NodeAcc:
    """A replayed node plus every edge folded onto it."""

    node_id: str
    node_type: str
    label: str
    group: str
    edges: dict[tuple[str, str], _EdgeAcc] = field(default_factory=dict)
    first_seen: Optional[dt.datetime] = None
    last_seen: Optional[dt.datetime] = None
    handle: Optional[str] = None
    actor_type: Optional[str] = None
    value: Optional[str] = None
    id_type: Optional[str] = None
    confidence: Optional[float] = None
    meta: Mapping[str, Any] = field(default_factory=dict)

    def edge(self, link_type: str, neighbour: str) -> _EdgeAcc:
        key = (link_type, neighbour)
        acc = self.edges.get(key)
        if acc is None:
            acc = _EdgeAcc()
            self.edges[key] = acc
        return acc

    def absorb(self, edge: _RawEdge, neighbour: str) -> None:
        """Record one observation on the node that sits on ``neighbour``'s side."""
        self.edge(edge.link_type, neighbour).absorb(edge)
        if self.first_seen is None or edge.observed_at < self.first_seen:
            self.first_seen = edge.observed_at
        if self.last_seen is None or edge.observed_at > self.last_seen:
            self.last_seen = edge.observed_at

    def induced(self, keep: frozenset[str]) -> "_NodeAcc":
        """A detached copy carrying only the edges that stay inside ``keep``.

        Copying rather than mutating in place matters: a shared accumulator
        would mean walking one ball silently rewrites the whole case model, and
        the next caller over the same session would replay a graph that has
        quietly lost edges. The folded ``_EdgeAcc`` values are read-only once
        assembly is finished, so those are shared; only the membership test is
        re-applied.
        """
        clone = _NodeAcc(
            node_id=self.node_id,
            node_type=self.node_type,
            label=self.label,
            group=self.group,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            handle=self.handle,
            actor_type=self.actor_type,
            value=self.value,
            id_type=self.id_type,
            confidence=self.confidence,
            meta=self.meta,
        )
        clone.edges = {
            key: acc for key, acc in self.edges.items() if key[1] in keep
        }
        return clone


@dataclass(slots=True)
class _GraphModel:
    """The replayed graph: nodes, folded edges and the cutoff that produced them."""

    cutoff_time: Optional[dt.datetime] = None
    nodes: dict[str, _NodeAcc] = field(default_factory=dict)

    @property
    def unattributed_id(self) -> str:
        return UNATTRIBUTED_NODE_ID


# ---------------------------------------------------------------------------
# Query and assembly
# ---------------------------------------------------------------------------
_SELECT = (
    select(
        IdentifierLink.id,
        IdentifierLink.actor_id,
        IdentifierLink.identifier_id,
        IdentifierLink.link_type,
        IdentifierLink.observed_at,
        IdentifierLink.weight,
        IdentifierLink.meta_json,
        Actor.handle,
        Actor.actor_type,
        Identifier.id_type,
        Identifier.value,
        Identifier.confidence,
        Identifier.meta_json,
    )
    .join(Identifier, IdentifierLink.identifier_id == Identifier.id)
    .outerjoin(Actor, IdentifierLink.actor_id == Actor.id)
)


def _raw_edges(rows: Iterable[Any]) -> list[_RawEdge]:
    """Normalise query rows into edges, repairing naive timestamps on the way."""
    edges: list[_RawEdge] = []
    for row in rows:
        (
            link_id,
            actor_id,
            identifier_id,
            link_type,
            observed_at,
            weight,
            link_meta,
            handle,
            actor_type,
            id_type,
            value,
            confidence,
            identifier_meta,
        ) = row

        # A link whose actor row has gone missing is treated as unattributed
        # rather than dropped: the identifier was still seen, and losing the
        # observation would understate both the timeline and the orphan count.
        resolved_handle = str(handle).strip() if handle else ""
        if actor_id is None or not resolved_handle:
            actor_key: tuple[str, int] = ("unattributed", 0)
            actor_candidate = UNATTRIBUTED_NODE_ID
            resolved_handle = None
            actor_type = None
        else:
            actor_key = ("actor", int(actor_id))
            actor_candidate = f"{ACTOR_PREFIX}:{resolved_handle}"

        string_value = str(value) if value is not None else ""
        edges.append(
            _RawEdge(
                link_id=int(link_id),
                actor_key=actor_key,
                actor_candidate=actor_candidate,
                identifier_key=("identifier", int(identifier_id)),
                identifier_candidate=(
                    f"{_identifier_prefix(id_type)}:{string_value}"
                    if string_value
                    else f"{_identifier_prefix(id_type)}:{identifier_id}"
                ),
                link_type=str(link_type or "ASSOCIATED_WITH"),
                # A row with no timestamp is evidence of unknown age; it is
                # anchored at the epoch so it always precedes any cutoff rather
                # than vanishing or throwing.
                observed_at=_as_utc(observed_at) or dt.datetime(1970, 1, 1, tzinfo=UTC),
                weight=_finite(weight, 1.0),
                meta=link_meta if isinstance(link_meta, Mapping) else {},
                handle=resolved_handle,
                actor_type=str(actor_type) if actor_type else None,
                id_type=str(id_type) if id_type else None,
                value=string_value or None,
                confidence=_finite(confidence, DEFAULT_CONFIDENCE),
                meta_extra=identifier_meta if isinstance(identifier_meta, Mapping) else {},
            )
        )
    return edges


def _assemble(
    edges: list[_RawEdge], *, cutoff_time: Optional[dt.datetime]
) -> _GraphModel:
    """Fold raw edges into a bipartite model keyed by stable node ids."""
    model = _GraphModel(cutoff_time=cutoff_time)
    if not edges:
        return model

    actor_entries: list[tuple[str, tuple[str, int]]] = []
    identifier_entries: list[tuple[str, tuple[str, int]]] = []
    seen_actors: set[tuple[str, int]] = set()
    seen_identifiers: set[tuple[str, int]] = set()

    for edge in edges:
        if edge.actor_key not in seen_actors:
            seen_actors.add(edge.actor_key)
            actor_entries.append((edge.actor_candidate, edge.actor_key))
        if edge.identifier_key not in seen_identifiers:
            seen_identifiers.add(edge.identifier_key)
            identifier_entries.append((edge.identifier_candidate, edge.identifier_key))

    actor_ids = _unique_node_ids(actor_entries)
    identifier_ids = _unique_node_ids(identifier_entries)

    def _node(node_id: str, node_type: str, label: str, group: str, edge: _RawEdge) -> _NodeAcc:
        node = model.nodes.get(node_id)
        if node is not None:
            return node
        node = _NodeAcc(node_id=node_id, node_type=node_type, label=label, group=group)
        if node_type == NODE_TYPE_ACTOR:
            node.handle = edge.handle
            node.actor_type = edge.actor_type
        else:
            node.value = edge.value
            node.id_type = edge.id_type
            node.confidence = edge.confidence
            node.meta = edge.meta_extra
        model.nodes[node_id] = node
        return node

    for edge in edges:
        actor_id = actor_ids[edge.actor_key]
        identifier_id = identifier_ids[edge.identifier_key]
        actor_label = edge.handle if edge.handle else UNATTRIBUTED_HANDLE
        identifier_label = edge.value if edge.value else identifier_id

        actor_node = _node(
            actor_id,
            NODE_TYPE_ACTOR,
            actor_label,
            NODE_TYPE_ACTOR,
            edge,
        )
        identifier_node = _node(
            identifier_id,
            NODE_TYPE_IDENTIFIER,
            identifier_label or "",
            edge.id_type or NODE_TYPE_IDENTIFIER,
            edge,
        )

        actor_node.absorb(edge, identifier_id)
        identifier_node.absorb(edge, actor_id)

    return model


def _build_model(
    session: Session, *, cutoff_time: Optional[dt.datetime] = None
) -> _GraphModel:
    """Read every link, apply the cutoff and fold the survivors into a model.

    The cutoff is evaluated in Python rather than pushed into SQL. SQLite
    serialises a tz-aware bind parameter by discarding the offset, so a
    ``WHERE observed_at <= :cutoff`` would compare a UTC wall-clock string
    against stored values that were only ever UTC by ingest convention - an
    assumption the driver itself does not enforce. Filtering after re-tagging
    both sides as UTC makes the comparison mean what it says, and the link table
    for a single case is small enough that the row count does not matter.
    """
    bound = _as_utc(cutoff_time)
    edges = _raw_edges(session.execute(_SELECT).all())
    if bound is not None:
        edges = [edge for edge in edges if edge.observed_at <= bound]
    edges.sort(key=lambda edge: (edge.observed_at, edge.link_id))
    return _assemble(edges, cutoff_time=bound)


# ---------------------------------------------------------------------------
# Derived views
# ---------------------------------------------------------------------------
def _iter_links(
    model: _GraphModel,
) -> list[tuple[str, str, str, _EdgeAcc]]:
    """Every folded edge as ``(source, target, link_type, accumulator)``.

    Only actor-side nodes originate a link, which is what keeps the bipartition
    unambiguous: an identifier-to-actor edge and the actor-to-identifier edge
    describing the same relationship are the same edge, and emitting both would
    double every count in ``stats``.
    """
    rows: list[tuple[str, str, str, _EdgeAcc]] = []
    for node_id in sorted(model.nodes):
        node = model.nodes[node_id]
        if node.node_type != NODE_TYPE_ACTOR:
            continue
        for (link_type, neighbour), acc in node.edges.items():
            rows.append((node_id, neighbour, link_type, acc))
    return rows


def _node_detail(node: _NodeAcc, *, unattributed_id: str) -> dict[str, Any]:
    """Free-form per-node analytics, carried in ``GraphNode.detail``.

    ``GraphLink`` is a fixed contract and cannot hold the fold's
    ``observation_count``, so it is exposed here instead: keyed by neighbour id,
    ``neighbour_observation_counts`` answers "how many times did we actually see
    *this* pairing" for any edge on the canvas.
    """
    edges = node.edges
    observations = sum(edge.observation_count for edge in edges.values())
    total_weight = sum(edge.total_weight for edge in edges.values())
    neighbour_counts: dict[str, int] = {}
    type_counts: dict[str, int] = {}
    for (link_type, neighbour), edge in edges.items():
        neighbour_counts[neighbour] = neighbour_counts.get(neighbour, 0) + edge.observation_count
        type_counts[link_type] = type_counts.get(link_type, 0) + edge.observation_count

    detail: dict[str, Any] = {
        "degree": len(neighbour_counts),
        "weighted_degree": round(total_weight, WEIGHT_DECIMALS),
        "observation_count": observations,
        "link_count": len(edges),
        "total_weight": round(total_weight, WEIGHT_DECIMALS),
        "average_weight": (
            round(total_weight / observations, WEIGHT_DECIMALS) if observations else 0.0
        ),
        "neighbour_observation_counts": dict(sorted(neighbour_counts.items())),
        "link_observation_counts": dict(sorted(type_counts.items())),
        "contradiction": any(edge.contradiction for edge in edges.values()),
        "first_link_at": _iso(node.first_seen),
        "last_link_at": _iso(node.last_seen),
    }

    if node.node_type == NODE_TYPE_ACTOR:
        detail["handle"] = node.handle
        detail["actor_type"] = node.actor_type
        detail["unattributed"] = node.node_id == unattributed_id
    else:
        detail["id_type"] = node.id_type
        detail["value"] = node.value
        detail["confidence"] = (
            round(node.confidence, WEIGHT_DECIMALS)
            if node.confidence is not None
            else None
        )
        detail["meta"] = _json_safe(node.meta)
        detail["orphan"] = bool(neighbour_counts) and set(neighbour_counts) == {
            unattributed_id
        }

    return detail


def _components(model: _GraphModel) -> list[list[str]]:
    """Connected components as sorted node lists, largest first.

    Components are the cheapest honest cluster detection available on a
    bipartite graph: each one is a set of records that share evidence with each
    other and with nothing outside, which is precisely the boundary a cluster
    algorithm would redraw from scratch every run. Ordering is total, so the
    component list is stable.
    """
    graph = nx.Graph()
    graph.add_nodes_from(model.nodes)
    for source, target, _link_type, _acc in _iter_links(model):
        graph.add_edge(source, target)
    blocks = [sorted(component) for component in nx.connected_components(graph)]
    blocks.sort(key=lambda block: (-len(block), block[0] if block else ""))
    return blocks


def _stats(model: _GraphModel) -> dict[str, Any]:
    """Roll-up that makes a snapshot readable without walking it."""
    nodes = model.nodes
    links = _iter_links(model)
    unattributed_id = model.unattributed_id

    node_type_counts: dict[str, int] = {}
    identifier_type_counts: dict[str, int] = {}
    degrees: list[int] = []
    real_actors = 0
    identifiers = 0
    orphans: list[str] = []
    unattributed_present = False

    for node_id in sorted(nodes):
        node = nodes[node_id]
        node_type_counts[node.node_type] = node_type_counts.get(node.node_type, 0) + 1
        if node.node_type == NODE_TYPE_ACTOR:
            if node.node_id == unattributed_id:
                unattributed_present = True
            else:
                real_actors += 1
        else:
            identifiers += 1
            if node.id_type:
                identifier_type_counts[node.id_type] = (
                    identifier_type_counts.get(node.id_type, 0) + 1
                )
            neighbours = {key[1] for key in node.edges}
            if neighbours == {unattributed_id}:
                orphans.append(node_id)
        degrees.append(len({key[1] for key in node.edges}))

    link_type_counts: dict[str, int] = {}
    observations = 0
    total_weight = 0.0
    contradictions = 0
    contradiction_observations = 0
    multi_observation_links = 0
    max_observations = 0
    first_seen: Optional[dt.datetime] = None
    last_seen: Optional[dt.datetime] = None

    for _source, _target, link_type, acc in links:
        link_type_counts[link_type] = link_type_counts.get(link_type, 0) + 1
        observations += acc.observation_count
        total_weight += acc.total_weight
        if acc.contradiction:
            contradictions += 1
            contradiction_observations += acc.observation_count
        if acc.observation_count > 1:
            multi_observation_links += 1
        max_observations = max(max_observations, acc.observation_count)
        if acc.first_observed_at is not None:
            if first_seen is None or acc.first_observed_at < first_seen:
                first_seen = acc.first_observed_at
        if acc.last_observed_at is not None:
            if last_seen is None or acc.last_observed_at > last_seen:
                last_seen = acc.last_observed_at

    node_count = len(nodes)
    link_count = len(links)
    span_hours = (
        round((last_seen - first_seen).total_seconds() / 3600.0, WEIGHT_DECIMALS)
        if first_seen is not None and last_seen is not None
        else 0.0
    )
    components = _components(model)
    average_degree = (
        round(sum(degrees) / node_count, WEIGHT_DECIMALS) if node_count else 0.0
    )
    density = (
        round(2.0 * link_count / (node_count * (node_count - 1)), WEIGHT_DECIMALS)
        if node_count > 1
        else 0.0
    )

    return {
        "node_count": node_count,
        "link_count": link_count,
        "observation_count": observations,
        "node_type_counts": dict(sorted(node_type_counts.items())),
        "identifier_type_counts": dict(sorted(identifier_type_counts.items())),
        "link_type_counts": dict(sorted(link_type_counts.items())),
        "actor_count": real_actors,
        "identifier_count": identifiers,
        "orphan_identifier_count": len(orphans),
        "orphan_identifiers": sorted(orphans),
        "unattributed_node_present": unattributed_present,
        "contradiction_count": contradictions,
        "contradiction_observation_count": contradiction_observations,
        "multi_observation_link_count": multi_observation_links,
        "max_observations_per_link": max_observations,
        "total_weight": round(total_weight, WEIGHT_DECIMALS),
        "average_weight": (
            round(total_weight / observations, WEIGHT_DECIMALS) if observations else 0.0
        ),
        "component_count": len(components),
        "largest_component_size": len(components[0]) if components else 0,
        "average_degree": average_degree,
        "max_degree": max(degrees) if degrees else 0,
        "density": density,
        "first_observed_at": _iso(first_seen),
        "last_observed_at": _iso(last_seen),
        "time_span_hours": span_hours,
        "cutoff_time": _iso(model.cutoff_time),
    }


def _snapshot_dict(model: _GraphModel) -> dict[str, Any]:
    """Render the model as a ``GraphSnapshot``-compatible payload.

    The rendered mapping is validated against the real Pydantic contract before
    it is returned. That costs a few milliseconds on a case-sized graph and buys
    a loud, immediate failure at the source if a field ever drifts out of
    agreement with the API model, instead of a 500 discovered through the UI.
    """
    unattributed_id = model.unattributed_id

    nodes: list[dict[str, Any]] = []
    for node_id in sorted(model.nodes):
        node = model.nodes[node_id]
        nodes.append(
            {
                "id": node.node_id,
                "label": node.label,
                "type": node.node_type,
                "group": node.group,
                "first_seen": _iso(node.first_seen),
                "detail": _node_detail(node, unattributed_id=unattributed_id),
            }
        )

    ordered = sorted(
        _iter_links(model),
        key=lambda row: (row[0], row[1], row[3].last_observed_at or dt.datetime.min.replace(tzinfo=UTC), row[2]),
    )
    links: list[dict[str, Any]] = [
        {
            "source": source,
            "target": target,
            "type": link_type,
            "observed_at": _iso(acc.last_observed_at),
            "weight": acc.mean_weight,
            "contradiction": acc.contradiction,
        }
        for source, target, link_type, acc in ordered
    ]

    payload: dict[str, Any] = {
        "nodes": nodes,
        "links": links,
        "cutoff_time": _iso(model.cutoff_time),
        "stats": _stats(model),
    }

    # Validates and is discarded: the JSON-native payload above is what callers
    # receive, but nothing is allowed to leave this function that the API
    # contract would reject.
    GraphSnapshot(**payload)
    return payload


def _summary_entry(node: _NodeAcc, *, unattributed_id: str) -> dict[str, Any]:
    """Compact per-entity row for :func:`graph_summary`."""
    detail = _node_detail(node, unattributed_id=unattributed_id)
    entry: dict[str, Any] = {
        "node_id": node.node_id,
        "label": node.label,
        "type": node.node_type,
        "group": node.group,
        "neighbour_count": detail["degree"],
        "observation_count": detail["observation_count"],
        "total_weight": detail["total_weight"],
        "average_weight": detail["average_weight"],
        "first_link_at": detail["first_link_at"],
        "last_link_at": detail["last_link_at"],
    }
    if node.node_type == NODE_TYPE_ACTOR:
        entry["actor_type"] = node.actor_type
        entry["unattributed"] = node.node_id == unattributed_id
    else:
        entry["id_type"] = node.id_type
        entry["confidence"] = detail["confidence"]
        entry["orphan"] = detail["orphan"]
    return entry


def _top_entries(
    model: _GraphModel, node_type: str, *, unattributed_id: str
) -> list[dict[str, Any]]:
    """Highest-degree entities of one class, ranked deterministically."""
    entries = [
        _summary_entry(model.nodes[node_id], unattributed_id=unattributed_id)
        for node_id in sorted(model.nodes)
        if model.nodes[node_id].node_type == node_type
    ]
    entries.sort(
        key=lambda entry: (
            -int(entry["neighbour_count"]),
            -int(entry["observation_count"]),
            str(entry["node_id"]),
        )
    )
    return entries[:SUMMARY_ENTITY_LIMIT]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def build_graph(
    session: Session, *, cutoff_time: Optional[dt.datetime] = None
) -> dict[str, Any]:
    """Reconstruct the bipartite graph as it stood at ``cutoff_time``.

    Only links with ``observed_at <= cutoff_time`` are folded in, and a node
    with no surviving link is omitted entirely - replaying the graph before an
    identifier was ever seen must not leave that identifier on the canvas as an
    island. ``cutoff_time`` may be naive (read as UTC, matching the ingest
    pipeline) or carry any offset; both are normalised to UTC before they are
    compared or echoed back.

    Returns a mapping shaped exactly like
    :class:`~app.models.schemas.GraphSnapshot` and validated against it, with
    ISO-8601 ``Z`` timestamps throughout so the payload is directly
    JSON-serialisable. Nodes are sorted by id and links by
    ``(source, target, observed_at, type)``; two calls over unchanged data return
    identical dictionaries.
    """
    return _snapshot_dict(_build_model(session, cutoff_time=cutoff_time))


def graph_summary(
    session: Session, *, cutoff_time: Optional[dt.datetime] = None
) -> dict[str, Any]:
    """Statistics and leaderboards for a replay, without the node/link payload.

    The canvas is the wrong shape for a sidebar list or a header counter: it
    carries every edge to answer questions about one of them. This replays the
    identical graph and returns the same ``stats`` block plus the
    :data:`SUMMARY_ENTITY_LIMIT` most connected actors and identifiers, ranked
    by degree and broken by node id so the ordering never shifts between
    requests.
    """
    model = _build_model(session, cutoff_time=cutoff_time)
    unattributed_id = model.unattributed_id
    return {
        "cutoff_time": _iso(model.cutoff_time),
        "stats": _stats(model),
        "actors": _top_entries(model, NODE_TYPE_ACTOR, unattributed_id=unattributed_id),
        "identifiers": _top_entries(
            model, NODE_TYPE_IDENTIFIER, unattributed_id=unattributed_id
        ),
        "actor_limit": SUMMARY_ENTITY_LIMIT,
    }


def neighbourhood(
    session: Session, node_id: str, *, depth: int = 1
) -> dict[str, Any]:
    """The breadth-first ball of radius ``depth`` around ``node_id``.

    Traversal is a networkx BFS over the replayed graph, so the returned
    sub-graph is closed under its own edges: every link shown has both endpoints
    inside the ball, which is what makes it renderable on its own. Degree
    centrality is recomputed on that induced sub-graph - centrality is a
    property of the neighbourhood you are looking at, not of the whole case.

    ``depth`` is clamped at zero, so a non-positive depth yields the single seed
    node. An unknown ``node_id`` is not an error: the result carries
    ``found: False`` with an empty snapshot, which is what an API endpoint wants
    when an analyst follows a stale link.
    """
    model = _build_model(session)
    unattributed_id = model.unattributed_id
    root = str(node_id)
    radius = max(0, int(depth))

    graph = nx.Graph()
    graph.add_nodes_from(sorted(model.nodes))
    for source, target, _link_type, _acc in _iter_links(model):
        graph.add_edge(source, target)

    if root not in model.nodes:
        return {
            "node_id": root,
            "found": False,
            "depth": radius,
            "snapshot": _snapshot_dict(_GraphModel()),
            "centrality": {},
            "distances": {},
        }

    distances = nx.single_source_shortest_path_length(graph, root, cutoff=radius)
    keep = frozenset(distances)

    # The induced sub-graph carries the ball's nodes *and only* those nodes. A
    # node outside the ball is dropped outright rather than left edge-less, so
    # the snapshot obeys the same isolation rule as a cutoff replay: a node is
    # present because something inside this view depends on it. The seed is the
    # one exception - it is the subject of the query, so it is rendered even at
    # depth 0 where it has no surviving edge at all.
    sub = _GraphModel(cutoff_time=model.cutoff_time)
    for node_id in sorted(keep):
        sub.nodes[node_id] = model.nodes[node_id].induced(keep)

    induced = graph.subgraph(sorted(keep))
    centrality = {
        name: round(float(value), WEIGHT_DECIMALS)
        for name, value in nx.degree_centrality(induced).items()
    }

    return {
        "node_id": root,
        "found": True,
        "depth": radius,
        "snapshot": _snapshot_dict(sub),
        "centrality": {name: centrality[name] for name in sorted(centrality)},
        "distances": {name: int(distances[name]) for name in sorted(distances)},
    }


__all__ = [
    "ACTOR_PREFIX",
    "NODE_TYPE_ACTOR",
    "NODE_TYPE_IDENTIFIER",
    "SUMMARY_ENTITY_LIMIT",
    "UNATTRIBUTED_HANDLE",
    "UNATTRIBUTED_NODE_ID",
    "build_graph",
    "graph_summary",
    "neighbourhood",
]
