"""Tests for the replayable temporal bipartite graph engine.

The engine's whole reason to exist is the claim that a graph reconstructed under
a ``cutoff_time`` is the graph that stood at that instant. So the tests are
organised as a replay ledger: a fixture inserts a small, fully enumerated corpus
of actors, identifiers, observations and links across four distinct instants,
and almost every assertion is a claim about one specific instant.

What is checked, and why each thing outranks a cosmetic one:

1. **Replay fidelity.** Every node that survives a cutoff, and every node that
   must vanish because its last edge fell after it, is asserted by id. An
   identifier left floating as an island is the characteristic bug of a
   time-scrubber: it asserts a correlation that had not happened yet.
2. **Fold arithmetic.** Multi-edges collapse to one link whose weight is the
   mean of the underlying confidences, whose ``observed_at`` is the most recent
   fold member, and whose underlying row count is recoverable from node detail.
3. **Contract integrity.** Every payload validates against the real
   ``GraphSnapshot`` model and survives ``json.dumps(..., allow_nan=False)``,
   because it is handed straight to an HTTP response.
4. **Determinism.** Two calls over unchanged data must return deep-equal
   dictionaries; a force-directed canvas redraws on every request and jitters
   if the payload ordering moves.
5. **Timezone discipline.** SQLite drops ``tzinfo``, so a naive read is
   indistinguishable from a UTC value only if the engine says so out loud.
"""

from __future__ import annotations

import ast
import datetime as dt
import json
import math
import sys
from pathlib import Path
from typing import Any, Iterator

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.models import entities as _entities  # noqa: E402,F401  (registers tables)
from backend.app.models.database import Base  # noqa: E402
from backend.app.models.entities import (  # noqa: E402
    Actor,
    AuditLedgerBlock,
    Identifier,
    IdentifierLink,
    ObservationEvent,
)
from backend.app.models.schemas import GraphSnapshot  # noqa: E402
from backend.app.services import graph_engine  # noqa: E402
from backend.app.services.graph_engine import (  # noqa: E402
    NODE_TYPE_ACTOR,
    NODE_TYPE_IDENTIFIER,
    UNATTRIBUTED_NODE_ID,
    build_graph,
    graph_summary,
    neighbourhood,
)

UTC = dt.timezone.utc

#: Four distinct instants the fixture writes across.
T0 = dt.datetime(2024, 1, 1, tzinfo=UTC)
T1 = dt.datetime(2024, 1, 2, tzinfo=UTC)
T2 = dt.datetime(2024, 1, 3, tzinfo=UTC)
T3 = dt.datetime(2024, 1, 4, tzinfo=UTC)
BEFORE_ALL = dt.datetime(2023, 12, 31, tzinfo=UTC)
AFTER_ALL = dt.datetime(2024, 1, 5, tzinfo=UTC)

# --- Node ids the fixture is expected to produce ---------------------------
ACTOR_FOX = "actor:darkfox77"
ACTOR_GHOST = "actor:ghost_rider"
BTC_FOX = "btc:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
BTC_GHOST = "btc:1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
PGP_FOX = "pgp:AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
ONION = "onion:abc.onion"
HANDLE_FOX = "handle:darkfox77"
IP_ORPHAN = "ip:203.0.113.7"

ALL_NODES = frozenset(
    {ACTOR_FOX, ACTOR_GHOST, UNATTRIBUTED_NODE_ID, BTC_FOX, BTC_GHOST, PGP_FOX, ONION, HANDLE_FOX, IP_ORPHAN}
)

#: json.dumps rejects these outright; a payload containing one is a 500 in
#: production and a silent corruption in a saved report.
JSON_SCALARS = (str, int, float, bool, type(None))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def empty_session(tmp_path: Path) -> Iterator[Session]:
    """A real, fully-migrated SQLite database containing no rows at all."""
    engine = create_engine(
        f"sqlite:///{tmp_path / 'empty.db'}",
        future=True,
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)
    with factory() as session:
        yield session
    engine.dispose()


@pytest.fixture()
def session(empty_session: Session) -> Iterator[Session]:
    """The reference corpus, written across ``T0``..``T3``.

    Ten link rows over four instants produce nine folded edges and nine nodes.
    The structure is chosen so every claim in the suite is checkable by hand:

    * ``darkfox77`` and its four artifacts give a depth-1 ball of five nodes;
    * ``abc.onion`` is shared with ``ghost_rider`` *and* with the reserved
      unattributed node, which is what makes depth-2 reachable at all;
    * ``203.0.113.7`` is attached to nobody, so it is the single orphan and the
      subject of the "disappears when its only edge is cut" test;
    * ``1A1z...`` is observed twice, so it is the only folded multi-edge;
    * ``handle:darkfox77`` carries a contradiction marker;
    * ``abc.onion`` carries a second link type, so per-type counts are non-trivial.
    """
    db = empty_session

    for index, observed_at in enumerate((T0, T1, T2, T3), start=1):
        db.add(
            AuditLedgerBlock(
                block_index=index - 1,
                timestamp=observed_at.isoformat(),
                raw_payload=f"payload-{index}",
                source_url=f"https://example.invalid/{index}",
                previous_hash="0" * 64,
                current_hash=f"{index}" * 64,
            )
        )
    db.flush()

    actors = {
        "darkfox77": Actor(handle="darkfox77", actor_type="PERSONA", profile_json={}),
        "ghost_rider": Actor(handle="ghost_rider", actor_type="PERSONA", profile_json={}),
    }
    for actor in actors.values():
        db.add(actor)

    identifiers = {
        "btc_fox": Identifier(
            id_type="BTC_WALLET", value=BTC_FOX.split(":", 1)[1], confidence=1.0
        ),
        "btc_ghost": Identifier(
            id_type="BTC_WALLET", value=BTC_GHOST.split(":", 1)[1], confidence=1.0
        ),
        "pgp": Identifier(
            id_type="PGP_FINGERPRINT", value=PGP_FOX.split(":", 1)[1], confidence=1.0
        ),
        "onion": Identifier(id_type="ONION_DOMAIN", value="abc.onion", confidence=0.8),
        "handle": Identifier(
            id_type="HANDLE", value="darkfox77", confidence=0.6, meta_json={"platform": "FORUM"}
        ),
        "ip": Identifier(
            id_type="CLEARNET_IP", value="203.0.113.7", confidence=0.7, meta_json={"is_private": False}
        ),
    }
    for identifier in identifiers.values():
        db.add(identifier)

    observations = {
        "o1": ObservationEvent(
            source_url="https://example.invalid/1",
            platform="forum",
            observed_at=T0,
            ledger_block_id=1,
        ),
        "o2": ObservationEvent(
            source_url="https://example.invalid/2",
            platform="forum",
            observed_at=T1,
            ledger_block_id=2,
        ),
        "o3": ObservationEvent(
            source_url="https://example.invalid/3",
            platform="market",
            observed_at=T2,
            ledger_block_id=3,
        ),
        "o4": ObservationEvent(
            source_url="https://example.invalid/4",
            platform="paste",
            observed_at=T3,
            ledger_block_id=4,
        ),
    }
    for observation in observations.values():
        db.add(observation)
    db.flush()

    rows: list[tuple[str | None, str, str, str, dt.datetime, float, dict[str, Any]]] = [
        ("darkfox77", "btc_fox", "o1", "ASSOCIATED_WITH", T0, 0.9, {}),
        ("darkfox77", "pgp", "o1", "ASSOCIATED_WITH", T0, 1.0, {}),
        ("darkfox77", "onion", "o2", "ASSOCIATED_WITH", T1, 0.5, {}),
        ("ghost_rider", "btc_ghost", "o2", "ASSOCIATED_WITH", T1, 1.0, {}),
        ("darkfox77", "btc_fox", "o3", "ASSOCIATED_WITH", T2, 0.7, {}),
        ("darkfox77", "onion", "o3", "SIGNSED", T2, 0.4, {}),
        (None, "ip", "o4", "ASSOCIATED_WITH", T3, 0.8, {}),
        (
            "darkfox77",
            "handle",
            "o4",
            "ASSOCIATED_WITH",
            T3,
            0.6,
            {"contradiction": True, "contradiction_reasons": ["handle sold to another tenant"]},
        ),
        ("ghost_rider", "onion", "o4", "ASSOCIATED_WITH", T3, 0.55, {}),
        (None, "onion", "o4", "ASSOCIATED_WITH", T3, 0.45, {}),
    ]

    for handle, identifier_key, observation_key, link_type, observed_at, weight, meta in rows:
        db.add(
            IdentifierLink(
                actor_id=actors[handle].id if handle else None,
                identifier_id=identifiers[identifier_key].id,
                observation_id=observations[observation_key].id,
                link_type=link_type,
                observed_at=observed_at,
                weight=weight,
                meta_json=meta,
            )
        )

    db.commit()
    yield db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _node_ids(snapshot: dict[str, Any]) -> set[str]:
    return {node["id"] for node in snapshot["nodes"]}


def _node(snapshot: dict[str, Any], node_id: str) -> dict[str, Any]:
    for candidate in snapshot["nodes"]:
        if candidate["id"] == node_id:
            return candidate
    raise AssertionError(f"node {node_id!r} absent from snapshot")


def _link(
    snapshot: dict[str, Any], source: str, target: str, link_type: str
) -> dict[str, Any]:
    for candidate in snapshot["links"]:
        if (
            candidate["source"] == source
            and candidate["target"] == target
            and candidate["type"] == link_type
        ):
            return candidate
    raise AssertionError(f"link {source}->{target} ({link_type}) absent from snapshot")


def _assert_json_safe(value: Any, path: str = "$") -> None:
    """Walk a payload, asserting it is built only from strict JSON scalars.

    Datetimes would raise here, which is the point: the graph payload is
    serialised directly into an HTTP response, so an aware ``datetime`` object
    surviving this module would be a production 500 rather than a test failure.
    """
    if isinstance(value, dict):
        for key, item in value.items():
            assert isinstance(key, str), f"non-string key at {path}: {key!r}"
            _assert_json_safe(item, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _assert_json_safe(item, f"{path}[{index}]")
        return
    assert isinstance(value, JSON_SCALARS), f"non-JSON value at {path}: {type(value).__name__}"
    if isinstance(value, float):
        assert math.isfinite(value), f"non-finite float at {path}: {value!r}"


# ---------------------------------------------------------------------------
# Static guarantees
# ---------------------------------------------------------------------------
def test_module_surface_is_complete_and_documented() -> None:
    source = Path(graph_engine.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    public_functions = {
        node.name
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and not node.name.startswith("_")
    }
    exported = set(graph_engine.__all__)
    assert public_functions <= exported, f"not exported: {sorted(public_functions - exported)}"
    assert {"build_graph", "graph_summary", "neighbourhood"} <= exported

    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and not node.name.startswith("_"):
            assert ast.get_docstring(node), f"{node.name} has no docstring"

    assert graph_engine.__doc__ and len(graph_engine.__doc__) > 200


def test_module_uses_no_nondeterministic_or_ambient_sources() -> None:
    """No randomness, no wall-clock read, no unordered ambient state.

    The graph is re-rendered on every UI poll; a payload that varied between
    identical requests would make the canvas jump for no evidential reason, and
    a payload that varied between *machines* could not be reproduced in a
    report. ``datetime.now`` and ``random`` are banned outright.
    """
    tree = ast.parse(Path(graph_engine.__file__).read_text(encoding="utf-8"))

    banned_modules = {"random", "secrets", "time", "uuid"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in banned_modules, (
                    f"banned import {alias.name!r}"
                )
        elif isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] not in banned_modules, (
                f"banned import from {node.module!r}"
            )
        elif isinstance(node, ast.Attribute) and node.attr in {"now", "utcnow", "today"}:
            assert not isinstance(node.value, ast.Name) or node.value.id != "datetime", (
                f"wall-clock read via datetime.{node.attr}"
            )

    source = Path(graph_engine.__file__).read_text(encoding="utf-8").upper()
    for marker in ("TODO", "FIXME", "XXX", "NOT IMPLEMENTED", "PLACEHOLDER"):
        assert marker not in source, f"{marker} left in graph_engine.py"


def test_networkx_is_the_traversal_engine() -> None:
    """The traversal must be networkx, per the module's stated design."""
    tree = ast.parse(Path(graph_engine.__file__).read_text(encoding="utf-8"))
    nx_calls = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "nx"
    }
    assert "single_source_shortest_path_length" in nx_calls
    assert "degree_centrality" in nx_calls
    assert "connected_components" in nx_calls


# ---------------------------------------------------------------------------
# Empty database
# ---------------------------------------------------------------------------
def test_empty_database_yields_a_valid_empty_snapshot(empty_session: Session) -> None:
    snapshot = build_graph(empty_session)

    assert snapshot["nodes"] == []
    assert snapshot["links"] == []
    assert snapshot["cutoff_time"] is None

    stats = snapshot["stats"]
    assert stats["node_count"] == 0
    assert stats["link_count"] == 0
    assert stats["observation_count"] == 0
    assert stats["actor_count"] == 0
    assert stats["identifier_count"] == 0
    assert stats["orphan_identifier_count"] == 0
    assert stats["orphan_identifiers"] == []
    assert stats["unattributed_node_present"] is False
    assert stats["component_count"] == 0
    assert stats["average_degree"] == 0.0
    assert stats["density"] == 0.0
    assert stats["total_weight"] == 0.0
    assert stats["average_weight"] == 0.0
    assert stats["max_degree"] == 0
    assert stats["first_observed_at"] is None
    assert stats["last_observed_at"] is None
    assert stats["time_span_hours"] == 0.0

    GraphSnapshot(**snapshot)
    json.dumps(snapshot, allow_nan=False)


def test_empty_database_summary_and_neighbourhood(empty_session: Session) -> None:
    summary = graph_summary(empty_session)
    assert summary["actors"] == []
    assert summary["identifiers"] == []
    assert summary["stats"]["node_count"] == 0

    result = neighbourhood(empty_session, "actor:nobody")
    assert result["found"] is False
    assert result["centrality"] == {}
    assert result["distances"] == {}
    assert result["snapshot"]["nodes"] == []
    GraphSnapshot(**result["snapshot"])
    json.dumps(summary, allow_nan=False)
    json.dumps(result, allow_nan=False)


# ---------------------------------------------------------------------------
# Full replay
# ---------------------------------------------------------------------------
def test_full_replay_produces_the_expected_graph(session: Session) -> None:
    snapshot = build_graph(session)

    assert _node_ids(snapshot) == set(ALL_NODES)
    assert len(snapshot["links"]) == 9
    assert snapshot["cutoff_time"] is None

    fox = _node(snapshot, ACTOR_FOX)
    assert fox["label"] == "darkfox77"
    assert fox["type"] == NODE_TYPE_ACTOR
    assert fox["group"] == NODE_TYPE_ACTOR
    assert fox["first_seen"] == "2024-01-01T00:00:00Z"

    ip = _node(snapshot, IP_ORPHAN)
    assert ip["label"] == "203.0.113.7"
    assert ip["type"] == NODE_TYPE_IDENTIFIER
    assert ip["group"] == "CLEARNET_IP"
    assert ip["detail"]["orphan"] is True

    onion = _node(snapshot, ONION)
    assert onion["group"] == "ONION_DOMAIN"
    assert onion["detail"]["orphan"] is False
    # No meta_json was written for this identifier, so the default empty dict is
    # carried through as such rather than dropped or replaced with null.
    assert onion["detail"]["meta"] == {}

    assert _node(snapshot, UNATTRIBUTED_NODE_ID)["label"] == "__unattributed__"
    assert _node(snapshot, UNATTRIBUTED_NODE_ID)["type"] == NODE_TYPE_ACTOR


def test_full_replay_stats_are_complete(session: Session) -> None:
    stats = build_graph(session)["stats"]

    assert stats["node_count"] == 9
    assert stats["link_count"] == 9
    assert stats["observation_count"] == 10

    assert stats["node_type_counts"] == {NODE_TYPE_ACTOR: 3, NODE_TYPE_IDENTIFIER: 6}
    assert stats["actor_count"] == 2
    assert stats["identifier_count"] == 6

    assert stats["link_type_counts"] == {"ASSOCIATED_WITH": 8, "SIGNSED": 1}
    assert stats["identifier_type_counts"] == {
        "BTC_WALLET": 2,
        "PGP_FINGERPRINT": 1,
        "ONION_DOMAIN": 1,
        "HANDLE": 1,
        "CLEARNET_IP": 1,
    }

    assert stats["orphan_identifier_count"] == 1
    assert stats["orphan_identifiers"] == [IP_ORPHAN]
    assert stats["unattributed_node_present"] is True

    assert stats["contradiction_count"] == 1
    assert stats["contradiction_observation_count"] == 1

    assert stats["component_count"] == 1
    assert stats["largest_component_size"] == 9

    assert stats["total_weight"] == 6.9
    assert stats["average_weight"] == 0.69
    assert stats["max_degree"] == 4
    assert stats["density"] == 0.25


def test_stats_time_span_covers_the_whole_corpus(session: Session) -> None:
    stats = build_graph(session)["stats"]
    assert stats["first_observed_at"] == "2024-01-01T00:00:00Z"
    assert stats["last_observed_at"] == "2024-01-04T00:00:00Z"
    assert stats["time_span_hours"] == 72.0


def test_every_link_is_bipartite_actor_to_identifier(session: Session) -> None:
    snapshot = build_graph(session)
    types = {node["id"]: node["type"] for node in snapshot["nodes"]}
    for link in snapshot["links"]:
        assert types[link["source"]] == NODE_TYPE_ACTOR, link
        assert types[link["target"]] == NODE_TYPE_IDENTIFIER, link
        assert link["source"] != link["target"]


# ---------------------------------------------------------------------------
# Replay under a cutoff
# ---------------------------------------------------------------------------
def test_cutoff_before_every_edge_yields_an_empty_graph(session: Session) -> None:
    snapshot = build_graph(session, cutoff_time=BEFORE_ALL)
    assert snapshot["nodes"] == []
    assert snapshot["links"] == []
    assert snapshot["cutoff_time"] == "2023-12-31T00:00:00Z"
    assert snapshot["stats"]["node_count"] == 0
    GraphSnapshot(**snapshot)


def test_cutoff_after_every_edge_matches_the_unbounded_replay(session: Session) -> None:
    bounded = build_graph(session, cutoff_time=AFTER_ALL)
    unbounded = build_graph(session)

    assert _node_ids(bounded) == _node_ids(unbounded)
    assert bounded["links"] == unbounded["links"]
    assert bounded["stats"]["node_count"] == unbounded["stats"]["node_count"]
    assert bounded["stats"]["observation_count"] == 10
    assert bounded["cutoff_time"] == "2024-01-05T00:00:00Z"


def test_cutoff_exactly_on_an_edge_admits_it(session: Session) -> None:
    """The comparison is ``<=``, so an edge is admitted at its own instant."""
    snapshot = build_graph(session, cutoff_time=T0)
    assert _node_ids(snapshot) == {ACTOR_FOX, BTC_FOX, PGP_FOX}
    assert snapshot["stats"]["observation_count"] == 2
    assert snapshot["stats"]["first_observed_at"] == "2024-01-01T00:00:00Z"


def test_midstream_cutoff_excludes_later_edges(session: Session) -> None:
    snapshot = build_graph(session, cutoff_time=T1)

    assert _node_ids(snapshot) == {ACTOR_FOX, ACTOR_GHOST, BTC_FOX, PGP_FOX, ONION, BTC_GHOST}
    assert snapshot["stats"]["observation_count"] == 4
    assert snapshot["stats"]["link_count"] == 4

    # Nothing from T2 or T3 leaked in.
    assert HANDLE_FOX not in _node_ids(snapshot)
    assert IP_ORPHAN not in _node_ids(snapshot)
    assert _link(snapshot, ACTOR_FOX, BTC_FOX, "ASSOCIATED_WITH")["weight"] == 0.9
    assert ONION in _node_ids(snapshot)

    # ghost_rider has not yet reached the onion at T1.
    assert _node(snapshot, ONION)["detail"]["neighbour_observation_counts"] == {
        ACTOR_FOX: 1
    }

    assert snapshot["stats"]["component_count"] == 2
    assert snapshot["stats"]["largest_component_size"] == 4
    assert snapshot["stats"]["orphan_identifier_count"] == 0
    assert snapshot["stats"]["unattributed_node_present"] is False


def test_later_cutoff_adds_back_the_second_observation(session: Session) -> None:
    early = build_graph(session, cutoff_time=T1)
    later = build_graph(session, cutoff_time=T2)

    assert _node_ids(early) == _node_ids(later)
    assert early["stats"]["observation_count"] == 4
    assert later["stats"]["observation_count"] == 6
    assert early["stats"]["multi_observation_link_count"] == 0
    assert later["stats"]["multi_observation_link_count"] == 1
    assert _link(later, ACTOR_FOX, ONION, "SIGNSED")["weight"] == 0.4


def test_orphan_identifier_disappears_when_its_only_edge_is_cut(session: Session) -> None:
    before = build_graph(session, cutoff_time=T2)
    after = build_graph(session, cutoff_time=T3)

    assert IP_ORPHAN in _node_ids(after)
    assert IP_ORPHAN not in _node_ids(before)

    assert before["stats"]["orphan_identifier_count"] == 0
    assert before["stats"]["orphan_identifiers"] == []
    assert UNATTRIBUTED_NODE_ID not in _node_ids(before)

    assert after["stats"]["orphan_identifier_count"] == 1
    assert after["stats"]["orphan_identifiers"] == [IP_ORPHAN]
    assert _node(after, IP_ORPHAN)["detail"]["neighbour_observation_counts"] == {
        UNATTRIBUTED_NODE_ID: 1
    }


def test_actor_disappears_when_its_last_edge_is_cut(session: Session) -> None:
    """The isolation rule applies to the actor side too, not just identifiers."""
    early = build_graph(session, cutoff_time=T0)
    assert ACTOR_FOX in _node_ids(early)
    assert ACTOR_GHOST not in _node_ids(early)
    assert early["stats"]["actor_count"] == 1

    assert all(node["detail"]["degree"] > 0 for node in early["nodes"])


def test_naive_cutoff_is_read_as_utc(session: Session) -> None:
    """A naive cutoff means UTC, matching the ingest pipeline's convention."""
    naive = dt.datetime(2024, 1, 2, 0, 0, 0)
    assert naive.tzinfo is None

    from_naive = build_graph(session, cutoff_time=naive)
    from_aware = build_graph(session, cutoff_time=T1)

    assert from_naive == from_aware
    assert from_naive["cutoff_time"] == "2024-01-02T00:00:00Z"


def test_offset_cutoff_is_normalised_to_utc(session: Session) -> None:
    """+05:00 midnight is 19:00 the previous day in UTC, and must replay as such."""
    offset = dt.timezone(dt.timedelta(hours=5))
    same_instant = dt.datetime(2024, 1, 2, 5, 0, 0, tzinfo=offset)

    snapshot = build_graph(session, cutoff_time=same_instant)
    assert snapshot["cutoff_time"] == "2024-01-02T00:00:00Z"
    assert snapshot["stats"]["observation_count"] == 4
    assert snapshot == build_graph(session, cutoff_time=T1)


def test_cutoff_rejects_non_datetime(session: Session) -> None:
    with pytest.raises(TypeError):
        build_graph(session, cutoff_time="2024-01-02T00:00:00Z")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------
def test_multi_edge_aggregation(session: Session) -> None:
    snapshot = build_graph(session)
    link = _link(snapshot, ACTOR_FOX, BTC_FOX, "ASSOCIATED_WITH")

    # Mean of 0.9 and 0.7, not their sum and not either one of them.
    assert link["weight"] == 0.8
    # Most recent fold member wins, so the link is current as at the cutoff.
    assert link["observed_at"] == "2024-01-03T00:00:00Z"
    assert link["contradiction"] is False

    raw_count = len(
        session.execute(
            select(IdentifierLink).where(IdentifierLink.link_type == "ASSOCIATED_WITH")
        ).scalars().all()
    )
    assert raw_count == 9
    assert len(snapshot["links"]) == 9
    assert snapshot["stats"]["observation_count"] == 10
    assert snapshot["stats"]["multi_observation_link_count"] == 1
    assert snapshot["stats"]["max_observations_per_link"] == 2


def test_aggregation_exposes_observation_count_in_node_detail(session: Session) -> None:
    fox = _node(build_graph(session), ACTOR_FOX)
    btc = _node(build_graph(session), BTC_FOX)

    assert fox["detail"]["neighbour_observation_counts"][BTC_FOX] == 2
    assert btc["detail"]["neighbour_observation_counts"][ACTOR_FOX] == 2
    assert fox["detail"]["observation_count"] == 6
    assert btc["detail"]["observation_count"] == 2
    assert fox["detail"]["degree"] == 4
    # 0.9 + 0.7 (btc) + 1.0 (pgp) + 0.5 + 0.4 (onion) + 0.6 (handle)
    assert fox["detail"]["total_weight"] == 4.1
    assert fox["detail"]["average_weight"] == round(4.1 / 6, 6)


def test_same_pair_under_two_link_types_stays_two_links(session: Session) -> None:
    """Different link types are different claims and must not be folded together."""
    snapshot = build_graph(session)
    association = _link(snapshot, ACTOR_FOX, ONION, "ASSOCIATED_WITH")
    signature = _link(snapshot, ACTOR_FOX, ONION, "SIGNSED")

    assert association["weight"] == 0.5
    assert signature["weight"] == 0.4
    assert association["source"] == signature["source"]
    assert association["target"] == signature["target"]

    detail = _node(snapshot, ONION)["detail"]
    # Node detail is a roll-up over the whole node, so the onion's counts span
    # every actor attached to it - not just the pair this test is about.
    assert detail["link_observation_counts"] == {"ASSOCIATED_WITH": 3, "SIGNSED": 1}
    assert detail["neighbour_observation_counts"] == {
        ACTOR_FOX: 2,  # both link types, counted as two separate claims
        ACTOR_GHOST: 1,
        UNATTRIBUTED_NODE_ID: 1,
    }
    assert detail["degree"] == 3


def test_contradiction_is_raised_from_meta_json(session: Session) -> None:
    snapshot = build_graph(session)
    contradicted = _link(snapshot, ACTOR_FOX, HANDLE_FOX, "ASSOCIATED_WITH")
    clean = _link(snapshot, ACTOR_FOX, BTC_FOX, "ASSOCIATED_WITH")

    assert contradicted["contradiction"] is True
    assert clean["contradiction"] is False
    assert _node(snapshot, HANDLE_FOX)["detail"]["contradiction"] is True
    assert _node(snapshot, BTC_FOX)["detail"]["contradiction"] is False
    assert snapshot["stats"]["contradiction_count"] == 1


def test_contradiction_detected_from_a_bare_reason_list(session: Session) -> None:
    """A non-empty ``contradiction_reasons`` list is as good a marker as a flag."""
    identifier = Identifier(id_type="HANDLE", value="ghost_rider")
    observation = session.execute(
        select(ObservationEvent).order_by(ObservationEvent.id)
    ).scalars().first()
    actor = session.execute(select(Actor).where(Actor.handle == "ghost_rider")).scalars().one()
    session.add(identifier)
    session.flush()
    session.add(
        IdentifierLink(
            actor_id=actor.id,
            identifier_id=identifier.id,
            observation_id=observation.id,
            link_type="ASSOCIATED_WITH",
            observed_at=T3,
            weight=1.0,
            meta_json={"contradiction_reasons": ["claimed by two personas"]},
        )
    )
    session.commit()

    link = _link(build_graph(session), ACTOR_GHOST, "handle:ghost_rider", "ASSOCIATED_WITH")
    assert link["contradiction"] is True


def test_non_conflicting_meta_json_does_not_flag(session: Session) -> None:
    assert _node(build_graph(session), ONION)["detail"]["contradiction"] is False
    assert build_graph(session)["stats"]["contradiction_observation_count"] == 1


# ---------------------------------------------------------------------------
# Naive timestamps
# ---------------------------------------------------------------------------
def test_sqlite_reads_back_naive_timestamps_and_engine_retags_them(
    session: Session,
) -> None:
    """Pin the driver behaviour the engine has to defend against.

    ``DateTime(timezone=True)`` is a promise SQLite does not keep: the value
    round-trips without ``tzinfo``. If the engine tagged it with the *local*
    zone instead of UTC, the offending edge would drift by the machine's
    offset and a cutoff would admit or drop the wrong rows.
    """
    stored = session.execute(
        select(IdentifierLink.observed_at)
        .join(Identifier, IdentifierLink.identifier_id == Identifier.id)
        .where(Identifier.value == "abc.onion", IdentifierLink.link_type == "SIGNSED")
    ).scalars().one()
    assert stored.tzinfo is None, "fixture assumption: SQLite strips tzinfo"

    snapshot = build_graph(session)
    link = _link(snapshot, ACTOR_FOX, ONION, "SIGNSED")
    assert link["observed_at"] == "2024-01-03T00:00:00Z"
    assert _node(snapshot, ONION)["first_seen"] == "2024-01-02T00:00:00Z"


def test_rows_inserted_with_naive_datetimes_are_treated_as_utc(session: Session) -> None:
    observation = session.execute(select(ObservationEvent)).scalars().first()
    actor = session.execute(select(Actor).where(Actor.handle == "darkfox77")).scalars().one()
    identifier = Identifier(id_type="ONION_DOMAIN", value="naive.onion")
    session.add(identifier)
    session.flush()
    session.add(
        IdentifierLink(
            actor_id=actor.id,
            identifier_id=identifier.id,
            observation_id=observation.id,
            link_type="ASSOCIATED_WITH",
            observed_at=dt.datetime(2024, 1, 5, 6, 30, 0),  # deliberately naive
            weight=1.0,
            meta_json={},
        )
    )
    session.commit()

    snapshot = build_graph(session)
    node = _node(snapshot, "onion:naive.onion")
    assert node["first_seen"] == "2024-01-05T06:30:00Z"

    # And the cutoff sees exactly that instant: excluded one second early,
    # admitted on the second, and absent from the T3 replay that precedes it.
    one_second_early = dt.datetime(2024, 1, 5, 6, 29, 59, tzinfo=UTC)
    assert "onion:naive.onion" not in _node_ids(build_graph(session, cutoff_time=one_second_early))
    on_the_second = dt.datetime(2024, 1, 5, 6, 30, 0, tzinfo=UTC)
    assert "onion:naive.onion" in _node_ids(build_graph(session, cutoff_time=on_the_second))
    assert "onion:naive.onion" not in _node_ids(build_graph(session, cutoff_time=T3))


# ---------------------------------------------------------------------------
# Neighbourhood
# ---------------------------------------------------------------------------
def test_neighbourhood_depth_one(session: Session) -> None:
    result = neighbourhood(session, ACTOR_FOX, depth=1)

    assert result["found"] is True
    assert result["node_id"] == ACTOR_FOX
    assert result["depth"] == 1

    snapshot = result["snapshot"]
    assert _node_ids(snapshot) == {ACTOR_FOX, BTC_FOX, PGP_FOX, ONION, HANDLE_FOX}
    assert len(snapshot["links"]) == 5
    assert result["distances"] == {
        ACTOR_FOX: 0,
        BTC_FOX: 1,
        PGP_FOX: 1,
        ONION: 1,
        HANDLE_FOX: 1,
    }

    # ghost_rider sits three hops away through the onion, so it is out.
    assert ACTOR_GHOST not in _node_ids(snapshot)
    assert BTC_GHOST not in _node_ids(snapshot)
    assert UNATTRIBUTED_NODE_ID not in _node_ids(snapshot)


def test_neighbourhood_depth_two(session: Session) -> None:
    result = neighbourhood(session, ACTOR_FOX, depth=2)
    snapshot = result["snapshot"]

    assert _node_ids(snapshot) == {
        ACTOR_FOX,
        BTC_FOX,
        PGP_FOX,
        ONION,
        HANDLE_FOX,
        ACTOR_GHOST,
        UNATTRIBUTED_NODE_ID,
    }
    assert result["distances"] == {
        ACTOR_FOX: 0,
        BTC_FOX: 1,
        PGP_FOX: 1,
        ONION: 1,
        HANDLE_FOX: 1,
        ACTOR_GHOST: 2,
        UNATTRIBUTED_NODE_ID: 2,
    }
    # Reached through the shared onion, one hop further out.
    assert ONION in _node_ids(snapshot)
    assert len(snapshot["links"]) == 7


def test_neighbourhood_depth_one_is_a_strict_subset_of_depth_two(session: Session) -> None:
    shallow = _node_ids(neighbourhood(session, ACTOR_FOX, depth=1)["snapshot"])
    deep = _node_ids(neighbourhood(session, ACTOR_FOX, depth=2)["snapshot"])
    assert shallow < deep


def test_neighbourhood_depth_zero_is_the_seed_alone(session: Session) -> None:
    result = neighbourhood(session, ACTOR_FOX, depth=0)
    assert _node_ids(result["snapshot"]) == {ACTOR_FOX}
    assert result["snapshot"]["links"] == []
    assert result["distances"] == {ACTOR_FOX: 0}


def test_negative_depth_is_clamped(session: Session) -> None:
    result = neighbourhood(session, ACTOR_FOX, depth=-5)
    assert result["depth"] == 0
    assert _node_ids(result["snapshot"]) == {ACTOR_FOX}


def test_neighbourhood_from_an_identifier_reaches_the_actor_side(session: Session) -> None:
    result = neighbourhood(session, ONION, depth=1)
    assert _node_ids(result["snapshot"]) == {ONION, ACTOR_FOX, ACTOR_GHOST, UNATTRIBUTED_NODE_ID}
    assert result["distances"][ONION] == 0
    assert all(distance == 1 for node, distance in result["distances"].items() if node != ONION)


def test_neighbourhood_subgraph_is_closed_under_its_own_edges(session: Session) -> None:
    """A sub-snapshot must render alone: no link may dangle off the canvas."""
    for depth in (0, 1, 2, 3):
        snapshot = neighbourhood(session, ACTOR_FOX, depth=depth)["snapshot"]
        present = _node_ids(snapshot)
        for link in snapshot["links"]:
            assert link["source"] in present, (depth, link)
            assert link["target"] in present, (depth, link)


def test_neighbourhood_never_renders_a_node_it_did_not_reach(session: Session) -> None:
    """A ball is a strict subset of the case, and stays a subset at every depth.

    The isolation rule that governs a cutoff replay - a node is present only
    while something holds an edge to it - has to hold for a ball too. Trimming
    the ball's *edges* without trimming its *nodes* would render a full-page
    constellation of edgeless nodes, which is exactly what this pins shut.
    """
    for seed in (ACTOR_FOX, ONION, IP_ORPHAN, UNATTRIBUTED_NODE_ID):
        for depth in (0, 1, 2, 3):
            snapshot = neighbourhood(session, seed, depth=depth)["snapshot"]
            rendered = _node_ids(snapshot)
            whole = _node_ids(build_graph(session))

            assert rendered <= whole, (seed, depth, rendered - whole)
            assert len(rendered) == snapshot["stats"]["node_count"], (seed, depth)
            # The seed is the subject of the query, so it renders even alone.
            assert seed in rendered, (seed, depth)


def test_neighbourhood_does_not_mutate_the_case_model(session: Session) -> None:
    """Walking a ball must leave the whole-case replay untouched.

    Folding shares accumulator objects between the case model and its balls, so
    a ball that trimmed edges in place would silently rewrite the case: a second
    request on the same session would return a graph that has lost edges. Two
    balls and a full replay, in that order, have to agree with a clean one.
    """
    clean = build_graph(session)

    for seed, depth in ((ACTOR_FOX, 0), (ONION, 2), (BTC_GHOST, 1), (ACTOR_FOX, 3)):
        neighbourhood(session, seed, depth=depth)

    after = build_graph(session)
    assert after == clean
    assert after["stats"]["node_count"] == 9
    assert after["stats"]["link_count"] == 9
    assert len(after["links"]) == 9


def test_neighbourhood_stats_describe_the_subgraph_not_the_case(session: Session) -> None:
    whole = build_graph(session)["stats"]
    ball = neighbourhood(session, ACTOR_FOX, depth=1)["snapshot"]["stats"]

    assert ball["node_count"] == 5
    assert ball["observation_count"] == 6
    assert whole["node_count"] == 9
    assert whole["observation_count"] == 10
    assert ball["link_count"] == 5
    assert ball["max_degree"] == 4
    assert ball["component_count"] == 1


def test_neighbourhood_centrality_is_present_and_normalised(session: Session) -> None:
    result = neighbourhood(session, ACTOR_FOX, depth=1)
    centrality = result["centrality"]

    assert set(centrality) == _node_ids(result["snapshot"])
    assert all(0.0 <= value <= 1.0 for value in centrality.values())
    assert centrality[ACTOR_FOX] == 1.0
    assert centrality[BTC_FOX] == 0.25
    assert centrality[ONION] == 0.25


def test_neighbourhood_centrality_reflects_the_induced_subgraph(session: Session) -> None:
    """Centrality is a property of the neighbourhood shown, not of the case."""
    centrality = neighbourhood(session, ACTOR_FOX, depth=2)["centrality"]

    # Seven nodes, so the denominator is six: the seed holds degree four and the
    # onion - shared with two actors - holds degree three.
    assert centrality[ACTOR_FOX] == round(4 / 6, 6)
    assert centrality[ONION] == round(3 / 6, 6)
    assert centrality[BTC_FOX] == round(1 / 6, 6)


def test_neighbourhood_singleton_centrality_is_one(session: Session) -> None:
    """A one-node graph has no denominator; networkx reports 1.0 and so must we."""
    result = neighbourhood(session, BTC_GHOST, depth=0)
    assert result["centrality"] == {BTC_GHOST: 1.0}


def test_neighbourhood_unknown_node_is_reported_not_raised(session: Session) -> None:
    result = neighbourhood(session, "actor:does_not_exist", depth=2)

    assert result["found"] is False
    assert result["node_id"] == "actor:does_not_exist"
    assert result["depth"] == 2
    assert result["snapshot"]["nodes"] == []
    assert result["snapshot"]["links"] == []
    assert result["centrality"] == {}
    assert result["distances"] == {}
    GraphSnapshot(**result["snapshot"])
    json.dumps(result, allow_nan=False)


def test_neighbourhood_accepts_the_integer_form_of_a_node_id(session: Session) -> None:
    result = neighbourhood(session, BTC_FOX)
    assert result["found"] is True
    assert result["distances"][BTC_FOX] == 0


def test_neighbourhood_on_an_empty_database_is_empty(empty_session: Session) -> None:
    result = neighbourhood(empty_session, ACTOR_FOX, depth=3)
    assert result["found"] is False
    assert result["snapshot"]["nodes"] == []


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
def test_graph_summary_reports_stats_and_leaderboards(session: Session) -> None:
    summary = graph_summary(session)

    assert summary["cutoff_time"] is None
    assert summary["stats"] == build_graph(session)["stats"]
    assert summary["actor_limit"] == graph_engine.SUMMARY_ENTITY_LIMIT

    assert [entry["node_id"] for entry in summary["actors"]] == [
        ACTOR_FOX,
        UNATTRIBUTED_NODE_ID,
        ACTOR_GHOST,
    ]
    assert [entry["node_id"] for entry in summary["identifiers"]] == [
        ONION,
        BTC_FOX,
        BTC_GHOST,
        HANDLE_FOX,
        IP_ORPHAN,
        PGP_FOX,
    ]

    fox = summary["actors"][0]
    assert fox["label"] == "darkfox77"
    assert fox["neighbour_count"] == 4
    assert fox["observation_count"] == 6
    assert fox["actor_type"] == "PERSONA"
    assert fox["unattributed"] is False

    assert summary["identifiers"][0]["orphan"] is False
    assert summary["identifiers"][4]["orphan"] is True


def test_graph_summary_honours_a_cutoff(session: Session) -> None:
    summary = graph_summary(session, cutoff_time=T1)

    assert summary["cutoff_time"] == "2024-01-02T00:00:00Z"
    assert summary["stats"]["observation_count"] == 4
    assert summary["stats"]["orphan_identifier_count"] == 0
    assert [entry["node_id"] for entry in summary["actors"]] == [ACTOR_FOX, ACTOR_GHOST]
    assert all(entry["node_id"] != UNATTRIBUTED_NODE_ID for entry in summary["actors"])
    assert all(entry["node_id"] != IP_ORPHAN for entry in summary["identifiers"])


def test_graph_summary_leaderboard_is_capped(session: Session) -> None:
    """The cap must actually bind once a case exceeds it, not just be declared."""
    for index in range(graph_engine.SUMMARY_ENTITY_LIMIT + 4):
        actor = Actor(handle=f"filler{index:02d}", actor_type="PERSONA")
        identifier = Identifier(id_type="HANDLE", value=f"filler{index:02d}")
        session.add_all([actor, identifier])
        session.flush()
        session.add(
            IdentifierLink(
                actor_id=actor.id,
                identifier_id=identifier.id,
                observation_id=1,
                link_type="ASSOCIATED_WITH",
                observed_at=T3,
                weight=1.0,
                meta_json={},
            )
        )
    session.commit()

    summary = graph_summary(session)
    assert len(summary["actors"]) == graph_engine.SUMMARY_ENTITY_LIMIT
    assert len(summary["identifiers"]) == graph_engine.SUMMARY_ENTITY_LIMIT
    assert ACTOR_FOX in {entry["node_id"] for entry in summary["actors"]}


# ---------------------------------------------------------------------------
# Contract: validation, JSON safety, ordering, determinism
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "cutoff",
    [None, BEFORE_ALL, T0, T1, T2, T3, AFTER_ALL],
    ids=["none", "before", "t0", "t1", "t2", "t3", "after"],
)
def test_every_payload_validates_as_a_graph_snapshot(
    session: Session, cutoff: dt.datetime | None
) -> None:
    payload = build_graph(session, cutoff_time=cutoff)
    model = GraphSnapshot(**payload)

    assert len(model.nodes) == len(payload["nodes"])
    assert len(model.links) == len(payload["links"])
    assert model.cutoff_time is None or model.cutoff_time.tzinfo is not None
    for node in model.nodes:
        assert node.id and node.label
        assert node.type in {NODE_TYPE_ACTOR, NODE_TYPE_IDENTIFIER}
        assert isinstance(node.detail, dict)
        if node.first_seen is not None:
            assert node.first_seen.tzinfo is not None
    for link in model.links:
        assert link.observed_at.tzinfo is not None
        assert math.isfinite(link.weight)
        assert isinstance(link.contradiction, bool)


def test_every_payload_is_strictly_json_serialisable(session: Session) -> None:
    """No NaN, no infinity, no datetime, no ORM object: ever."""
    payloads = [
        build_graph(session),
        build_graph(session, cutoff_time=T2),
        graph_summary(session),
        neighbourhood(session, ACTOR_FOX, depth=1),
        neighbourhood(session, ONION, depth=2),
        neighbourhood(session, "actor:missing"),
    ]
    for payload in payloads:
        _assert_json_safe(payload)
        round_tripped = json.loads(json.dumps(payload, allow_nan=False))
        assert round_tripped == payload


def test_serialised_timestamps_are_utc_marked(session: Session) -> None:
    """Every timestamp is ISO-8601 with an explicit ``Z``, never a bare offset."""
    snapshot = build_graph(session)
    timestamps = [node["first_seen"] for node in snapshot["nodes"]]
    timestamps += [link["observed_at"] for link in snapshot["links"]]
    timestamps.append(snapshot["stats"]["first_observed_at"])
    timestamps.append(snapshot["stats"]["last_observed_at"])

    assert all(value is None or value.endswith("Z") for value in timestamps)
    assert all("+" not in value for value in timestamps if value)


def test_nodes_are_sorted_by_id(session: Session) -> None:
    ids = [node["id"] for node in build_graph(session)["nodes"]]
    assert ids == sorted(ids)


def test_links_are_sorted_and_fully_deterministic(session: Session) -> None:
    links = build_graph(session)["links"]
    keys = [(link["source"], link["target"], link["observed_at"], link["type"]) for link in links]
    assert keys == sorted(keys)


def test_repeated_calls_are_deep_equal(session: Session) -> None:
    assert build_graph(session) == build_graph(session)
    assert build_graph(session, cutoff_time=T2) == build_graph(session, cutoff_time=T2)
    assert graph_summary(session) == graph_summary(session)
    assert neighbourhood(session, ACTOR_FOX, depth=2) == neighbourhood(session, ACTOR_FOX, depth=2)


def test_output_is_independent_of_insertion_order(session: Session, empty_session: Session) -> None:
    """Same corpus, reversed insert order, identical bytes out.

    Primary keys are assigned in insertion order, so anything that leaked a
    primary key - or sorted by rowid - would surface here.
    """
    reference = build_graph(session)
    links = session.execute(select(IdentifierLink)).scalars().all()
    session.query(IdentifierLink).delete()
    session.commit()
    for link in reversed(links):
        session.merge(
            IdentifierLink(
                id=link.id,
                actor_id=link.actor_id,
                identifier_id=link.identifier_id,
                observation_id=link.observation_id,
                link_type=link.link_type,
                observed_at=link.observed_at,
                weight=link.weight,
                meta_json=link.meta_json,
            )
        )
    session.commit()

    replayed = build_graph(session)
    assert _node_ids(replayed) == _node_ids(reference)
    assert replayed["links"] == reference["links"]
    assert replayed["stats"] == reference["stats"]
    assert empty_session is not None


def test_no_sqlalchemy_objects_leak_into_the_payload(session: Session) -> None:
    snapshot = build_graph(session)
    serialised = json.dumps(snapshot, allow_nan=False)
    for forbidden in ("Actor(", "Identifier(", "IdentifierLink(", "SQLAlchemy", "object at 0x"):
        assert forbidden not in serialised


def test_identifier_meta_is_sanitised_for_json(session: Session) -> None:
    """Hostile ``meta_json`` still produces a serialisable payload.

    ``NaN`` and ``Infinity`` survive a SQLite ``JSON`` round trip verbatim -
    ``json.dumps`` emits them as bare tokens - and ``json.dumps(...,
    allow_nan=False)``, which the API layer uses, rejects them on the way out.
    Anything the graph did not neutralise would therefore be a 500.
    """
    identifier = Identifier(
        id_type="HANDLE",
        value="sanitised",
        meta_json={"nested": {"float": float("nan"), "list": [float("inf"), "ok"]}},
    )
    observation = session.execute(select(ObservationEvent)).scalars().first()
    actor = session.execute(select(Actor).where(Actor.handle == "darkfox77")).scalars().one()
    session.add(identifier)
    session.flush()
    session.add(
        IdentifierLink(
            actor_id=actor.id,
            identifier_id=identifier.id,
            observation_id=observation.id,
            link_type="ASSOCIATED_WITH",
            observed_at=T3,
            weight=1.0,
            meta_json={},
        )
    )
    session.commit()

    # Fixture assumption: the non-finite floats really did reach the database.
    raw = session.execute(
        select(Identifier.meta_json).where(Identifier.value == "sanitised")
    ).scalar_one()
    assert math.isnan(raw["nested"]["float"])
    assert raw["nested"]["list"][0] == float("inf")

    detail = _node(build_graph(session), "handle:sanitised")["detail"]
    meta = detail["meta"]
    assert meta["nested"]["float"] is None
    assert meta["nested"]["list"][0] is None
    assert meta["nested"]["list"][1] == "ok"
    _assert_json_safe(meta)


def test_json_safe_neutralises_objects_the_json_column_cannot_hold() -> None:
    """Defence for values SQLite's JSON type rejects before they are ever stored.

    A ``set`` or a ``datetime`` inside ``meta_json`` fails at ``commit`` with a
    ``TypeError``, so no row containing one can exist and no replay can be
    observed. The sanitiser is nevertheless the last line of defence for whatever
    a future column type or in-process caller admits, and it is a pure function
    - so it is exercised directly.
    """
    sanitised = graph_engine._json_safe(
        {
            "set": {1, 2},
            "when": T0,
            "date": dt.date(2024, 1, 1),
            "nan": float("nan"),
            "inf": float("-inf"),
            "object": object(),
            "nested": {"deep": [{"deeper": float("nan")}]},
        }
    )

    assert sanitised["set"] == [1, 2]  # sorted, so the fold stays deterministic
    assert sanitised["when"] == "2024-01-01T00:00:00Z"
    assert sanitised["date"] == "2024-01-01"
    assert sanitised["nan"] is None
    assert sanitised["inf"] is None
    assert isinstance(sanitised["object"], str)
    assert sanitised["nested"]["deep"][0]["deeper"] is None

    _assert_json_safe(sanitised)
    assert json.loads(json.dumps(sanitised, allow_nan=False)) == sanitised


def test_json_safe_is_depth_bounded_and_deterministic() -> None:
    """A pathologically nested structure degrades instead of recursing forever."""
    hostile: dict[str, Any] = {"leaf": float("nan")}
    for _ in range(graph_engine.MAX_META_DEPTH + 3):
        hostile = {"wrap": hostile}

    rendered = graph_engine._json_safe(hostile)
    assert graph_engine._json_safe(hostile) == rendered
    _assert_json_safe(rendered)


def test_dangling_actor_reference_is_treated_as_unattributed(session: Session) -> None:
    """A link whose actor row is gone still has to land somewhere observable."""
    observation = session.execute(select(ObservationEvent)).scalars().first()
    identifier = Identifier(id_type="HANDLE", value="dangling")
    session.add(identifier)
    session.flush()
    session.add(
        IdentifierLink(
            actor_id=9999,  # no such actor
            identifier_id=identifier.id,
            observation_id=observation.id,
            link_type="ASSOCIATED_WITH",
            observed_at=T3,
            weight=1.0,
            meta_json={},
        )
    )
    session.commit()

    snapshot = build_graph(session)
    assert "handle:dangling" in _node_ids(snapshot)
    link = _link(snapshot, UNATTRIBUTED_NODE_ID, "handle:dangling", "ASSOCIATED_WITH")
    assert link["weight"] == 1.0
    assert snapshot["stats"]["orphan_identifier_count"] == 2


def test_link_without_a_timestamp_still_replays() -> None:
    """A row whose ``observed_at`` is missing must not crash the replay.

    ``identifier_link.observed_at`` is ``NOT NULL`` with a ``utcnow`` default, so
    the database will not actually store a null timestamp - the ORM fills it in.
    The engine still defends against one, because a legacy row, a hand-edited
    dump, or a future migration that relaxes the column must not be able to take
    a whole replay down. Row normalisation is a pure function over the tuple the
    query returns, so the defensive branch is exercised directly on the tuple a
    driver would hand back.
    """
    row = (
        1,  # id
        1,  # actor_id
        1,  # identifier_id
        "ASSOCIATED_WITH",
        None,  # observed_at - the case under test
        1.0,  # weight
        {},  # link meta
        "darkfox77",  # handle
        "PERSONA",  # actor_type
        "HANDLE",  # id_type
        "undated",  # value
        1.0,  # confidence
        {},  # identifier meta
    )
    (edge,) = graph_engine._raw_edges([row])

    # Anchored at the epoch rather than dropped: an observation of unknown age
    # still happened, and treating it as ancient keeps it under every cutoff.
    assert edge.observed_at == dt.datetime(1970, 1, 1, tzinfo=UTC)

    model = graph_engine._assemble([edge], cutoff_time=None)
    payload = graph_engine._snapshot_dict(model)
    assert payload["stats"]["first_observed_at"] == "1970-01-01T00:00:00Z"
    assert _link(payload, ACTOR_FOX, "handle:undated", "ASSOCIATED_WITH")["observed_at"] == (
        "1970-01-01T00:00:00Z"
    )
    GraphSnapshot(**payload)

    # And it survives a cutoff taken before any real observation.
    early = graph_engine._assemble([edge], cutoff_time=BEFORE_ALL)
    assert "handle:undated" in _node_ids(graph_engine._snapshot_dict(early))


def test_the_engine_defends_against_a_null_observed_at_column() -> None:
    """Pin the schema fact that makes the test above a defensive branch.

    If this ever starts failing, the null-timestamp case has become reachable
    through the ORM and :func:`test_link_without_a_timestamp_still_replays`
    should be rewritten to insert a real row instead of a raw tuple.
    """
    assert IdentifierLink.__table__.c.observed_at.nullable is False
    assert IdentifierLink.observed_at.default is not None
