"""Tests for the circadian behavioural time-pattern engine.

The engine is the behavioural half of the fusion stack: the stylometry module
compares *how* two actors write, this one compares *when* they are online. So
the tests here are organised around the two questions an analyst actually asks:
does this actor's rhythm look human, and does actor A's rhythm look like actor
B's?

The two properties that outrank every individual statistic are determinism
(a cached profile is compared byte-for-byte across runs) and total safety (no
input, however hostile, may raise or emit a non-JSON number). Those get
dedicated tests; everything else is built on top of them.
"""

from __future__ import annotations

import ast
import datetime as dt
import json
import math
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.services.circadian_engine import (  # noqa: E402
    NIGHT_HOURS,
    analyse,
    score_pair,
)

UTC = dt.timezone.utc

#: A Monday, so weekday/weekend fixtures are unambiguous.
START = dt.datetime(2024, 3, 4, tzinfo=UTC)

REQUIRED_ANALYSE_KEYS = frozenset(
    {
        "actor_handle",
        "event_count",
        "window",
        "span_hours",
        "hour_histogram_utc",
        "dow_histogram_utc",
        "active_window_utc",
        "circadian_concentration",
        "burst_analysis",
        "weekend_ratio",
        "night_ratio",
        "human_plausibility",
        "verdict",
        "confidence",
        "notes",
    }
)

REQUIRED_PAIR_KEYS = frozenset(
    {"temporal_score", "confidence", "components", "actor_a", "actor_b", "notes"}
)

VALID_VERDICTS = frozenset(
    {"HUMAN_LIKE", "REGULAR_INTERVAL_BOT", "BURST_BEHAVIOUR", "INSUFFICIENT_DATA"}
)

#: (hour, minute) pairs for a plausible working day, and a lighter weekend.
WORKDAY = ((8, 41), (9, 12), (10, 55), (11, 5), (13, 27), (14, 51), (16, 8), (19, 16))
WEEKEND = ((10, 12), (12, 38), (15, 4), (17, 51))
#: Per-post minute/second jitter; without it a "human" fixture is periodic.
JITTER = ((7, 13), (-4, 29), (11, 3), (-9, 41), (5, 17), (-2, 53), (9, 31), (-6, 7))


def human_timestamps(
    days: int = 12, shift_hours: float = 0.0, handle: str = ""
) -> list[dt.datetime]:
    """An irregular diurnal actor: workdays are busier than weekends.

    ``shift_hours`` rotates the whole rhythm around the 24h clock, which is the
    cleanest possible way to ask "would you still call this the same person?".
    """
    stamps: list[dt.datetime] = []
    for day in range(days):
        base = START + dt.timedelta(days=day)
        pattern = WORKDAY if base.weekday() < 5 else WEEKEND
        for index, (hour, minute) in enumerate(pattern):
            if (day * 3 + index) % 7 == 0:
                continue
            jitter_minutes, jitter_seconds = JITTER[(day * 5 + index) % len(JITTER)]
            stamps.append(
                base
                + dt.timedelta(hours=hour, minutes=minute + jitter_minutes)
                + dt.timedelta(seconds=jitter_seconds)
            )
    shifted = [stamp + dt.timedelta(hours=shift_hours) for stamp in stamps]
    del handle
    return shifted


def bot_timestamps(step_hours: float = 6.0, count: int = 50) -> list[dt.datetime]:
    """A cron job: identical intervals, identical minute-of-hour, forever."""
    return [START + dt.timedelta(hours=step_hours * i) for i in range(count)]


def burst_timestamps() -> list[dt.datetime]:
    """Two people working an all-nighter: dense sessions, long silences."""
    stamps: list[dt.datetime] = []
    for day in range(6):
        base = START + dt.timedelta(days=day)
        for index in range(12):
            stamps.append(
                base
                + dt.timedelta(hours=1)
                + dt.timedelta(minutes=index * 3, seconds=(index * 7) % 41)
            )
    return stamps


# ---------------------------------------------------------------------------
# Total safety: hostile input must never raise
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "hostile",
    [
        pytest.param([], id="empty-list"),
        pytest.param(None, id="none"),
        pytest.param(b"", id="empty-bytes"),
        pytest.param("", id="empty-string"),
        pytest.param("not-a-timestamp", id="junk-string"),
        pytest.param(object(), id="arbitrary-object"),
        pytest.param([[[[[1]]]]], id="nested-junk"),
        pytest.param([None] * 40, id="all-none"),
        pytest.param([{}, [], object()], id="mixed-junk"),
        pytest.param(float("nan"), id="nan"),
        pytest.param(float("inf"), id="inf"),
        pytest.param(-float("inf"), id="negative-inf"),
        pytest.param(1e308, id="huge-float"),
        pytest.param(0, id="zero-epoch"),
        pytest.param(-1, id="negative-epoch"),
        pytest.param(10**20, id="absurd-epoch"),
        pytest.param(True, id="bool"),
        pytest.param("2024-13-45T99:99:99Z", id="impossible-date"),
        pytest.param({"nested": {"deeply": {"nope": 1}}}, id="unhelpful-mapping"),
        pytest.param(range(3), id="range"),
        pytest.param(iter([START, START]), id="one-shot-iterator"),
    ],
)
def test_analyse_never_raises(hostile: Any) -> None:
    result = analyse(hostile)
    assert isinstance(result, dict)
    assert REQUIRED_ANALYSE_KEYS <= set(result)
    assert result["verdict"] in VALID_VERDICTS
    # allow_nan=False is the real contract: no NaN, no infinity, anywhere.
    json.dumps(result, allow_nan=False)


@pytest.mark.parametrize("count", [0, 1, 2, 3])
def test_small_samples_are_insufficient(count: int) -> None:
    stamps = [START + dt.timedelta(hours=3 * i) for i in range(count)]
    result = analyse(stamps)
    assert result["event_count"] == count
    assert result["verdict"] == "INSUFFICIENT_DATA"
    assert result["confidence"] < 0.35, "a small sample must not look certain"
    json.dumps(result, allow_nan=False)


def test_fifty_events_produce_a_confident_reading() -> None:
    result = analyse(bot_timestamps())
    assert result["event_count"] == 50
    assert result["confidence"] > 0.6
    assert result["verdict"] in VALID_VERDICTS


def test_identical_timestamps_do_not_divide_by_zero() -> None:
    moment = START + dt.timedelta(hours=9, minutes=8, seconds=29)
    result = analyse([moment] * 25)
    # Duplicates are kept: 25 posts in one second are 25 events, and dropping
    # them would understate evidence the analyst actually has.
    assert result["event_count"] == 25
    assert result["span_hours"] == 0.0
    gaps = result["burst_analysis"]
    assert gaps["gap_count"] == 24, "every consecutive pair yields a gap"
    assert gaps["median_gap_hours"] == 0.0
    assert gaps["max_gap_hours"] == 0.0
    assert gaps["min_gap_hours"] == 0.0
    assert result["interval_cv"] is None, "CV of zero gaps is undefined, not 0.0"
    json.dumps(result, allow_nan=False)


def test_zero_gaps_do_not_break_the_burst_split() -> None:
    moment = START + dt.timedelta(hours=9, minutes=8, seconds=29)
    result = analyse([moment, moment, moment])
    assert result["burst_analysis"]["burst_count"] == 1, "one unbroken session"
    assert result["burst_analysis"]["longest_burst_events"] == 3
    assert result["burst_analysis"]["longest_burst_span_minutes"] == 0.0


def test_same_instant_flooding_is_burst_not_human() -> None:
    """Nine posts in one second is not a person varying their intervals.

    The median gap is zero here, which leaves the silence test with no
    baseline; without an explicit check the profile falls through to the human
    verdict and the notes assert it "varies normally".
    """
    moment = START + dt.timedelta(hours=9, minutes=8, seconds=29)
    flooded = [moment] * 9 + [moment + dt.timedelta(hours=20)]
    result = analyse(flooded)
    assert result["burst_analysis"]["median_gap_hours"] == 0.0
    assert result["verdict"] == "BURST_BEHAVIOUR"
    assert not any("consistent with a person" in note for note in result["notes"])
    assert result["human_plausibility"] < 0.5, "faster than a person can type"


def test_notes_never_report_a_ratio_against_a_zero_baseline() -> None:
    """A "0x the median gap" sentence is arithmetic on an undefined ratio."""
    moment = START + dt.timedelta(hours=9, minutes=8, seconds=29)
    notes = analyse([moment] * 10)["notes"]
    assert not any("0x the median" in note for note in notes), notes
    assert any("median gap 0.00h" in note for note in notes), notes
    assert all("x the median gap" in note or "median gap 0.00h" in note
               for note in notes if "silence" in note)


# ---------------------------------------------------------------------------
# Histograms and the day/night window
# ---------------------------------------------------------------------------
def test_histograms_are_valid_distributions() -> None:
    for profile in (
        analyse(human_timestamps()),
        analyse(bot_timestamps(step_hours=7, count=40)),
        analyse(burst_timestamps()),
    ):
        for key, width in (("hour_histogram_utc", 24), ("dow_histogram_utc", 7)):
            bins = profile[key]
            assert len(bins) == width
            assert all(bin_ >= 0.0 for bin_ in bins)
            assert sum(bins) == pytest.approx(1.0, abs=1e-9)
        assert 0.0 <= profile["circadian_concentration"] <= 1.0
        assert 0.0 <= profile["human_plausibility"] <= 1.0
        assert 0.0 <= profile["weekend_ratio"] <= 1.0
        assert 0.0 <= profile["night_ratio"] <= 1.0
        assert 0.0 <= profile["confidence"] <= 1.0


def test_empty_profile_reports_zero_histograms_not_a_fake_distribution() -> None:
    result = analyse([])
    assert result["hour_histogram_utc"] == [0.0] * 24
    assert result["dow_histogram_utc"] == [0.0] * 7
    assert result["window"] == {"earliest": None, "latest": None}
    assert result["span_hours"] == 0.0
    assert result["notes"], "an analyst still deserves an explanation"


def test_night_window_is_22_to_06_utc() -> None:
    assert NIGHT_HOURS == frozenset({22, 23, 0, 1, 2, 3, 4, 5})

    by_hour = {
        hour: analyse([dt.datetime(2024, 3, 4, hour, tzinfo=UTC)])["night_ratio"]
        for hour in range(24)
    }
    inside = {hour for hour, ratio in by_hour.items() if ratio == 1.0}
    outside = {hour for hour, ratio in by_hour.items() if ratio == 0.0}
    assert inside == set(NIGHT_HOURS)
    assert outside == set(range(24)) - set(NIGHT_HOURS)


def test_weekend_ratio_tracks_the_week() -> None:
    saturday = analyse(
        [dt.datetime(2024, 3, 9, 12, tzinfo=UTC)] * 5
        + [dt.datetime(2024, 3, 4, 12, tzinfo=UTC)] * 5
    )
    assert saturday["weekend_ratio"] == pytest.approx(0.5)
    assert analyse([dt.datetime(2024, 3, 9, 12, tzinfo=UTC)])["weekend_ratio"] == 1.0
    assert analyse([dt.datetime(2024, 3, 8, 12, tzinfo=UTC)])["weekend_ratio"] == 0.0


def test_active_window_wraps_across_midnight() -> None:
    nocturnal = [
        dt.datetime(2024, 3, 4, 22, tzinfo=UTC) + dt.timedelta(hours=h)
        for h in range(8)
    ]
    window = analyse(nocturnal)["active_window_utc"]
    # 22:00 and 00:00 are neighbours, so the window has to be a circular arc
    # rather than a slice: a naive min/max would have reported 00:00-22:00.
    assert window["start_hour"] == 22
    assert window["end_hour"] < window["start_hour"], "the arc wraps midnight"
    assert window["span_hours"] < 24
    assert window["covered_mass"] >= 0.8
    assert window["label"].startswith("22:00-")
    assert "UTC" in window["label"]


def test_active_window_covers_the_bulk_of_activity() -> None:
    result = analyse(human_timestamps())
    window = result["active_window_utc"]
    assert window["covered_mass"] >= 0.5, "the window must hold the bulk of posts"
    assert 1 <= window["span_hours"] <= 24
    assert window["start_hour"] != window["end_hour"] or window["span_hours"] == 1
    inside = sum(
        result["hour_histogram_utc"][hour]
        for hour in _window_hours(window["start_hour"], window["end_hour"])
    )
    assert inside == pytest.approx(window["covered_mass"], abs=1e-6)


def _window_hours(start: int, end: int) -> range | list[int]:
    if start <= end:
        return range(start, end + 1)
    return list(range(start, 24)) + list(range(0, end + 1))


# ---------------------------------------------------------------------------
# Timestamp normalisation
# ---------------------------------------------------------------------------
def test_naive_and_aware_input_agree() -> None:
    aware = [dt.datetime(2024, 3, 4, 9, 8, 29, tzinfo=UTC)]
    naive = [dt.datetime(2024, 3, 4, 9, 8, 29)]
    assert analyse(aware)["hour_histogram_utc"] == analyse(naive)["hour_histogram_utc"]


def test_offset_and_zulu_strings_agree() -> None:
    zulu = ["2024-03-04T09:08:29Z"]
    offset = ["2024-03-04T10:08:29+01:00"]
    assert analyse(zulu)["hour_histogram_utc"] == analyse(offset)["hour_histogram_utc"]


def test_epoch_seconds_and_milliseconds_agree() -> None:
    moment = dt.datetime(2024, 3, 4, 9, 8, 29, tzinfo=UTC)
    seconds = int(moment.timestamp())
    assert analyse([seconds])["hour_histogram_utc"] == analyse(
        [seconds * 1000]
    )["hour_histogram_utc"]
    assert analyse([moment])["hour_histogram_utc"] == analyse(
        [seconds]
    )["hour_histogram_utc"]


def test_mixed_representations_resolve_to_one_instant() -> None:
    moment = dt.datetime(2024, 3, 4, 9, 8, 29, tzinfo=UTC)
    seconds = int(moment.timestamp())
    mixed = [
        moment,
        moment.isoformat(),
        moment.isoformat().replace("+00:00", "Z"),
        seconds,
        seconds * 1000,
        moment.astimezone(dt.timezone(dt.timedelta(hours=-5))),
    ]
    result = analyse(mixed)
    assert result["event_count"] == 6
    assert result["span_hours"] == 0.0, "all six resolve to the same UTC instant"
    assert result["hour_histogram_utc"] == analyse([moment])["hour_histogram_utc"]


def test_none_and_junk_entries_are_skipped_not_fatal() -> None:
    good = [START + dt.timedelta(hours=3 * i) for i in range(6)]
    result = analyse([None, *good, "", "  ", "nonsense", {}, [None], object()])
    assert result["event_count"] == 6


def test_bare_epoch_zero_is_read_as_1970_not_as_junk() -> None:
    """Epoch 0 is a real instant; silently dropping it would hide a clock bug."""
    result = analyse([0, 0.0])
    assert result["event_count"] == 2
    assert result["window"]["earliest"] == "1970-01-01T00:00:00Z"


def test_missing_and_none_inputs_are_safe_for_pairing() -> None:
    for empty in ([], None, "", b"", {}, {"actor_handle": "ghost"}):
        result = score_pair(human_timestamps(), empty)
        assert 0.0 <= result["temporal_score"] <= 1.0
        assert result["confidence"] < 0.2
        json.dumps(result, allow_nan=False)


# ---------------------------------------------------------------------------
# Verdict vocabulary
# ---------------------------------------------------------------------------
def test_diurnal_irregular_actor_reads_human_like() -> None:
    result = analyse(human_timestamps())
    assert result["verdict"] == "HUMAN_LIKE"
    assert result["human_plausibility"] > 0.5
    assert result["is_periodic"] is False


def test_fixed_interval_actor_reads_as_a_bot() -> None:
    result = analyse(bot_timestamps())
    assert result["verdict"] == "REGULAR_INTERVAL_BOT"
    assert result["is_periodic"] is True
    assert result["interval_cv"] == pytest.approx(0.0, abs=1e-9)
    assert result["minute_regularity"]["same_minute_every_time"] is True
    assert result["human_plausibility"] < 0.5
    assert result["confidence"] > 0.6, "a blatant bot is an easy call"


def test_overnight_sessions_read_as_burst_behaviour() -> None:
    result = analyse(burst_timestamps())
    assert result["verdict"] == "BURST_BEHAVIOUR"
    assert result["burst_analysis"]["burst_count"] >= 2
    assert result["night_ratio"] > 0.5
    # The tell: a median gap of minutes, then a silence of many hours.
    assert result["burst_analysis"]["median_gap_hours"] < 0.25
    assert result["machine_evidence"]["burst_dominance"] > 0.5


def test_classic_nightly_dumper_is_caught() -> None:
    """The common real-world case: 20 posts in 10 minutes, then sleep."""
    dumper = sorted(
        START + dt.timedelta(days=day, hours=1, minutes=index * 0.5)
        for day in range(20)
        for index in range(20)
    )
    result = analyse(dumper)
    assert result["verdict"] == "BURST_BEHAVIOUR"
    assert result["interval_cv"] is not None and result["interval_cv"] > 1.0
    assert result["burst_analysis"]["burst_count"] == 20


def test_human_plausibility_never_claims_certainty() -> None:
    """Absence of machine evidence is not proof of a human."""
    result = analyse(human_timestamps())
    assert result["human_plausibility"] <= 0.98
    assert result["human_plausibility"] > 0.5


def test_every_verdict_is_in_the_agreed_vocabulary() -> None:
    fixtures = {
        "empty": [],
        "single": [START],
        "tiny": [START + dt.timedelta(hours=i) for i in range(3)],
        "human": human_timestamps(),
        "bot": bot_timestamps(),
        "burst": burst_timestamps(),
    }
    seen = set()
    for label, stamps in fixtures.items():
        verdict = analyse(stamps)["verdict"]
        assert verdict in VALID_VERDICTS, label
        seen.add(verdict)
    assert seen == VALID_VERDICTS, "every verdict needs a fixture that reaches it"


def test_notes_are_specific_rather_than_boilerplate() -> None:
    result = analyse(human_timestamps(), actor_handle="daylight-worker")
    notes = result["notes"]
    assert len(notes) >= 4
    # Every note should carry at least one number from the evidence it cites.
    assert all(any(char.isdigit() for char in note) for note in notes), notes
    assert any("median gap" in note.lower() for note in notes), notes
    assert any("UTC" in note for note in notes), "notes name their timezone"
    assert notes[0].startswith("daylight-worker: "), "the handle is echoed back"


# ---------------------------------------------------------------------------
# Pair scoring
# ---------------------------------------------------------------------------
def test_diurnal_actor_does_not_match_the_same_actor_rotated_eight_hours() -> None:
    day = human_timestamps()
    night = human_timestamps(shift_hours=8.0)

    same = score_pair(day, human_timestamps(days=10))
    rotated = score_pair(day, night)

    assert same["temporal_score"] > 0.8, "a re-sample of one rhythm must match"
    assert rotated["temporal_score"] < 0.45, (
        "an 8h phase shift is a different daily rhythm, not a rounding error"
    )
    assert rotated["temporal_score"] < same["temporal_score"] / 2
    assert rotated["components"]["hour_similarity"] < 0.4
    assert rotated["confidence"] > 0.5, "the verdict is about rhythm, not sample size"


def test_identical_actors_score_maximally() -> None:
    stamps = human_timestamps()
    result = score_pair(stamps, list(stamps))
    assert result["temporal_score"] == pytest.approx(1.0, abs=1e-6)
    assert result["confidence"] > 0.6


def test_bot_and_human_are_easily_told_apart() -> None:
    result = score_pair(bot_timestamps(), human_timestamps())
    assert result["temporal_score"] < 0.3
    assert result["components"]["burst_similarity"] < 0.5
    assert result["actor_a"]["verdict"] == "REGULAR_INTERVAL_BOT"
    assert result["actor_b"]["verdict"] == "HUMAN_LIKE"


def test_bursty_and_bursty_match_each_other() -> None:
    result = score_pair(burst_timestamps(), burst_timestamps())
    assert result["temporal_score"] > 0.7


def test_score_is_symmetric() -> None:
    day = human_timestamps()
    night = human_timestamps(shift_hours=8.0)
    assert score_pair(day, night)["temporal_score"] == pytest.approx(
        score_pair(night, day)["temporal_score"]
    )


def test_insufficient_side_yields_neutral_score_and_low_confidence() -> None:
    day = human_timestamps()
    for thin in ([START], [START, START + dt.timedelta(hours=4)], []):
        result = score_pair(day, thin)
        assert 0.25 <= result["temporal_score"] <= 0.75, (
            "a thin side must not produce a confident extreme"
        )
        assert result["confidence"] < 0.2
        assert result["actor_b"]["verdict"] == "INSUFFICIENT_DATA"
        thin_text = " ".join(note.lower() for note in result["notes"])
        assert "fewer than 4 events" in thin_text or "no usable timestamps" in thin_text


def test_single_event_pairing_is_near_neutral() -> None:
    result = score_pair([START], [START + dt.timedelta(hours=1)])
    assert 0.4 <= result["temporal_score"] <= 0.6
    assert result["confidence"] < 0.05


@pytest.mark.parametrize(
    "wrap,expects_handle",
    [
        pytest.param(lambda s: s, False, id="plain-sequence"),
        pytest.param(
            lambda s: {"actor_handle": "w", "timestamps": s}, True, id="timestamps-key"
        ),
        pytest.param(
            lambda s: {"actor_handle": "w", "events": s}, True, id="events-key"
        ),
        pytest.param(
            lambda s: {"actor_handle": "w", "observed_at": s}, True, id="observed-at-key"
        ),
        pytest.param(
            lambda s: analyse(s, actor_handle="w"), True, id="full-analyse-dict"
        ),
    ],
)
def test_score_pair_accepts_every_documented_input_shape(
    wrap: Any, expects_handle: bool
) -> None:
    """All five shapes must reach the same score, not merely avoid raising."""
    day = human_timestamps()
    night = human_timestamps(shift_hours=8.0)
    result = score_pair(wrap(day), wrap(night))
    assert result["temporal_score"] == pytest.approx(0.39, abs=0.05)
    if expects_handle:
        assert result["actor_a"]["actor_handle"] == "w"
        assert result["actor_b"]["actor_handle"] == "w"
    else:
        assert result["actor_a"]["actor_handle"] == "A", "positional default"
        assert result["actor_b"]["actor_handle"] == "B"


def test_pair_output_shape_is_complete_and_json_safe() -> None:
    result = score_pair(human_timestamps(), bot_timestamps())
    assert REQUIRED_PAIR_KEYS <= set(result)
    assert set(result["components"]) == {
        "hour_similarity",
        "dow_similarity",
        "burst_similarity",
    }
    for side in ("actor_a", "actor_b"):
        assert REQUIRED_ANALYSE_KEYS <= set(result[side])
        assert 0.0 <= result[side]["confidence"] <= 1.0
    assert 0.0 <= result["confidence"] <= 1.0
    assert isinstance(result["notes"], list) and result["notes"]
    json.dumps(result, allow_nan=False)


def test_day_of_week_evidence_is_downweighted_on_thin_samples() -> None:
    day = human_timestamps()
    sparse = score_pair(day[:3], human_timestamps(shift_hours=8.0)[:3])
    dense = score_pair(day, human_timestamps(shift_hours=8.0))
    assert sparse["components"]["dow_similarity"] >= dense["components"][
        "dow_similarity"
    ], "three posts are noisy, so the term is given less say"
    assert sparse["temporal_score"] > dense["temporal_score"] - 0.1


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------
def test_identical_input_gives_identical_output() -> None:
    stamps = human_timestamps()
    assert analyse(stamps) == analyse(stamps)
    assert score_pair(stamps, bot_timestamps()) == score_pair(
        stamps, bot_timestamps()
    )


def test_input_order_does_not_matter() -> None:
    stamps = human_timestamps()
    assert analyse(stamps) == analyse(sorted(stamps, reverse=True))
    assert score_pair(stamps, bot_timestamps())["temporal_score"] == pytest.approx(
        score_pair(list(reversed(stamps)), bot_timestamps())["temporal_score"]
    )


def test_module_never_imports_a_nondeterministic_source() -> None:
    """Check the parsed code, not the prose: the docstring says "no randomness".

    A raw substring scan would flag the module's own comment saying exactly
    that, so this walks the AST and inspects imports, call names and attribute
    access only.
    """
    tree = ast.parse(
        (ROOT / "backend/app/services/circadian_engine.py").read_text()
    )
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    assert "random" not in imported
    assert not ({"os", "time", "secrets"} & imported), "no ambient state source"

    called: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                called.add(func.id)
            elif isinstance(func, ast.Attribute):
                called.add(func.attr)
    assert not ({"now", "utcnow", "today", "time", "monotonic"} & called), (
        "reading the wall clock would make a cached profile unreproducible"
    )


def test_determinism_survives_a_fresh_interpreter() -> None:
    """Byte-identical across processes, not just across calls in one process."""
    stamps = human_timestamps()
    payload = [stamp.isoformat() for stamp in stamps]
    script = (
        "import json,sys;"
        "sys.path.insert(0, %r);" % str(ROOT)
        + "from backend.app.services.circadian_engine import analyse;"
        "print(json.dumps(analyse(json.loads(sys.argv[1])), sort_keys=True))"
    )
    runs = [
        subprocess.run(
            [sys.executable, "-c", script, json.dumps(payload)],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        for _ in range(2)
    ]
    assert runs[0] == runs[1]
    assert json.loads(runs[0])["event_count"] == len(set(stamps))


# ---------------------------------------------------------------------------
# Boundary sweep: nothing in here may produce a non-finite number
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "stamps",
    [
        pytest.param(
            [START + dt.timedelta(hours=h) for h in range(24)], id="every-hour"
        ),
        pytest.param(
            [START + dt.timedelta(hours=12 * i) for i in range(6)], id="twice-daily"
        ),
        pytest.param(
            [START + dt.timedelta(hours=i % 24) for i in range(400)], id="dense-400"
        ),
        pytest.param(
            [START + dt.timedelta(minutes=1) for _ in range(60)], id="one-minute-apart"
        ),
        pytest.param([START, START + dt.timedelta(days=3650)], id="a-decade-apart"),
        pytest.param(
            [START + dt.timedelta(hours=1.0 * i) for i in range(50)], id="float-steps"
        ),
    ],
)
def test_no_nan_or_infinity_anywhere(stamps: list[dt.datetime]) -> None:
    for profile in (analyse(stamps), score_pair(stamps, bot_timestamps())):
        for value in _walk(profile):
            if isinstance(value, float):
                assert math.isfinite(value), f"non-finite value {value!r}"


def _walk(node: Any) -> list[Any]:
    if isinstance(node, dict):
        return [item for value in node.values() for item in _walk(value)]
    if isinstance(node, (list, tuple)):
        return [item for value in node for item in _walk(value)]
    return [node]
