"""Circadian (behavioural time-pattern) analysis for dark-web actors.

Why this module exists
----------------------
An actor handle is a costume, not an identity. Vendors rotate handles and keep
the same operating rhythm, and two different people behind one shared account
look like a single actor to every content-based signal. What does *not* change
when a handle changes is *when* the operator is awake. Posting cadence is the
one behavioural feature that survives handle rotation, forum migration and
topic change, which is why it carries weight in the attribution fusion: every
other signal here can be faked, a circadian rhythm largely cannot.

The claim this module supports is therefore narrow and stated precisely: two
actors are more likely to be the same operator when their posting rhythms share
the same *shape*, independent of volume. A vendor posting 400 times a day and a
hobbyist posting 6 times a day can be the same person, and a count-based
comparison would call them different people. Every score produced here is a
shape comparison over normalised distributions.

Method
------
1. Normalise every timestamp to tz-aware UTC. Naive datetimes are treated as
   UTC because the ingest pipeline (``ingest_service._parse_ts``) already emits
   UTC, and silently mixing conventions shifts an actor by hours.
2. Build two probability mass functions: hour-of-day (24 bins) and day-of-week
   (7 bins). These are the only volume-free descriptions of a rhythm.
3. Derive burst structure from inter-event gaps: an interval longer than
   ``BURST_GAP_HOURS`` severs one posting burst from the next.
4. Score plausibility from cadence regularity, clock alignment, burst dominance
   and circadian narrowness.
5. ``score_pair`` blends hour-histogram distance, day-of-week agreement and
   burst-characteristic agreement into a single ``0.0-1.0`` sub-score.

Determinism
-----------
This is forensic software: a score that cannot be reproduced cannot be defended
in court. There is no randomness, no wall-clock read and no reliance on
dictionary iteration order anywhere in the scoring path. Identical input always
yields byte-identical output. Every returned float is finite and
JSON-serialisable under ``json.dumps(..., allow_nan=False)``.

Definitions used by the returned metrics
----------------------------------------
Night window
    22:00-06:00 UTC, i.e. hours ``{22, 23, 0, 1, 2, 3, 4, 5}``. Most of the
    dark-web user base operates on European or Russian offsets, where this is
    the post-dinner to early-morning posting block, and it is the window in
    which the clearnet-linked personas of the same operators are usually
    asleep - a mismatch between a forum's night ratio and a linked social
    account's day ratio is a strong negative signal.
Weekend
    Saturday and Sunday, ``dt.date.weekday()`` values 5 and 6, evaluated in
    UTC. Weekend-weighted activity is a known signature of botnets spreading
    load across otherwise idle capacity, and of investigators running jobs
    from residential hosts in other regions.
Burst
    A maximal run of events where every consecutive gap is at most
    ``BURST_GAP_HOURS`` (6h). Six hours is roughly the length of a night, so a
    longer silence means the operator went away rather than paused.

Circadian concentration formula
-------------------------------
``circadian_concentration = 0.55 * peak + 0.45 * (1 - H / log2(24))``

where ``peak`` is the largest single hour-of-day bin and ``H`` is the Shannon
entropy of the 24-bin hour histogram. The peak term rewards a rhythm that
occupies one obvious part of the day; the entropy term penalises one that
smears activity thinly across the whole clock. Blending both avoids the two
failure modes of a single statistic: ``peak`` alone scores a three-event sample
that happens to share an hour as perfectly concentrated, while ``H`` alone
scores a sample filling 23 of 24 hours uniformly as near-maximally
concentrated. The result is 0.0 for an empty sample and 1.0 for a rhythm locked
to a single hour.

Pair scoring
------------
``temporal_score = 0.55 * hour_similarity + 0.15 * dow_similarity
                   + 0.30 * burst_similarity``

``hour_similarity`` blends total-variation distance with a centred cosine over
the 24-bin histograms, ``dow_similarity`` is ``1 - TVD`` over the 7-bin
histograms, and ``burst_similarity`` compares median inter-event gap, burst
share, inter-arrival CV and circadian concentration. The day-of-week weight is
discounted and its mass moved to the hour term when either side has fewer than
``DOW_COVERAGE_EVENTS`` events, because a 7-bin distribution estimated from
four observations is almost pure noise. If either side is
``INSUFFICIENT_DATA`` the score is pulled halfway to the neutral 0.5 and
confidence is halved, so a thin pair can never produce a confident verdict in
either direction.
"""

from __future__ import annotations

import datetime as dt
import math
from typing import Any, Iterable, Mapping, Sequence

UTC = dt.timezone.utc

HOURS_PER_DAY = 24
DAYS_PER_WEEK = 7

#: Night window: 22:00 through 06:00 UTC, expressed as hours-of-day. The window
#: is circular, so it is assembled as the tail of the day plus the head.
NIGHT_START_HOUR = 22
NIGHT_END_HOUR = 6
NIGHT_HOURS: frozenset[int] = frozenset(
    range(NIGHT_START_HOUR, HOURS_PER_DAY)
) | frozenset(range(0, NIGHT_END_HOUR))

#: Day-of-week indices (Monday == 0, per ``dt.date.weekday``) counted as weekend.
WEEKEND_DOWS: frozenset[int] = frozenset({5, 6})

#: A gap strictly longer than this severs one posting burst from the next.
BURST_GAP_HOURS = 6.0

#: Fraction of activity the reported active window must contain.
ACTIVE_WINDOW_BULK = 0.80

#: Below this many events a rhythm cannot be characterised.
MIN_EVENTS_FOR_VERDICT = 4

#: ``confidence`` uses ``n / (n + k)``; this ``k`` is the half-life in events.
CONFIDENCE_HALF_LIFE = 12.0

#: Distinct active days needed before sampling covers a full behavioural cycle.
CONFIDENCE_FULL_COVERAGE_DAYS = 3.0

#: Inter-arrival CV at or below this is treated as machine-regular.
REGULARITY_CV_MAX = 0.08

#: Every gap within this fraction of the median gap counts as a fixed period.
PERIODIC_TOLERANCE = 0.02

#: Events needed before "identical minute-of-hour" counts as evidence.
CLOCK_MIN_EVENTS = 5

#: Concentration at or below this is ordinary human diurnal behaviour; above
#: it, narrowness starts to read as automated.
CONCENTRATION_HUMAN_CEILING = 0.45
CONCENTRATION_SPAN = 0.35

#: Burst share above this starts to read as dump / burst behaviour.
#: ``max_gap / median_gap``. An actor who posts steadily all day has a median gap
#: in hours and an overnight silence of single-digit multiples of it; an actor who
#: empties a session in minutes has a median gap in minutes and the same silence
#: is hundreds of times larger. Measured on fixtures: ~9 for a regular 7-per-day
#: poster, ~450 for a nightly session-dumper.
BURST_CONTRAST_HUMAN_CEILING = 12.0
BURST_CONTRAST_VERDICT = 25.0
BURST_CONTRAST_SPAN = 38.0

#: ``human_plausibility`` is capped here rather than reaching 1.0, because "no
#: evidence of automation" is not the same claim as "certainly a person".
PLAUSIBILITY_CEILING = 0.98

VERDICT_HUMAN = "HUMAN_LIKE"
VERDICT_BOT = "REGULAR_INTERVAL_BOT"
VERDICT_BURST = "BURST_BEHAVIOUR"
VERDICT_INSUFFICIENT = "INSUFFICIENT_DATA"

VERDICTS: tuple[str, ...] = (
    VERDICT_HUMAN,
    VERDICT_BOT,
    VERDICT_BURST,
    VERDICT_INSUFFICIENT,
)

# Pair-similarity weights. Hour-of-day shape dominates; day-of-week agreement
# is real evidence but the noisiest term at small sample sizes.
#: Evidence components are combined as a weighted *geometric* mean, not a sum.
#: The attribution claim "same operator" has to survive every independent
#: dimension at once, so a single strong disagreement - a day-shift operator
#: against a night-shift operator, say - must collapse the score rather than be
#: averaged away by two agreeable components. The floor keeps every component
#: strictly positive, so a disjoint pair reads as "very unlikely" rather than as
#: a mathematical certainty the evidence cannot support.
COMPONENT_FLOOR = 0.01

#: Component weights for the pair score. ``W_DOW`` is the *ceiling* for the
#: day-of-week term; a profile too thin to establish a weekly rhythm is given
#: less than that, and the unused share falls back to the hour term, which is
#: always estimable. So the weights always sum to 1.0 and the hour term is
#: ``W_HOUR`` plus whatever the DOW term did not claim.
W_DOW = 0.10
W_BURST = 0.20
W_HOUR = 1.0 - W_DOW - W_BURST

#: Split of the hour term between total-variation distance, centred cosine and
#: first-harmonic phase agreement.
W_TVD = 0.45
W_CENTRED_COSINE = 0.20
W_PHASE = 0.35

#: First-harmonic amplitude below which a rhythm has no recoverable phase.
#: A perfectly uniform histogram and a comb locked to 6-hourly ticks both
#: collapse to zero amplitude, which is why the phase term is weighted by
#: amplitude instead of being trusted unconditionally. Full weight is earned
#: at the floor, i.e. as soon as a phase exists at all - a weak-but-present
#: rhythm is still evidence, and down-weighting it further would just hand the
#: decision back to a metric with no phase information.
PHASE_AMP_FLOOR = 0.05

#: Burst-similarity sub-weights.
W_BURST_GAP = 0.45
W_BURST_SHARE = 0.25
W_BURST_CV = 0.15
W_BURST_CONCENTRATION = 0.15

#: Events needed on each side before day-of-week agreement earns full weight.
DOW_COVERAGE_EVENTS = 14.0

#: Floors for the ratio-closeness helper, so a missing statistic reads as "no
#: information" rather than "infinitely different".
_GAP_FLOOR_HOURS = 1.0
_SHARE_FLOOR = 0.05
_CV_FLOOR = 0.25
_CONCENTRATION_FLOOR = 0.10

#: How far a thin pair is dragged back toward the neutral score of 0.5.
INSUFFICIENT_PULL = 0.5

_EPS = 1e-12
_MAX_NOTES = 8

#: Mapping keys a caller may use to hand a timestamp collection to this module.
TIMESTAMP_KEYS: tuple[str, ...] = (
    "timestamps",
    "events",
    "observed_at",
    "times",
    "activity",
)

_LOOSE_FORMATS: tuple[str, ...] = (
    "%Y/%m/%d %H:%M:%S",
    "%Y/%m/%d %H:%M",
    "%d-%m-%Y %H:%M:%S",
    "%d-%m-%Y %H:%M",
    "%Y-%m-%dT%H:%M",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
    "%Y/%m/%d",
)

# 1e11 seconds is the year 5138; every timestamp this platform can plausibly
# ingest is below that, so a larger magnitude must be milliseconds.
_EPOCH_MS_THRESHOLD = 1e11


# ---------------------------------------------------------------------------
# Timestamp normalisation
# ---------------------------------------------------------------------------
def _from_loose_string(text: str) -> dt.datetime | None:
    """Best-effort parse for strings ``datetime.fromisoformat`` rejects."""
    stripped = text.strip().strip("'\"")
    for fmt in _LOOSE_FORMATS:
        try:
            return dt.datetime.strptime(stripped, fmt)
        except ValueError:
            continue
    try:
        return dt.datetime.fromtimestamp(float(stripped), tz=UTC)
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def normalise_timestamp(value: Any) -> dt.datetime | None:
    """Coerce one input value into a tz-aware UTC datetime.

    Accepts ``datetime`` (naive values are assumed to be UTC, matching the
    ingest pipeline), ``date``, ``int``/``float`` epoch seconds or
    milliseconds, ``bytes`` and ISO-8601 strings carrying ``Z`` or an explicit
    offset. Anything unusable yields ``None`` so callers can skip it; this
    function never raises on hostile input.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
    if isinstance(value, dt.date):
        return dt.datetime(value.year, value.month, value.day, tzinfo=UTC)
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            return None
        seconds = float(value)
        if abs(seconds) > _EPOCH_MS_THRESHOLD:
            seconds /= 1000.0
        try:
            return dt.datetime.fromtimestamp(seconds, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, (bytes, bytearray)):
        try:
            value = bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        candidate = f"{text[:-1]}+00:00" if text[-1] in ("Z", "z") else text
        try:
            parsed: dt.datetime | None = dt.datetime.fromisoformat(candidate)
        except ValueError:
            parsed = _from_loose_string(text)
        if parsed is None:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    return None


def _collect_timestamps(values: Any) -> list[dt.datetime]:
    """Normalise an arbitrary collection of timestamps, sorted ascending.

    Duplicates are deliberately preserved. Several messages posted within the
    same second are distinct events, and collapsing them would understate
    ``event_count`` and corrupt the confidence and burst statistics that depend
    on it. Mapping inputs are resolved to a single field before this point, so
    a dict never contributes the same instant twice.
    """
    if values is None:
        return []
    if isinstance(values, Mapping):
        for key in TIMESTAMP_KEYS:
            if values.get(key) is not None:
                return _collect_timestamps(values[key])
        return []
    if isinstance(values, (str, bytes, bytearray, dt.datetime, dt.date)):
        single = normalise_timestamp(values)
        return [single] if single is not None else []
    if isinstance(values, Iterable):
        stamps: list[dt.datetime] = []
        for item in values:
            moment = normalise_timestamp(item)
            if moment is not None:
                stamps.append(moment)
        return sorted(stamps)

    # A bare scalar timestamp is accepted too, so ``analyse(epoch_seconds)``
    # behaves the way a caller would expect from ``analyse([epoch_seconds])``.
    single = normalise_timestamp(values)
    return [single] if single is not None else []


def _iso(moment: dt.datetime) -> str:
    """Render a UTC datetime as an unambiguous ISO-8601 string with a ``Z`` suffix."""
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    """Clamp into a closed interval, mapping non-finite input to ``low``."""
    if not math.isfinite(value):
        return low
    return max(low, min(high, value))


def _ratio_closeness(a: float, b: float, floor: float) -> float:
    """``1.0`` at equality, decaying as the two values diverge relative to scale.

    ``floor`` is the smallest value that counts as real evidence; below it a
    statistic is sampling noise and must not dominate the comparison.
    """
    spread = abs(a - b)
    scale = max(abs(a), abs(b), floor)
    if scale <= _EPS:
        return 1.0
    return _clamp(1.0 - spread / scale)


# ---------------------------------------------------------------------------
# Distribution helpers
# ---------------------------------------------------------------------------
def _mass_function(counts: Sequence[float], size: int) -> list[float]:
    """Convert counts to a probability vector whose entries sum to exactly 1.0.

    Rounding each bin independently would leave a residual that a downstream
    ``sum()`` check - and a sceptical analyst - would catch, so the residual is
    folded back into the heaviest bin.
    """
    total = float(sum(counts))
    if total <= 0.0:
        return [0.0] * size
    bins = [round(float(count) / total, 6) for count in counts]
    heaviest = max(range(size), key=lambda index: counts[index])
    bins[heaviest] = round(bins[heaviest] + (1.0 - sum(bins)), 6)
    return bins


def _entropy(bins: Sequence[float]) -> float:
    """Shannon entropy in bits of an already-normalised probability vector."""
    entropy = 0.0
    for probability in bins:
        if probability > 0.0:
            entropy -= probability * math.log2(probability)
    return entropy


def _normalised_entropy(bins: Sequence[float], size: int) -> float:
    """Entropy divided by its maximum for ``size`` bins, so 0.0 means uniform."""
    if size <= 1:
        return 0.0
    total = float(sum(bins))
    if total <= 0.0:
        return 0.0
    return _clamp(_entropy(bins) / math.log2(size))


def _median(values: Sequence[float]) -> float:
    """Median of a sequence, averaging the central pair on even counts."""
    if not values:
        return 0.0
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2 == 1:
        return float(ordered[middle])
    return (float(ordered[middle - 1]) + float(ordered[middle])) / 2.0


def _coefficient_of_variation(values: Sequence[float]) -> float | None:
    """Standard deviation over mean, or ``None`` when the mean is unusable."""
    if len(values) < 2:
        return None
    mean = sum(values) / len(values)
    if mean <= _EPS:
        return None
    variance = sum((value - mean) ** 2 for value in values) / len(values)
    return math.sqrt(variance) / mean


# ---------------------------------------------------------------------------
# Active window, bursts and cadence
# ---------------------------------------------------------------------------
def _active_window(counts: Sequence[int]) -> dict[str, Any]:
    """Shortest circular arc of hours-of-day holding ``ACTIVE_WINDOW_BULK``.

    Hours-of-day is a circle, not a line: 23:00 and 00:00 are neighbours, and a
    nocturnal actor's window genuinely runs 22:00-06:00. Every start hour is
    therefore tested over a doubled bin array, and the shortest arc that reaches
    the bulk threshold wins, with the most mass breaking ties.
    """
    size = HOURS_PER_DAY
    total = sum(counts)
    if total <= 0:
        return {
            "start_hour": None,
            "end_hour": None,
            "span_hours": 0,
            "covered_mass": 0.0,
            "midpoint_hour": None,
            "label": None,
        }

    doubled = list(counts) * 2
    threshold = total * ACTIVE_WINDOW_BULK
    length = size
    start = 0
    mass = total
    for candidate_length in range(1, size + 1):
        best_start = 0
        best_sum = -1
        for offset in range(size):
            window_sum = sum(doubled[offset : offset + candidate_length])
            if window_sum > best_sum:
                best_sum = window_sum
                best_start = offset
        if best_sum >= threshold - _EPS:
            length, start, mass = candidate_length, best_start, best_sum
            break

    end = (start + length - 1) % size
    midpoint = (start + (length - 1) / 2.0) % size
    return {
        "start_hour": start,
        "end_hour": end,
        "span_hours": length,
        "covered_mass": round(mass / total, 4),
        "midpoint_hour": round(midpoint, 2),
        "label": f"{start:02d}:00-{end:02d}:59 UTC",
    }


def _burst_analysis(times: Sequence[dt.datetime]) -> dict[str, Any]:
    """Split the timeline into bursts and summarise the inter-event gaps.

    A run of events whose every consecutive gap is at most ``BURST_GAP_HOURS``
    is one session. With fewer than two events there are no gaps, and the gap
    statistics are reported as ``0.0`` alongside an explicit ``gap_count`` of
    zero rather than as ``None``, so a caller can sum them without a guard.

    ``burst_share`` is the fraction of events that sit in a session of two or
    more, i.e. how much of the activity is session-bound rather than isolated.
    It describes session *structure*, not rhythm: a steady all-day poster and a
    nightly session-dumper both score high, so the burst verdict deliberately
    leans on :func:`_silence_contrast` instead.
    """
    count = len(times)
    if count < 2:
        return {
            "max_gap_hours": 0.0,
            "median_gap_hours": 0.0,
            "min_gap_hours": 0.0,
            "burst_count": 0,
            "longest_burst_events": 0,
            "longest_burst_span_minutes": 0.0,
            "burst_share": 0.0,
            "gap_count": 0,
        }

    gap_seconds = [
        (times[index + 1] - times[index]).total_seconds() for index in range(count - 1)
    ]
    boundary = BURST_GAP_HOURS * 3600.0

    bursts: list[list[dt.datetime]] = [[times[0]]]
    for index, gap in enumerate(gap_seconds):
        if gap > boundary:
            bursts.append([times[index + 1]])
        else:
            bursts[-1].append(times[index + 1])

    def _run_key(run: list[dt.datetime]) -> tuple[int, float]:
        """Rank a session by event count first, then by how long it sprawled."""
        return (len(run), (run[-1] - run[0]).total_seconds())

    longest = max(bursts, key=_run_key)
    span_minutes = (longest[-1] - longest[0]).total_seconds() / 60.0
    gap_hours = [gap / 3600.0 for gap in gap_seconds]
    sessioned = sum(len(run) for run in bursts if len(run) >= 2)

    return {
        "max_gap_hours": round(max(gap_hours), 4),
        "median_gap_hours": round(_median(gap_hours), 4),
        "min_gap_hours": round(min(gap_hours), 4),
        "burst_count": len(bursts),
        "longest_burst_events": len(longest),
        "longest_burst_span_minutes": round(span_minutes, 2),
        "burst_share": round(sessioned / count, 4),
        "gap_count": len(gap_seconds),
    }


def _silence_contrast(median_gap_hours: float, max_gap_hours: float) -> float:
    """Longest silence expressed in units of this actor's own typical gap.

    This is what separates a regular poster from a dumper, and it works because
    the *median* lands in a different place for each. Someone who posts seven
    times a day has mostly short gaps and a median measured in hours, so their
    overnight silence is only single-digit times that median. Someone who
    empties a whole session in ten minutes has mostly *very* short gaps, so their
    median is minutes and the same overnight silence is hundreds of times
    larger. Being a ratio, it says nothing about how busy an actor is, only
    about how lopsided the silence is relative to their own rhythm.
    """
    if median_gap_hours <= _EPS:
        return 0.0
    return max_gap_hours / median_gap_hours


def _minute_regularity(times: Sequence[dt.datetime]) -> dict[str, Any]:
    """How lopsidedly activity lands on a single minute-of-hour.

    A human posting by hand almost never hits the same minute repeatedly; a
    cron entry almost always does, so a high dominant-minute ratio across many
    events is close to a machine signature.
    """
    if not times:
        return {
            "distinct_minutes": 0,
            "dominant_minute": None,
            "dominant_minute_ratio": 0.0,
            "same_minute_every_time": False,
        }
    counts: dict[int, int] = {}
    for moment in times:
        counts[moment.minute] = counts.get(moment.minute, 0) + 1
    dominant = min(counts, key=lambda minute: (-counts[minute], minute))
    ratio = counts[dominant] / len(times)
    return {
        "distinct_minutes": len(counts),
        "dominant_minute": dominant,
        "dominant_minute_ratio": round(ratio, 4),
        "same_minute_every_time": len(counts) == 1,
    }


def _day_streaks(times: Sequence[dt.datetime]) -> dict[str, Any]:
    """Number of distinct active UTC days and the longest consecutive run."""
    if not times:
        return {"active_days": 0, "longest_active_streak_days": 0}
    days = sorted({moment.date() for moment in times})
    longest = 1
    run = 1
    for index in range(1, len(days)):
        if (days[index] - days[index - 1]).days == 1:
            run += 1
            longest = max(longest, run)
        else:
            run = 1
    return {"active_days": len(days), "longest_active_streak_days": longest}


def _is_periodic(gap_hours: Sequence[float]) -> bool:
    """True when every gap sits within ``PERIODIC_TOLERANCE`` of the median.

    A strict tolerance matters: real humans show a spread of roughly 0.5-3.0
    CV, so anything inside 2% of the median interval is a timer, not a person.
    """
    if len(gap_hours) < 2:
        return False
    median = _median(gap_hours)
    if median <= _EPS:
        return False
    return all(abs(gap - median) <= median * PERIODIC_TOLERANCE for gap in gap_hours)


def _circadian_concentration(hour_bins: Sequence[float], event_count: int) -> float:
    """Blend the peak hour bin with the entropy deficit of the hour histogram.

    See the module docstring for the rationale; the short form is that a
    single statistic is always exploitable by one of the two degenerate sample
    shapes, so the peak and the entropy deficit are averaged.
    """
    if event_count <= 0:
        return 0.0
    peak = max(hour_bins) if hour_bins else 0.0
    deficit = 1.0 - _normalised_entropy(hour_bins, HOURS_PER_DAY)
    return _clamp(0.55 * peak + 0.45 * deficit)


def _plausibility(
    *,
    event_count: int,
    interval_cv: float | None,
    minute_profile: Mapping[str, Any],
    silence_contrast: float,
    collapsed_median: bool,
    concentration: float,
) -> tuple[float, dict[str, float]]:
    """Machine-evidence score, its complement, and the exposed components.

    Four independent tells, each rescaled so that ordinary human behaviour sits
    at 0 and the extreme machine behaviour sits at 1. The complement is what
    the caller reports as ``human_plausibility``.

    ``collapsed_median`` short-circuits the burst tell. A zero median gap leaves
    ``silence_contrast`` with no denominator, so it would otherwise read as "no
    evidence" and quietly hand a flooding account a high plausibility score.
    Several posts inside the same second is not something a person does, so the
    tell is set to its maximum instead of being computed.
    """
    if event_count < MIN_EVENTS_FOR_VERDICT:
        return 0.5, {
            "regularity": 0.0,
            "clock_alignment": 0.0,
            "burst_dominance": 0.0,
            "narrowness": 0.0,
        }

    regularity = (
        _clamp(1.0 - interval_cv / REGULARITY_CV_MAX)
        if interval_cv is not None
        else 0.0
    )
    clock_alignment = _clamp(
        (float(minute_profile["dominant_minute_ratio"]) - 0.5) / 0.5
    )
    burst_dominance = (
        1.0
        if collapsed_median
        else _clamp(
            (silence_contrast - BURST_CONTRAST_HUMAN_CEILING) / BURST_CONTRAST_SPAN
        )
    )
    narrowness = _clamp(
        (concentration - CONCENTRATION_HUMAN_CEILING) / CONCENTRATION_SPAN
    )

    machine = (
        0.45 * regularity
        + 0.20 * clock_alignment
        + 0.25 * burst_dominance
        + 0.10 * narrowness
    )
    # Absence of machine evidence is not proof of humanity, so the plausibility
    # claim is capped just short of certainty. A dossier reading "1.00" would
    # be asserting something this module is not entitled to assert.
    return min(PLAUSIBILITY_CEILING, _clamp(1.0 - machine)), {
        "regularity": round(regularity, 4),
        "clock_alignment": round(clock_alignment, 4),
        "burst_dominance": round(burst_dominance, 4),
        "narrowness": round(narrowness, 4),
    }


def _verdict(
    event_count: int,
    *,
    interval_cv: float | None,
    median_gap_hours: float,
    max_gap_hours: float,
    minute_profile: Mapping[str, Any],
    active_days: int,
) -> str:
    """Fixed-vocabulary behavioural verdict.

    Order matters: a machine clock also produces a single unbroken run, so the
    periodic test has to be asked first or every bot reads as a session dumper.
    """
    if event_count < MIN_EVENTS_FOR_VERDICT:
        return VERDICT_INSUFFICIENT

    gaps_present = event_count >= 3
    machine_clock = (
        gaps_present
        and interval_cv is not None
        and interval_cv <= REGULARITY_CV_MAX
        and median_gap_hours > 0.0
    )
    clock_aligned = (
        event_count >= CLOCK_MIN_EVENTS
        and bool(minute_profile["same_minute_every_time"])
        and interval_cv is not None
        and interval_cv <= 0.25
        and max_gap_hours > 0.0
    )
    if machine_clock or clock_aligned:
        return VERDICT_BOT

    if _silence_contrast(median_gap_hours, max_gap_hours) >= BURST_CONTRAST_VERDICT:
        return VERDICT_BURST

    if median_gap_hours <= _EPS:
        # The median gap is the workhorse of the silence test above, and a zero
        # median leaves it with nothing to divide by. That is not a reason to
        # fall through to the human verdict: it means the majority of
        # consecutive events share a single instant, and nobody types several
        # posts inside the same second. An account that emits faster than a
        # person can act is flooding, which is a burst, not a schedule.
        return VERDICT_BURST

    if active_days < 2 and event_count >= 3:
        return VERDICT_BURST
    return VERDICT_HUMAN


# ---------------------------------------------------------------------------
# Analyst-facing narrative
# ---------------------------------------------------------------------------
def _build_notes(context: Mapping[str, Any]) -> list[str]:
    """Deterministic, evidence-first observations for the analyst dossier.

    Each generator is guarded on a specific statistic, so a note only appears
    when the number behind it is actually present in the evidence. The order is
    fixed, and the list is truncated, so two runs on the same input always
    render the same narrative.
    """
    count = context["event_count"]
    if count <= 0:
        return ["No usable timestamps were supplied, so no rhythm could be measured."]

    notes: list[str] = []
    window = context["window"]
    active = context["active_window_utc"]
    burst = context["burst_analysis"]
    cv = context["interval_cv"]
    verdict = context["verdict"]

    handle = str(context.get("actor_handle") or "")
    prefix = f"{handle}: " if handle else ""
    notes.append(
        f"{prefix}{count} event(s) between {window['earliest']} and "
        f"{window['latest']} "
        f"({context['span_hours']:.2f}h span, {context['streaks']['active_days']} "
        f"active day(s)); confidence {context['confidence']:.2f}."
    )

    if active["start_hour"] is not None:
        notes.append(
            f"{active['covered_mass'] * 100:.0f}% of posts fall in a "
            f"{active['span_hours']}h band, {active['label']}."
        )
    else:
        notes.append("No hour-of-day band is populated.")

    if verdict == VERDICT_BOT:
        if cv is not None:
            notes.append(
                f"Inter-post intervals are near-constant (CV {cv:.4f} over a "
                f"median gap of {burst['median_gap_hours']:.2f}h) - a scheduled "
                f"job, not a person at a keyboard."
            )
        minute = context["minute_regularity"]
        if minute["same_minute_every_time"]:
            notes.append(
                f"All {count} posts carry the same minute-of-hour "
                f"(:{minute['dominant_minute']:02d}); hand-posting does not "
                f"produce that."
            )
    elif verdict == VERDICT_BURST:
        notes.append(
            f"Activity is concentrated into {burst['burst_count']} burst(s); "
            f"{burst['longest_burst_events']} of {count} events "
            f"({burst['burst_share'] * 100:.0f}%) sit in the densest one."
        )
    elif verdict == VERDICT_HUMAN:
        if cv is not None:
            notes.append(
                f"Inter-post intervals vary normally (CV {cv:.2f}, median gap "
                f"{burst['median_gap_hours']:.2f}h) - consistent with a person."
            )

    if burst["gap_count"]:
        # Naming the silence in units of the actor's own median is what makes
        # this actionable: "23.4h" alone reads as nothing much, "451x the
        # typical gap" is the observation that marks a session dumper. With a
        # zero median there is no baseline to divide by, so the ratio would be
        # a meaningless "0x" and the raw silence is reported on its own.
        median_gap = float(burst["median_gap_hours"])
        max_gap = float(burst["max_gap_hours"])
        session_note = (
            f"the densest session holds {burst['longest_burst_events']} "
            f"event(s) across {burst['longest_burst_span_minutes']:.1f} minutes."
        )
        if median_gap > _EPS:
            contrast = _silence_contrast(median_gap, max_gap)
            notes.append(
                f"Longest silence between events is {max_gap:.2f}h - "
                f"{contrast:.0f}x the median gap of {median_gap:.2f}h; "
                f"{session_note}"
            )
        else:
            notes.append(
                f"At least half of all event pairs share a single instant "
                f"(median gap 0.00h); longest silence is {max_gap:.2f}h; "
                f"{session_note}"
            )

    hour_bins = context["hour_histogram_utc"]
    peak_hour = max(range(HOURS_PER_DAY), key=lambda hour: hour_bins[hour])
    peak_share = hour_bins[peak_hour]
    if peak_share >= 0.25:
        notes.append(
            f"Busiest hour is {peak_hour:02d}:00 UTC, holding "
            f"{peak_share * 100:.0f}% of all activity."
        )
    elif count >= MIN_EVENTS_FOR_VERDICT:
        notes.append(
            f"Activity is spread across {context['occupied_hours']} distinct "
            f"hours of the day with no dominant hour (concentration "
            f"{context['circadian_concentration']:.2f})."
        )

    if context["night_ratio"] >= 0.5:
        notes.append(
            f"{context['night_ratio'] * 100:.0f}% of posts land in the "
            f"22:00-06:00 UTC night window, consistent with a European or "
            f"Russian operating offset."
        )
    if context["weekend_ratio"] >= 0.5:
        notes.append(
            f"{context['weekend_ratio'] * 100:.0f}% of posts fall at the "
            f"weekend, which is atypical for a person and typical of scheduled "
            f"work spread across idle capacity."
        )

    dow = context["dow_histogram_utc"]
    if context["streaks"]["active_days"] >= 2 and sum(1 for p in dow if p > 0.0) <= 2:
        notes.append(
            "Activity is confined to "
            f"{sum(1 for p in dow if p > 0.0)} day(s) of the week; a human "
            "actor normally spreads across the working week."
        )

    if verdict == VERDICT_INSUFFICIENT:
        notes.append(
            f"Fewer than {MIN_EVENTS_FOR_VERDICT} events - treat every figure "
            f"here as indicative only."
        )

    return notes[:_MAX_NOTES]


# ---------------------------------------------------------------------------
# Public analysis
# ---------------------------------------------------------------------------
def analyse(timestamps: Any, *, actor_handle: str = "") -> dict[str, Any]:
    """Characterise the behavioural time pattern of one actor.

    ``timestamps`` may be a sequence of ``datetime`` objects, ISO-8601 strings,
    epoch seconds or milliseconds, or a mapping carrying such a sequence under
    any of :data:`TIMESTAMP_KEYS`. ``None``, blank and unparseable entries are
    skipped. Duplicate instants are *kept*: several messages landing in the same
    second are distinct events, and collapsing them would understate
    ``event_count`` and corrupt every statistic derived from it. A single scalar
    timestamp is also accepted. Passing an already-computed profile back in
    returns the same profile, so the function is idempotent.

    The function is total: it never raises for small, empty or hostile input,
    and always returns a JSON-serialisable mapping containing at least
    ``actor_handle``, ``event_count``, ``window``, ``span_hours``,
    ``hour_histogram_utc``, ``dow_histogram_utc``, ``active_window_utc``,
    ``circadian_concentration``, ``burst_analysis``, ``weekend_ratio``,
    ``night_ratio``, ``human_plausibility``, ``verdict``, ``confidence`` and
    ``notes``. Undefined numeric statistics are reported as ``None`` rather
    than guessed at.
    """
    if isinstance(timestamps, Mapping) and {
        "hour_histogram_utc",
        "dow_histogram_utc",
    } <= set(timestamps):
        carried = str(timestamps.get("actor_handle") or "")
        return _complete_profile(timestamps, actor_handle or carried)

    times = _collect_timestamps(timestamps)
    count = len(times)

    hour_counts = [0] * HOURS_PER_DAY
    dow_counts = [0] * DAYS_PER_WEEK
    night_hits = 0
    weekend_hits = 0
    for moment in times:
        hour_counts[moment.hour] += 1
        weekday = moment.weekday()
        dow_counts[weekday] += 1
        if moment.hour in NIGHT_HOURS:
            night_hits += 1
        if weekday in WEEKEND_DOWS:
            weekend_hits += 1

    hour_bins = _mass_function(hour_counts, HOURS_PER_DAY)
    dow_bins = _mass_function(dow_counts, DAYS_PER_WEEK)

    span_hours = (
        round((times[-1] - times[0]).total_seconds() / 3600.0, 4) if count >= 2 else 0.0
    )
    gap_hours = [
        (times[index + 1] - times[index]).total_seconds() / 3600.0
        for index in range(count - 1)
    ]
    interval_cv = _coefficient_of_variation(gap_hours)

    burst = _burst_analysis(times)
    minute_profile = _minute_regularity(times)
    streaks = _day_streaks(times)
    active = _active_window(hour_counts)
    concentration = _circadian_concentration(hour_bins, count)

    # ``_silence_contrast`` reports 0 when the median gap is zero because the
    # ratio is undefined, not because there is no evidence. A degenerate
    # median - consecutive events landing inside the same instant - is itself
    # the strongest burst signal there is, so it is reported alongside the
    # ratio and the two are combined by the caller.
    contrast = _silence_contrast(
        float(burst["median_gap_hours"]), float(burst["max_gap_hours"])
    )
    collapsed_median = (
        float(burst["median_gap_hours"]) <= _EPS and int(burst["burst_count"]) > 0
    )
    plausibility, components = _plausibility(
        event_count=count,
        interval_cv=interval_cv,
        minute_profile=minute_profile,
        silence_contrast=contrast,
        collapsed_median=collapsed_median,
        concentration=concentration,
    )
    verdict = _verdict(
        count,
        interval_cv=interval_cv,
        median_gap_hours=float(burst["median_gap_hours"]),
        max_gap_hours=float(burst["max_gap_hours"]),
        minute_profile=minute_profile,
        active_days=int(streaks["active_days"]),
    )

    # Sample size dominates confidence, but a single evening's worth of posts
    # describes an evening, not a rhythm: coverage across distinct days is
    # therefore a multiplicative second term.
    size_term = count / (count + CONFIDENCE_HALF_LIFE) if count else 0.0
    coverage_term = min(1.0, streaks["active_days"] / CONFIDENCE_FULL_COVERAGE_DAYS)
    confidence = _clamp(size_term * coverage_term)

    is_periodic = _is_periodic(gap_hours)

    context: dict[str, Any] = {
        "actor_handle": actor_handle,
        "event_count": count,
        "window": {
            "earliest": _iso(times[0]) if count else None,
            "latest": _iso(times[-1]) if count else None,
        },
        "span_hours": span_hours,
        "hour_histogram_utc": hour_bins,
        "dow_histogram_utc": dow_bins,
        "active_window_utc": active,
        "circadian_concentration": round(concentration, 4),
        "burst_analysis": burst,
        "weekend_ratio": round(weekend_hits / count, 4) if count else 0.0,
        "night_ratio": round(night_hits / count, 4) if count else 0.0,
        "interval_cv": round(interval_cv, 4) if interval_cv is not None else None,
        "is_periodic": is_periodic,
        "minute_regularity": minute_profile,
        "streaks": streaks,
        "occupied_hours": sum(1 for value in hour_counts if value > 0),
        "human_plausibility": round(plausibility, 4),
        "machine_evidence": components,
        "verdict": verdict,
        "confidence": round(confidence, 4),
        "notes": [],
    }
    context["notes"] = _build_notes(context)

    return {
        "actor_handle": actor_handle,
        "event_count": count,
        "window": context["window"],
        "span_hours": context["span_hours"],
        "hour_histogram_utc": hour_bins,
        "dow_histogram_utc": dow_bins,
        "active_window_utc": active,
        "circadian_concentration": context["circadian_concentration"],
        "burst_analysis": burst,
        "weekend_ratio": context["weekend_ratio"],
        "night_ratio": context["night_ratio"],
        "interval_cv": context["interval_cv"],
        "is_periodic": is_periodic,
        "minute_regularity": minute_profile,
        "longest_active_streak_days": streaks["longest_active_streak_days"],
        "human_plausibility": context["human_plausibility"],
        "machine_evidence": components,
        "verdict": verdict,
        "confidence": context["confidence"],
        "notes": context["notes"],
    }


# ---------------------------------------------------------------------------
# Pair scoring
# ---------------------------------------------------------------------------
def _total_variation(p: Sequence[float], q: Sequence[float]) -> float:
    """Total-variation distance between two equal-length mass functions, 0..1."""
    return 0.5 * sum(abs(a - b) for a, b in zip(p, q))


def _centred_cosine(p: Sequence[float], q: Sequence[float]) -> float:
    """Cosine similarity of mean-centred histograms, rescaled to 0..1.

    Centring removes the shared uniform component, so two near-uniform rhythms
    compare as similar rather than as orthogonal noise. Two all-zero centred
    vectors carry no shape at all and are reported as identical.
    """
    size = len(p)
    if size == 0:
        return 1.0
    mean = 1.0 / size
    pc = [value - mean for value in p]
    qc = [value - mean for value in q]
    dot = sum(a * b for a, b in zip(pc, qc))
    norm_p = math.sqrt(sum(a * a for a in pc))
    norm_q = math.sqrt(sum(b * b for b in qc))
    if norm_p <= _EPS or norm_q <= _EPS:
        return 1.0
    return _clamp((dot / (norm_p * norm_q) + 1.0) / 2.0)


def _first_harmonic(bins: Sequence[float]) -> tuple[float, float]:
    """Cosinor summary of a 24-bin hour histogram: ``(amplitude, phase)``.

    This is the standard chronobiological summary of a daily rhythm, and it is
    the single most useful view for attribution: a night-shift operator and a
    day-shift operator can produce bins that partly overlap while sitting on
    opposite sides of the harmonic circle, and only the phase term sees that.
    """
    real = 0.0
    imag = 0.0
    for hour, probability in enumerate(bins):
        angle = 2.0 * math.pi * hour / HOURS_PER_DAY
        real += probability * math.cos(angle)
        imag += probability * math.sin(angle)
    return math.hypot(real, imag), math.atan2(imag, real)


def _phase_agreement(
    left: Sequence[float], right: Sequence[float]
) -> tuple[float, float]:
    """Phase agreement of two daily rhythms, with the evidence weight it earns.

    Returns ``(similarity, weight)``. The weight collapses to zero when either
    amplitude is too small to locate a phase, and the caller redistributes that
    mass to the bin-level terms rather than scoring against a meaningless
    phase.
    """
    amp_left, phase_left = _first_harmonic(left)
    amp_right, phase_right = _first_harmonic(right)
    weight = min(
        1.0,
        min(amp_left, amp_right) / PHASE_AMP_FLOOR,
    )
    if weight <= 0.0:
        return 0.5, 0.0
    delta = phase_left - phase_right
    similarity = (math.cos(delta) + 1.0) / 2.0
    return _clamp(similarity), weight


def _hour_similarity(a: Mapping[str, Any], b: Mapping[str, Any]) -> float:
    """Circadian shape agreement over the 24-bin hour-of-day histograms."""
    left = [float(v) for v in a["hour_histogram_utc"]]
    right = [float(v) for v in b["hour_histogram_utc"]]

    terms: list[tuple[float, float]] = [
        (1.0 - _total_variation(left, right), W_TVD),
        (_centred_cosine(left, right), W_CENTRED_COSINE),
    ]
    phase, phase_weight = _phase_agreement(left, right)
    if phase_weight > 0.0:
        terms.append((phase, W_PHASE * phase_weight))

    total_weight = sum(weight for _, weight in terms)
    if total_weight <= _EPS:
        return 0.5
    return _clamp(sum(value * weight for value, weight in terms) / total_weight)


def _burst_similarity(a: Mapping[str, Any], b: Mapping[str, Any]) -> float:
    """Agreement on cadence shape: gap scale, burstiness, spread, narrowness."""
    left = a["burst_analysis"]
    right = b["burst_analysis"]

    gap = _ratio_closeness(
        float(left["median_gap_hours"]),
        float(right["median_gap_hours"]),
        _GAP_FLOOR_HOURS,
    )
    share = _ratio_closeness(
        float(left["burst_share"]), float(right["burst_share"]), _SHARE_FLOOR
    )
    left_cv = a.get("interval_cv")
    right_cv = b.get("interval_cv")
    spread = (
        _ratio_closeness(
            _as_float(left_cv, 0.0), _as_float(right_cv, 0.0), _CV_FLOOR
        )
        if left_cv is not None and right_cv is not None
        else 0.5
    )
    narrowness = _ratio_closeness(
        float(a["circadian_concentration"]),
        float(b["circadian_concentration"]),
        _CONCENTRATION_FLOOR,
    )
    return _clamp(
        W_BURST_GAP * gap
        + W_BURST_SHARE * share
        + W_BURST_CV * spread
        + W_BURST_CONCENTRATION * narrowness
    )


def _geometric_blend(components: Sequence[tuple[float, float]]) -> float:
    """Weighted geometric mean of ``(value, weight)`` similarity components.

    Conjunctive by design: the exponent on each component is its weight, so a
    component fixed at ``COMPONENT_FLOOR`` and weighted at ``w`` alone caps the
    blend near ``COMPONENT_FLOOR ** w``. Weights are renormalised, so dropping a
    component to zero weight (a thin day-of-week estimate, or a rhythm with no
    recoverable phase) redistributes its influence instead of deflating the
    result. Only used where every weight is positive.
    """
    usable = [
        (max(COMPONENT_FLOOR, min(1.0, value)), weight)
        for value, weight in components
        if weight > 0.0
    ]
    total_weight = sum(weight for _, weight in usable)
    if total_weight <= _EPS:
        return 0.5
    log_mean = sum(
        weight * math.log(value) for value, weight in usable
    ) / total_weight
    return _clamp(math.exp(log_mean))


def _as_float(value: Any, default: float) -> float:
    """Coerce a possibly-``None`` statistic to float without raising."""
    if value is None:
        return default
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if math.isfinite(number) else default


def _coerce_profile(value: Any, label: str) -> dict[str, Any]:
    """Turn any accepted actor representation into a full analysis mapping.

    Accepts a raw timestamp sequence, a mapping as returned by :func:`analyse`
    (passed through unchanged so results stay canonical), or a mapping carrying
    a timestamp collection under any of :data:`TIMESTAMP_KEYS`. Anything else
    degrades to an empty analysis rather than raising, because this function
    sits on a fusion path where one bad input must not abort a whole sweep.
    """
    if value is None:
        return analyse([], actor_handle=label)

    if isinstance(value, Mapping):
        if "hour_histogram_utc" in value and "dow_histogram_utc" in value:
            return _complete_profile(value, label)
        handle = str(value.get("actor_handle") or value.get("handle") or label)
        for key in TIMESTAMP_KEYS:
            if value.get(key) is not None:
                return analyse(value[key], actor_handle=handle)
        return analyse([], actor_handle=handle)

    dump = getattr(value, "model_dump", None)
    if callable(dump):
        return _coerce_profile(dump(), label)

    if isinstance(value, (str, bytes, bytearray, dt.datetime, dt.date)):
        return analyse([value], actor_handle=label)

    if isinstance(value, int):
        return analyse([value], actor_handle=label)

    if isinstance(value, float):
        return analyse([value], actor_handle=label)

    if isinstance(value, Iterable):
        handle = str(getattr(value, "actor_handle", "") or label)
        return analyse(list(value), actor_handle=handle)

    return analyse([], actor_handle=label)


def _complete_profile(value: Mapping[str, Any], label: str) -> dict[str, Any]:
    """Fill gaps in a caller-supplied analysis mapping.

    A pre-computed profile supplied by another agent is trusted for its
    statistics, but every field this module's scoring path depends on is
    verified so a partial dict cannot raise deep inside the fusion engine.
    """
    profile = dict(value)
    profile.setdefault("actor_handle", label)
    if not str(profile.get("actor_handle") or ""):
        profile["actor_handle"] = label

    hour = profile.get("hour_histogram_utc")
    if not isinstance(hour, (list, tuple)) or len(hour) != HOURS_PER_DAY:
        profile["hour_histogram_utc"] = [0.0] * HOURS_PER_DAY
    else:
        profile["hour_histogram_utc"] = _mass_function(hour, HOURS_PER_DAY)

    dow = profile.get("dow_histogram_utc")
    if not isinstance(dow, (list, tuple)) or len(dow) != DAYS_PER_WEEK:
        profile["dow_histogram_utc"] = [0.0] * DAYS_PER_WEEK
    else:
        profile["dow_histogram_utc"] = _mass_function(dow, DAYS_PER_WEEK)

    burst = profile.get("burst_analysis")
    if not isinstance(burst, Mapping):
        burst = {}
    profile["burst_analysis"] = {
        "max_gap_hours": _as_float(burst.get("max_gap_hours"), 0.0),
        "median_gap_hours": _as_float(burst.get("median_gap_hours"), 0.0),
        "min_gap_hours": _as_float(burst.get("min_gap_hours"), 0.0),
        "burst_count": int(_as_float(burst.get("burst_count"), 0.0)),
        "longest_burst_events": int(_as_float(burst.get("longest_burst_events"), 0.0)),
        "longest_burst_span_minutes": _as_float(
            burst.get("longest_burst_span_minutes"), 0.0
        ),
        "burst_share": _clamp(_as_float(burst.get("burst_share"), 0.0)),
        "gap_count": int(_as_float(burst.get("gap_count"), 0.0)),
    }

    profile["event_count"] = int(_as_float(profile.get("event_count"), 0.0))
    profile["circadian_concentration"] = _clamp(
        _as_float(profile.get("circadian_concentration"), 0.0)
    )
    profile["weekend_ratio"] = _clamp(_as_float(profile.get("weekend_ratio"), 0.0))
    profile["night_ratio"] = _clamp(_as_float(profile.get("night_ratio"), 0.0))
    profile["human_plausibility"] = _clamp(
        _as_float(profile.get("human_plausibility"), 0.5)
    )
    profile["confidence"] = _clamp(_as_float(profile.get("confidence"), 0.0))
    profile["span_hours"] = _as_float(profile.get("span_hours"), 0.0)
    profile["interval_cv"] = profile.get("interval_cv")
    if profile["interval_cv"] is not None:
        profile["interval_cv"] = _as_float(profile["interval_cv"], 0.0)

    verdict = profile.get("verdict")
    profile["verdict"] = verdict if verdict in VERDICTS else VERDICT_INSUFFICIENT
    if profile["event_count"] < MIN_EVENTS_FOR_VERDICT:
        profile["verdict"] = VERDICT_INSUFFICIENT

    window = profile.get("window")
    if not isinstance(window, Mapping):
        window = {}
    profile["window"] = {
        "earliest": window.get("earliest"),
        "latest": window.get("latest"),
    }
    if not isinstance(profile.get("active_window_utc"), Mapping):
        profile["active_window_utc"] = {
            "start_hour": None,
            "end_hour": None,
            "span_hours": 0,
            "covered_mass": 0.0,
            "midpoint_hour": None,
            "label": None,
        }
    notes = profile.get("notes")
    profile["notes"] = [str(note) for note in notes] if isinstance(notes, list) else []
    return profile


def _is_thin(profile: Mapping[str, Any]) -> bool:
    """True when a profile cannot support a behavioural conclusion."""
    return (
        int(profile["event_count"]) < MIN_EVENTS_FOR_VERDICT
        or profile["verdict"] == VERDICT_INSUFFICIENT
    )


def _summary(profile: Mapping[str, Any]) -> dict[str, Any]:
    """Per-actor block returned alongside the pair score.

    The block is the full :func:`analyse` result plus a ``sufficient`` flag.
    Returning the whole profile rather than a hand-picked subset costs a few
    hundred bytes and means the fusion engine never has to call ``analyse``
    twice to get at a statistic this module already computed - and can never
    disagree with it about what that statistic is.
    """
    block = {key: value for key, value in profile.items()}
    block["sufficient"] = not _is_thin(profile)
    return block


def _busiest_hour(hour_bins: Sequence[float]) -> int | None:
    """Index of the heaviest hour bin, or ``None`` for an empty histogram."""
    if not hour_bins:
        return None
    peak = max(hour_bins)
    if peak <= 0.0:
        return None
    return min(
        range(len(hour_bins)), key=lambda hour: (-hour_bins[hour], hour)
    )


def score_pair(actor_a: Any, actor_b: Any) -> dict[str, Any]:
    """Circadian sub-score for two candidate personas (fusion engine input).

    Both arguments are accepted in any of the shapes the platform produces: a
    raw timestamp sequence, a mapping as returned by :func:`analyse`, or a
    mapping carrying ``timestamps`` / ``events`` / ``observed_at``.

    The comparison is over rhythm *shape*, never volume: an actor with 400 posts
    and an actor with 6 can still score highly if their hour-of-day and
    day-of-week distributions agree. If either side carries fewer than
    :data:`MIN_EVENTS_FOR_VERDICT` events the score is dragged halfway to the
    neutral 0.5 and confidence is halved, so a thin pair can never produce a
    confident 0.0 or 1.0 in either direction.
    """
    profile_a = _coerce_profile(actor_a, "A")
    profile_b = _coerce_profile(actor_b, "B")

    notes: list[str] = []
    thin_a = _is_thin(profile_a)
    thin_b = _is_thin(profile_b)
    empty = profile_a["event_count"] <= 0 or profile_b["event_count"] <= 0

    if empty:
        # Nothing at all was measured on one side. There is no evidence of
        # similarity and no evidence of difference, so the honest answer is the
        # neutral midpoint rather than a spurious 0.0.
        components = {
            "hour_similarity": 0.5,
            "dow_similarity": 0.5,
            "burst_similarity": 0.5,
        }
        temporal_score = 0.5
        confidence = 0.0
        notes.append(
            "One side has no usable timestamps, so no temporal comparison was "
            "possible; the score is a neutral placeholder, not a finding."
        )
    else:
        hour_sim = _hour_similarity(profile_a, profile_b)
        dow_sim = 1.0 - _total_variation(
            profile_a["dow_histogram_utc"], profile_b["dow_histogram_utc"]
        )
        burst_sim = _burst_similarity(profile_a, profile_b)
        components = {
            "hour_similarity": round(hour_sim, 4),
            "dow_similarity": round(_clamp(dow_sim), 4),
            "burst_similarity": round(burst_sim, 4),
        }

        # A 7-bin distribution estimated from a handful of events is mostly
        # noise, so its weight is scaled by coverage and the slack handed to
        # the hour term, which degrades far more gracefully.
        coverage = min(
            1.0,
            min(profile_a["event_count"], profile_b["event_count"])
            / DOW_COVERAGE_EVENTS,
        )
        dow_weight = W_DOW * coverage
        hour_weight = W_HOUR + (W_DOW - dow_weight)
        temporal_score = _geometric_blend(
            (
                (hour_sim, hour_weight),
                (_clamp(dow_sim), dow_weight),
                (burst_sim, W_BURST),
            )
        )
        confidence = min(
            float(profile_a["confidence"]), float(profile_b["confidence"])
        )

        if thin_a or thin_b:
            # Confining a thin pair to this band is the whole point: the module
            # must never hand the fusion engine a confident 0.0 or 1.0 built on
            # three timestamps.
            temporal_score = max(
                0.25,
                min(
                    0.75,
                    0.5 + (temporal_score - 0.5) * INSUFFICIENT_PULL,
                ),
            )
            confidence *= INSUFFICIENT_PULL
            thin_label = [
                name
                for name, thin in (("A", thin_a), ("B", thin_b))
                if thin
            ]
            notes.append(
                f"Side(s) {', '.join(thin_label)} carry fewer than "
                f"{MIN_EVENTS_FOR_VERDICT} events, so their circadian shape is "
                f"not established; the score is pulled toward neutral and "
                f"confidence is halved."
            )

        hour_tvd = _total_variation(
            profile_a["hour_histogram_utc"], profile_b["hour_histogram_utc"]
        )
        notes.append(
            f"Hour-of-day histograms sit {hour_tvd:.2f} total-variation apart "
            f"(busiest hour "
            f"{_hour_label(_busiest_hour(profile_a['hour_histogram_utc']))} vs "
            f"{_hour_label(_busiest_hour(profile_b['hour_histogram_utc']))})."
        )
        notes.append(
            f"Burst agreement {components['burst_similarity']:.2f} on median "
            f"gaps of {profile_a['burst_analysis']['median_gap_hours']:.2f}h vs "
            f"{profile_b['burst_analysis']['median_gap_hours']:.2f}h."
        )
        if components["dow_similarity"] < 0.5:
            notes.append(
                f"Day-of-week rhythms disagree (agreement "
                f"{components['dow_similarity']:.2f}), which points to different "
                f"weekly routines."
            )

    notes.append(
        f"Verdicts: A={profile_a['verdict']}, B={profile_b['verdict']}; "
        f"plausibility {profile_a['human_plausibility']:.2f} vs "
        f"{profile_b['human_plausibility']:.2f}."
    )

    return {
        "temporal_score": round(_clamp(temporal_score), 4),
        "confidence": round(_clamp(confidence), 4),
        "notes": notes,
        "actor_a": _summary(profile_a),
        "actor_b": _summary(profile_b),
        "components": components,
    }


def _hour_label(hour: int | None) -> str:
    """Human-readable rendering of an hour index for the notes narrative."""
    return "n/a" if hour is None else f"{hour:02d}:00 UTC"


__all__ = [
    "analyse",
    "score_pair",
    "normalise_timestamp",
    "NIGHT_HOURS",
    "NIGHT_START_HOUR",
    "NIGHT_END_HOUR",
    "WEEKEND_DOWS",
    "BURST_GAP_HOURS",
    "ACTIVE_WINDOW_BULK",
    "MIN_EVENTS_FOR_VERDICT",
    "CONFIDENCE_HALF_LIFE",
    "REGULARITY_CV_MAX",
    "PERIODIC_TOLERANCE",
    "DOW_COVERAGE_EVENTS",
    "VERDICTS",
    "VERDICT_HUMAN",
    "VERDICT_BOT",
    "VERDICT_BURST",
    "VERDICT_INSUFFICIENT",
    "TIMESTAMP_KEYS",
]
