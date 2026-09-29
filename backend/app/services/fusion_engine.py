"""Adjudication layer: four independent signals fused into one auditable verdict.

Why this module exists
----------------------
Four engines each answer the same question - "are these two personas the same
operator?" - and each answers it with a different kind of evidence: co-spend
clustering over the UTXO graph (:mod:`crypto_engine`), shared TLS artefacts
(:mod:`infra_prober`), posting rhythm (:mod:`circadian_engine`) and function-word
fingerprinting (:mod:`stylometry_engine`). None of them is authoritative on its
own, and the most dangerous failure mode in attribution is not a wrong score, it
is a confident average that quietly discards the fact that the evidence
*disagreed*. A tool that reports "0.62, moderately likely" when one channel says
0.95 and another says 0.11 has thrown away the only thing the analyst most needs
to see. This module therefore treats contradiction as a first-class output, not
as a rounding error, and it never lets a thin evidence base borrow confidence it
has not earned.

The confidence formula
----------------------
Let ``A`` be the set of signals that were *evaluated*, ``w_i`` the effective
weight of signal ``i`` and ``x_i`` its normalised score in ``[0, 1]``.

1. **Missing signals are excluded, not zeroed.** A signal that was never
   evaluated carries no weight at all, and the weight it would have held is
   redistributed pro rata across the signals that were. An actor assessed on
   wallet evidence alone is judged on wallet evidence alone; it is not punished
   for having no stylometry corpus. The redistribution is reported in ``notes``
   and the pre-redistribution weights are preserved in ``base_weights`` so the
   reader can see both. A signal that *was* evaluated and found nothing is a
   real ``0.0`` and keeps its weight - that is the distinction the whole design
   turns on.
2. **Weighted mean over the available signals.** ``base = sum(w_i * x_i)``.
3. **Agreement.** ``variance = sum(w_i * (x_i - base)^2)``, which cannot exceed
   ``0.25`` because the ``x_i`` are bounded. ``agreement = 1 - variance / 0.25``
   is ``1.0`` for a single signal and ``0.0`` when the channels sit at opposite
   ends. The mean is tempered by
   ``AGREEMENT_FLOOR + (1 - AGREEMENT_FLOOR) * agreement``: unanimous channels
   are barely touched, widely split ones collapse.
4. **Coverage.** ``coverage`` is the share of the *configured* weight that was
   evaluable at all - ``0.40`` for crypto alone, ``1.0`` when all four engines
   ran. The mean is tempered by
   ``COVERAGE_FLOOR + (1 - COVERAGE_FLOOR) * coverage``, which is what stops one
   strong signal from manufacturing a high-confidence link on its own.
5. **Contradiction.** If any contradiction was recorded, the result is scaled by
   ``1 - settings.contradiction_penalty``. The penalty is multiplicative rather
   than subtractive so it scales the verdict instead of being able to drive a
   low-confidence link negative.

``confidence = clamp01(base) * agreement_factor * coverage_factor * (1 - penalty)``

The effective weights are rounded to six decimals *before* the mean is taken, so
an examiner recomputing ``sum(weights[k] * signals[k])`` from the emitted payload
reproduces the emitted number exactly. That is what makes the breakdown worth
anything: it is arithmetic, not narrative.

Contradiction detection
-----------------------
Detection is conjunctive: a contradiction requires *two* channels to assert
opposite things, never one channel to be low. The rules, evaluated in this fixed
order, are:

``STYLE_VS_CIRCADIAN``
    Stylometry reports a common author (score at or above
    ``STYLE_SAME_AUTHOR_THRESHOLD``) while the circadian profiles are effectively
    disjoint (score at or below ``CIRCADIAN_DISJOINT_THRESHOLD``). Two vendors
    write alike and are never online together.
``CRYPTO_VS_PGP``
    Wallet clusters are shared, yet the two personas have disjoint, non-empty
    PGP key sets. Common control of a wallet, separate cryptographic identity.
``STYLE_VERDICT_VS_CRYPTO``
    Stylometry reports ``DIFFERENT_AUTHORS_*`` while clusters are shared.
``INFRA_SERIAL_VS_HOSTS``
    A shared certificate serial links the endpoints, yet the two personas'
    hostnames are disjoint. Either the serial was reused across unrelated
    tenants, or the hostnames were rotated - both weaken the artefact.
``SIGNAL_SPREAD``
    The strongest and weakest available channels are separated by at least
    ``SIGNAL_SPREAD_MIN`` with the strong channel at or above
    ``SIGNAL_STRONG_THRESHOLD`` and the weak one at or below
    ``SIGNAL_WEAK_THRESHOLD``. This is the backstop that catches a divergence
    no named pair-of-channels rule describes.

Reasons are emitted as stable strings, deduplicated, and caller-supplied
reasons (``contradictions=``) are appended last so an analyst or an upstream
detector can add context without editing this module.

Contract
--------
Every return value is strictly JSON-serialisable: no ``NaN``, no infinity, no
non-string mapping keys, no ``datetime`` objects, and no dependence on dict
iteration order. The ``signals`` sub-mapping is a valid
:class:`~app.models.schemas.SignalBreakdown` payload - :func:`signal_breakdown`
builds the model from it - and :func:`rank_candidates` orders a list of fused
results deterministically, breaking ties on a stable identity key rather than on
insertion or mapping order.
"""

from __future__ import annotations

import datetime as dt
import json
import math
import re
from typing import Any, Iterable, Mapping, Sequence

from ..config import settings
from ..models.schemas import SignalBreakdown
from . import circadian_engine, crypto_engine, infra_prober, stylometry_engine

#: The four attribution signals, in the fixed order used by every emitted list.
SIGNAL_NAMES: tuple[str, ...] = ("crypto", "infra", "temporal", "stylometry")

#: ``settings`` attribute backing each signal's configured weight.
_WEIGHT_ATTRIBUTES: dict[str, str] = {
    "crypto": "weight_crypto",
    "infra": "weight_infra",
    "temporal": "weight_temporal",
    "stylometry": "weight_stylometry",
}

#: Score fields carried in the ``SignalBreakdown`` sub-mapping.
_SCORE_FIELDS: dict[str, str] = {
    "crypto": "crypto_score",
    "infra": "infra_score",
    "temporal": "temporal_score",
    "stylometry": "stylometry_score",
}

#: Evidence keys :func:`fuse` reads for contradiction detection, on top of the
#: per-signal score mappings. They are accepted at the top level of ``signals``
#: so the rule set is usable without :func:`fuse_pair`.
_EVIDENCE_KEYS: tuple[str, ...] = (
    "shared_cluster_ids",
    "shared_clusters",
    "pgp_keys_a",
    "pgp_fingerprints_a",
    "pgp_keys_b",
    "pgp_fingerprints_b",
    "shared_cert_serial",
    "shared_cert_serials",
    "hostnames_a",
    "onion_hosts_a",
    "hostnames_b",
    "onion_hosts_b",
    "shared_hostnames",
)

#: Keys a caller may use to hand a stylometry verdict to :func:`fuse` directly.
_STYLE_VERDICT_KEYS: tuple[str, ...] = ("stylometry_verdict", "author_verdict")

#: Floors for the tempering terms. A single available signal is not evidence of
#: nothing - it is evidence, and it is allowed to speak - but it may not claim
#: the whole verdict, which is what the two floors encode.
COVERAGE_FLOOR = 0.50
AGREEMENT_FLOOR = 0.25

#: Largest weighted variance a ``[0, 1]``-valued signal set can have about its
#: own mean (attained by an even split between 0.0 and 1.0).
MAX_VARIANCE = 0.25

#: Contradiction thresholds. See the module docstring for the rule table.
STYLE_SAME_AUTHOR_THRESHOLD = 0.75
CIRCADIAN_DISJOINT_THRESHOLD = 0.30
STYLE_DIFFERENT_VERDICTS: frozenset[str] = frozenset(
    {"DIFFERENT_AUTHORS_PROBABLE", "DIFFERENT_AUTHORS_POSSIBLE"}
)
SIGNAL_STRONG_THRESHOLD = 0.75
SIGNAL_WEAK_THRESHOLD = 0.20
SIGNAL_SPREAD_MIN = 0.55

#: Decimal places for every emitted float. Six places is far finer than any
#: evidentiary claim the platform makes and coarse enough that the payload is
#: stable across platforms.
_ROUND = 6

#: How many layers of nested payload are unwrapped before a signal is declared
#: malformed. Two is the deepest shape the engines emit; the bound stops a
#: self-referential payload from spinning the resolver.
_MAX_UNWRAP = 3

#: Upper bound on harvested engine notes per signal, and on the emitted list.
_HARVEST_PER_SIGNAL = 2
_MAX_NOTES = 32

#: A v4 PGP fingerprint is 40 hex characters; used to spot keys that arrived as
#: a bare identifier rather than in a labelled field.
_PGP_FINGERPRINT_RE = re.compile(r"^[0-9A-Fa-f]{40}$")

#: A v3-style v6 onion hostname, checked only for the narrative wording.
_ONION_RE = re.compile(r"^[a-z2-7]{16}(?:[a-z2-7]{11})?\.onion$")

_EPS = 1e-12


# ---------------------------------------------------------------------------
# Coercion helpers
# ---------------------------------------------------------------------------
def _clamp01(value: float) -> float:
    """Clamp into ``[0, 1]``, mapping a non-finite input to ``0.0``."""
    if not math.isfinite(value):
        return 0.0
    return max(0.0, min(1.0, value))


def _as_float(value: Any, default: float = 0.0) -> float:
    """Coerce to a finite float, returning ``default`` when that is impossible.

    ``bool`` is rejected deliberately even though it is an ``int``: a ``True``
    arriving where a score was expected is a schema defect, and silently
    scoring it 1.0 would manufacture evidence out of a bug.
    """
    if value is None or isinstance(value, bool):
        return default
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if math.isfinite(number) else default


def _numeric(value: Any) -> float | None:
    """Coerce a numeric scalar to ``float``, *preserving* non-finite values.

    ``None`` means "not a number at all", so the caller can tell an unreadable
    payload from a ``nan``: the two are reported differently because an analyst
    needs to know which mistake upstream made. ``bool`` is rejected even though
    it is an ``int`` - a ``True`` arriving where a score was expected is a
    schema defect, and scoring it 1.0 would manufacture evidence out of a bug.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _is_number(value: Any) -> bool:
    """True when ``value`` is a real, finite numeric scalar."""
    number = _numeric(value)
    return number is not None and math.isfinite(number)


def _as_mapping(value: Any, label: str) -> dict[str, Any]:
    """Return ``value`` as a plain dict, unwrapping pydantic models.

    ``None`` yields an empty mapping so an absent actor degrades to "no
    evidence" instead of raising. Anything that is neither a mapping nor a model
    raises ``TypeError``: a loud failure is the correct outcome for a wrong type
    on an adjudication path.
    """
    if value is None:
        return {}
    if isinstance(value, Mapping):
        return dict(value)
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        dumped = dump()
        if isinstance(dumped, Mapping):
            return dict(dumped)
    raise TypeError(
        f"{label} must be a mapping, got {type(value).__name__}"
    )


def _normalise_key(key: Any) -> str:
    """Fold a mapping key to its canonical ``lower_snake_case`` form."""
    text = str(key).strip().lower().replace("-", "_").replace(" ", "_")
    while "__" in text:
        text = text.replace("__", "_")
    return text.strip("_")


def _index_keys(mapping: Mapping[str, Any]) -> dict[str, Any]:
    """Index a mapping by normalised key, exact canonical spellings winning.

    Without the two-pass rule, a payload carrying both ``crypto`` and
    ``Crypto-Score`` would resolve by insertion order, which is exactly the kind
    of hidden non-determinism this module exists to avoid.
    """
    canonical = {
        spelling
        for name in SIGNAL_NAMES
        for spelling in (name, f"{name}_score")
    } | set(_EVIDENCE_KEYS) | set(_STYLE_VERDICT_KEYS)
    exact: dict[str, Any] = {}
    loose: dict[str, Any] = {}
    for key, value in mapping.items():
        norm = _normalise_key(key)
        if not norm:
            continue
        target = exact if norm in canonical else loose
        target.setdefault(norm, value)
    merged = dict(loose)
    merged.update(exact)
    return merged


def _string_list(source: Any, keys: Sequence[str]) -> list[str]:
    """Collect the first present key from ``source`` as a list of clean strings."""
    if not isinstance(source, Mapping):
        return []
    index = _index_keys(source)
    for key in keys:
        raw = index.get(_normalise_key(key))
        if raw is None:
            continue
        items = [raw] if isinstance(raw, (str, bytes, int, float)) else raw
        if isinstance(items, (str, bytes)) or not isinstance(items, Iterable):
            continue
        out: list[str] = []
        for item in items:
            if isinstance(item, bytes):
                text = item.decode("utf-8", "replace")
            else:
                text = str(item)
            text = text.strip()
            if text:
                out.append(text)
        return list(dict.fromkeys(out))
    return []


def _sorted_set(values: Iterable[str]) -> list[str]:
    """Deduplicate and sort, so a derived set never depends on input order."""
    cleaned = {str(value).strip().lower() for value in values if str(value).strip()}
    return sorted(cleaned)


# ---------------------------------------------------------------------------
# JSON hygiene
# ---------------------------------------------------------------------------
def _iso(moment: dt.datetime) -> str:
    """Render a datetime as an unambiguous ISO-8601 string with a ``Z`` suffix."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=dt.timezone.utc)
    return moment.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def json_safe(value: Any) -> Any:
    """Recursively coerce ``value`` into strictly JSON-serialisable data.

    Floats that are not finite become ``None`` rather than the ``NaN`` and
    ``Infinity`` literals that ``allow_nan=False`` is there to reject;
    datetimes become ISO strings; sets become sorted lists; anything else
    becomes ``str(value)``. The traversal is depth- and order-stable, so equal
    inputs produce equal output.
    """
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, dt.datetime):
        return _iso(value)
    if isinstance(value, (dt.date, dt.time)):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    if isinstance(value, Mapping):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (set, frozenset)):
        try:
            ordered = sorted(value)
        except TypeError:
            ordered = sorted(value, key=repr)
        return [json_safe(item) for item in ordered]
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    return str(value)


# ---------------------------------------------------------------------------
# Weight handling
# ---------------------------------------------------------------------------
def _base_weights() -> dict[str, float]:
    """The four configured weights from ``settings``, normalised to sum to 1.0.

    Read at call time rather than import time so a reconfigured deployment - or
    a test - is honoured without reimporting the module. A configuration whose
    weights are all zero (or negative) is a configuration error, and the honest
    response is an even split rather than a division by zero.
    """
    raw = {
        name: max(0.0, _as_float(getattr(settings, attribute, 0.0), 0.0))
        for name, attribute in _WEIGHT_ATTRIBUTES.items()
    }
    total = sum(raw.values())
    if total <= _EPS:
        return {name: 0.25 for name in SIGNAL_NAMES}
    return {name: raw[name] / total for name in SIGNAL_NAMES}


def _normalise_weights(weights: Mapping[str, float]) -> dict[str, float]:
    """Round to six places and fold the residual into the heaviest entry.

    The residual fold is what keeps the emitted weights summing to 1.0 under
    binary floating point, and the tie-break is ``max`` over a fixed-order
    sequence, so the result never depends on mapping order.
    """
    rounded = {
        name: round(max(0.0, _as_float(weights.get(name, 0.0), 0.0)), _ROUND)
        for name in SIGNAL_NAMES
    }
    residual = round(1.0 - sum(rounded.values()), _ROUND)
    if residual and any(rounded.values()):
        heaviest = max(SIGNAL_NAMES, key=lambda name: rounded[name])
        rounded[heaviest] = round(rounded[heaviest] + residual, _ROUND)
    return rounded


def _redistribute(
    base: Mapping[str, float], available: Sequence[str]
) -> dict[str, float]:
    """Move the weight of unevaluated signals onto the ones that were evaluated.

    Returns the configured weights unchanged when nothing was evaluated, so the
    emitted vector still sums to 1.0 and still means "the configured weight
    this signal would carry" - the notes say plainly that no evidence backed it.
    """
    usable = [name for name in SIGNAL_NAMES if name in available]
    if not usable:
        return _normalise_weights(base)
    mass = sum(base[name] for name in usable)
    if mass <= _EPS:
        even = 1.0 / len(usable)
        return _normalise_weights(
            {name: (even if name in usable else 0.0) for name in SIGNAL_NAMES}
        )
    return _normalise_weights(
        {name: (base[name] / mass if name in usable else 0.0) for name in SIGNAL_NAMES}
    )


# ---------------------------------------------------------------------------
# Signal extraction
# ---------------------------------------------------------------------------
def _extract_score(
    mapping: Mapping[str, Any], name: str
) -> tuple[Any, Any]:
    """Return ``(value, nested_mapping)`` for one signal from a raw payload.

    A signal may arrive as a bare number, as a numeric string, or as the
    engine's own output mapping (``{"crypto_score": ..., "detail": {...}}``).
    ``<name>_score`` is preferred over a bare ``<name>`` key; anything other
    than a mapping is reported as a nested payload of ``None``.
    """
    candidates = (f"{name}_score", name)
    for key in candidates:
        if key in mapping:
            value = mapping[key]
            if isinstance(value, Mapping):
                for inner in candidates:
                    if inner in value:
                        return value[inner], value
                return None, value
            return value, None
    return None, None


def _resolve_signals(
    index: Mapping[str, Any],
) -> tuple[dict[str, float | None], dict[str, dict[str, Any]], list[str]]:
    """Split a raw payload into normalised scores, extras and parse notes.

    A score is ``None`` when the signal was **not evaluated**: absent, ``None``,
    non-numeric, non-finite, or a mapping with no score field. Each of those
    becomes a note, because silently dropping a malformed payload is how a
    channel disappears from a case file without anyone noticing.
    """
    values: dict[str, float | None] = {}
    extras: dict[str, dict[str, Any]] = {}
    notes: list[str] = []

    for name in SIGNAL_NAMES:
        raw, nested = _extract_score(index, name)
        # A payload nested more than a layer or two is a shape we do not
        # recognise; unwrap a bounded number of times rather than recursing
        # without limit.
        for _ in range(_MAX_UNWRAP):
            if nested is None or _is_number(raw):
                break
            raw, deeper = _extract_score(nested, name)
            if deeper is None:
                nested = None
                break
            nested = deeper
        if nested is not None:
            extras[name] = nested

        if raw is None:
            values[name] = None
            continue
        score = _numeric(raw)
        if score is None:
            values[name] = None
            notes.append(
                f"Signal {name!r} was supplied as "
                f"{type(raw).__name__} and could not be read as a score; it was "
                f"treated as not evaluated rather than as a zero."
            )
            continue
        if not math.isfinite(score):
            values[name] = None
            notes.append(
                f"Signal {name!r} was non-finite ({raw!r}) and was treated as not "
                f"evaluated rather than as a zero."
            )
            continue
        if score < 0.0 or score > 1.0:
            clamped = _clamp01(score)
            notes.append(
                f"Signal {name!r} scored {score:.4f}, outside the [0, 1] range, and "
                f"was clamped to {clamped:.4f}."
            )
            score = clamped
        values[name] = score

    return values, extras, notes


def _first_present(
    index: Mapping[str, Any], keys: Sequence[str]
) -> Any:
    """Return the first non-``None`` value among ``keys`` of a normalised index."""
    for key in keys:
        value = index.get(_normalise_key(key))
        if value is not None:
            return value
    return None


def _collect_evidence(
    index: Mapping[str, Any], extras: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    """Gather the contradiction-detection evidence, engines first, keys second.

    Nested engine output wins over a duplicated top-level key, because the
    engine is the authority on what it actually found; the explicit key exists
    for callers using :func:`fuse` without :func:`fuse_pair`.
    """
    crypto_extra = extras.get("crypto", {})
    stylometry_extra = extras.get("stylometry", {})

    shared_clusters = _string_list(
        crypto_extra, ("shared_cluster_ids", "shared_clusters")
    ) or _string_list(index, ("shared_cluster_ids", "shared_clusters"))

    serials = _string_list(index, ("shared_cert_serials",))
    shared_serial = bool(_first_present(index, ("shared_cert_serial",)))
    if not shared_serial and serials:
        shared_serial = True

    verdict = stylometry_extra.get("verdict")
    if not isinstance(verdict, str) or not verdict:
        supplied = _first_present(index, _STYLE_VERDICT_KEYS)
        verdict = supplied if isinstance(supplied, str) and supplied else None

    return {
        "shared_cluster_ids": shared_clusters,
        "pgp_keys_a": _string_list(index, ("pgp_keys_a", "pgp_fingerprints_a")),
        "pgp_keys_b": _string_list(index, ("pgp_keys_b", "pgp_fingerprints_b")),
        "shared_cert_serial": shared_serial,
        "shared_cert_serials": serials,
        "hostnames_a": _string_list(index, ("hostnames_a", "onion_hosts_a")),
        "hostnames_b": _string_list(index, ("hostnames_b", "onion_hosts_b")),
        "shared_hostnames": _string_list(index, ("shared_hostnames",)),
        "stylometry_verdict": verdict,
    }


# ---------------------------------------------------------------------------
# Contradiction detection
# ---------------------------------------------------------------------------
def _contrast_note(strong: float, strong_name: str, weak: float, weak_name: str) -> str:
    """Shared wording for the strongest/weakest channel pair in a reason."""
    return (
        f"strongest channel {strong_name} at {strong:.3f}, "
        f"weakest {weak_name} at {weak:.3f}"
    )


def _ranked_channels(
    values: Mapping[str, float | None],
) -> list[tuple[str, float]]:
    """The evaluated channels as ``(name, score)``, in fixed signal order.

    Ordering by the fixed :data:`SIGNAL_NAMES` sequence rather than by
    dictionary order is what makes a tie between two channels of equal score
    resolve the same way on every run.
    """
    return [
        (name, float(values[name]))
        for name in SIGNAL_NAMES
        if values.get(name) is not None
    ]


def _strongest(scored: Sequence[tuple[str, float]]) -> tuple[str, float]:
    """The highest-scoring channel, earliest in fixed order when scores tie."""
    return max(scored, key=lambda item: (item[1], -SIGNAL_NAMES.index(item[0])))


def _weakest(scored: Sequence[tuple[str, float]]) -> tuple[str, float]:
    """The lowest-scoring channel, earliest in fixed order when scores tie."""
    return min(scored, key=lambda item: (item[1], SIGNAL_NAMES.index(item[0])))


def _detect_contradictions(
    values: Mapping[str, float | None],
    evidence: Mapping[str, Any],
) -> list[str]:
    """Return the deduplicated, deterministically ordered contradiction reasons.

    Every rule needs two channels in explicit opposition. A single low score is
    never a contradiction: a low stylometry score with no crypto evidence is
    just one inconclusive measurement.
    """
    reasons: list[str] = []

    stylometry = values.get("stylometry")
    temporal = values.get("temporal")
    if (
        stylometry is not None
        and temporal is not None
        and stylometry >= STYLE_SAME_AUTHOR_THRESHOLD
        and temporal <= CIRCADIAN_DISJOINT_THRESHOLD
    ):
        reasons.append(
            f"STYLE_VS_CIRCADIAN: stylometry places both personas with a common "
            f"author (score {stylometry:.3f}, threshold "
            f"{STYLE_SAME_AUTHOR_THRESHOLD:.2f}) while their circadian profiles are "
            f"effectively disjoint (score {temporal:.3f}, threshold "
            f"{CIRCADIAN_DISJOINT_THRESHOLD:.2f}). Identical writing habits with no "
            f"overlapping operating rhythm is the signature of a copy, a "
            f"collaborator on the same account, or a shared template."
        )

    clusters = evidence.get("shared_cluster_ids") or []
    pgp_a = evidence.get("pgp_keys_a") or []
    pgp_b = evidence.get("pgp_keys_b") or []
    if clusters and pgp_a and pgp_b and not (set(pgp_a) & set(pgp_b)):
        reasons.append(
            f"CRYPTO_VS_PGP: wallet cluster(s) {', '.join(sorted(clusters))} are "
            f"shared, but the two personas hold disjoint PGP key sets "
            f"(A: {len(pgp_a)} key(s), B: {len(pgp_b)} key(s), no key in common). "
            f"Common control of a wallet under two separate cryptographic "
            f"identities points to custodial or proxied access."
        )

    verdict = evidence.get("stylometry_verdict")
    if clusters and isinstance(verdict, str) and verdict in STYLE_DIFFERENT_VERDICTS:
        reasons.append(
            f"STYLE_VERDICT_VS_CRYPTO: stylometry reports {verdict} while wallet "
            f"cluster(s) {', '.join(sorted(clusters))} link the two personas. "
            f"The shared wallet is more likely a market or an exchange than a "
            f"single operator."
        )

    hostnames_a = evidence.get("hostnames_a") or []
    hostnames_b = evidence.get("hostnames_b") or []
    if (
        evidence.get("shared_cert_serial")
        and hostnames_a
        and hostnames_b
        and not (set(hostnames_a) & set(hostnames_b))
    ):
        reasons.append(
            f"INFRA_SERIAL_VS_HOSTS: a shared certificate serial links the "
            f"endpoints, yet the two personas' hostnames are disjoint "
            f"(A: {', '.join(sorted(hostnames_a))}; B: "
            f"{', '.join(sorted(hostnames_b))}). Either the serial was reused "
            f"across unrelated tenants, or the hostnames were rotated after the "
            f"certificate was issued; the artefact is weaker than it looks."
        )

    scored = _ranked_channels(values)
    if len(scored) >= 2:
        strong_name, strong = _strongest(scored)
        weak_name, weak = _weakest(scored)
        spread = strong - weak
        if (
            spread >= SIGNAL_SPREAD_MIN
            and strong >= SIGNAL_STRONG_THRESHOLD
            and weak <= SIGNAL_WEAK_THRESHOLD
        ):
            reasons.append(
                f"SIGNAL_SPREAD: the evidence channels disagree materially - "
                f"{_contrast_note(strong, strong_name, weak, weak_name)}, a spread "
                f"of {spread:.3f}. A pair of channels this far apart is not a "
                f"rounding difference and must be resolved by an examiner."
            )

    return list(dict.fromkeys(reasons))


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------
def _harvest_notes(
    extras: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    """Lift a couple of engine-authored observations into the fused narrative.

    The engines already explain themselves well; re-deriving their findings here
    would only invite the two narratives to drift apart.
    """
    harvested: list[str] = []
    for name in SIGNAL_NAMES:
        payload = extras.get(name)
        if not isinstance(payload, Mapping):
            continue
        raw_notes = payload.get("notes")
        candidates: list[str] = []
        if isinstance(raw_notes, (list, tuple)):
            candidates.extend(str(note) for note in raw_notes if str(note).strip())
        rationale = payload.get("rationale")
        if isinstance(rationale, str) and rationale.strip():
            candidates.append(rationale)
        for note in candidates[:_HARVEST_PER_SIGNAL]:
            harvested.append(f"[{name}] {note}")
    return harvested


def _redistribution_note(
    available: Sequence[str], base: Mapping[str, float], weights: Mapping[str, float]
) -> str | None:
    """Explain, in words and figures, where the missing weight went."""
    missing = [name for name in SIGNAL_NAMES if name not in available]
    if not missing:
        return None
    released = round(sum(base[name] for name in missing), _ROUND)
    moves = ", ".join(
        f"{name} {base[name]:.3f} -> {weights[name]:.3f}" for name in available
    )
    return (
        f"Not evaluated: {', '.join(missing)}. Their combined configured weight "
        f"({released:.3f}) was redistributed pro rata across the evaluated "
        f"signals ({moves}). Absent evidence is unknown, not negative: an "
        f"unevaluated channel neither supports nor opposes the link, and scoring "
        f"it as a zero would penalise the pair for evidence that was never "
        f"gathered."
    )


def _spread_note(
    available: Sequence[str], values: Mapping[str, float | None]
) -> str | None:
    """Name the highest and lowest available channel, for the audit trail."""
    scored = _ranked_channels(values)
    if not scored:
        return None
    high_name, high = _strongest(scored)
    low_name, low = _weakest(scored)
    return (
        f"Channels considered: {', '.join(available)} - "
        f"{_contrast_note(high, high_name, low, low_name)}."
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def fuse(
    signals: Mapping[str, Any], *, contradictions: Sequence[str] | None = None
) -> dict[str, Any]:
    """Fuse per-signal scores into one confidence with a full audit breakdown.

    ``signals`` is a mapping keyed by ``crypto`` / ``infra`` / ``temporal`` /
    ``stylometry`` (the ``*_score`` suffixed spellings are accepted too), and each
    value may be a number or the corresponding engine's own output mapping.
    Contradiction-evidence keys such as ``shared_cluster_ids`` and
    ``hostnames_a`` are read from the same mapping; see the module docstring.

    A key that is absent, ``None``, non-numeric, non-finite or an empty mapping
    means the signal was **not evaluated**: it is dropped, its weight is
    redistributed, and the redistribution is reported. A signal that was
    evaluated and found nothing keeps its weight as a genuine ``0.0``.

    The returned mapping always carries ``confidence``, ``weights``,
    ``signals``, ``contradiction``, ``contradiction_reasons`` and ``notes``, plus
    ``base_weights``, ``available_signals``, ``missing_signals`` and a ``factors``
    block exposing every term of the formula. ``signals`` is a valid
    :class:`~app.models.schemas.SignalBreakdown` payload; see
    :func:`signal_breakdown`.

    ``contradictions`` is an optional caller-supplied list of reasons. They are
    appended after the detected ones, and any non-empty list flags a
    contradiction and applies ``settings.contradiction_penalty``.

    This function is total and deterministic: identical input yields identical
    output, and the result survives ``json.dumps(..., allow_nan=False)``.
    """
    payload = _as_mapping(signals, "signals")
    index = _index_keys(payload)
    values, extras, parse_notes = _resolve_signals(index)
    evidence = _collect_evidence(index, extras)

    base = _base_weights()
    available = [name for name in SIGNAL_NAMES if values[name] is not None]
    weights = _redistribute(base, available)

    reasons = _detect_contradictions(values, evidence)
    for supplied in contradictions or ():
        text = str(supplied).strip()
        if text:
            reasons.append(text)
    reasons = list(dict.fromkeys(reasons))
    contradiction = bool(reasons)

    scores = {
        name: (0.0 if values[name] is None else float(values[name]))
        for name in SIGNAL_NAMES
    }
    base_mean = sum(weights[name] * scores[name] for name in available)
    variance = sum(
        weights[name] * (scores[name] - base_mean) ** 2 for name in available
    )
    agreement = _clamp01(1.0 - variance / MAX_VARIANCE)
    coverage = _clamp01(sum(base[name] for name in available))
    coverage_factor = COVERAGE_FLOOR + (1.0 - COVERAGE_FLOOR) * coverage
    agreement_factor = AGREEMENT_FLOOR + (1.0 - AGREEMENT_FLOOR) * agreement
    unpenalised = _clamp01(base_mean * coverage_factor * agreement_factor)
    penalty = (
        _clamp01(_as_float(getattr(settings, "contradiction_penalty", 0.0), 0.0))
        if contradiction
        else 0.0
    )
    confidence = _clamp01(unpenalised * (1.0 - penalty))

    notes: list[str] = list(parse_notes)
    notes.extend(_harvest_notes(extras))
    if available:
        redistribution = _redistribution_note(available, base, weights)
        if redistribution:
            notes.append(redistribution)
        spread = _spread_note(available, values)
        if spread:
            notes.append(spread)
        notes.append(
            f"Weighted mean {base_mean:.4f} over {len(available)} available "
            f"signal(s), tempered by agreement {agreement:.4f} (weighted variance "
            f"{variance:.4f} of a possible {MAX_VARIANCE:.2f}) and coverage "
            f"{coverage:.4f} of the configured weight."
        )
        if len(available) == 1:
            notes.append(
                f"Only {available[0]!r} was evaluated, so the verdict rests on a "
                f"single channel. Coverage limits the fused confidence to "
                f"{coverage_factor:.4f} of the raw weighted mean; corroborate with "
                f"at least one independent signal before this reaches a dossier."
            )
        notes.append(
            f"Coverage factor {coverage_factor:.4f} x agreement factor "
            f"{agreement_factor:.4f} x weighted mean {base_mean:.4f} = "
            f"{unpenalised:.4f} before any contradiction penalty."
        )
    else:
        notes.append(
            "No signal engine produced a usable score, so the fused confidence is "
            "0.0. The weights reported are the configured weights; no evidence "
            "backs any of them."
        )

    if contradiction:
        notes.append(
            f"CONTRADICTION: {len(reasons)} conflicting finding(s) recorded, and "
            f"the contradiction penalty of {penalty:.2f} was applied "
            f"multiplicatively, taking confidence from {unpenalised:.4f} to "
            f"{confidence:.4f}. Disagreement is surfaced, not averaged away."
        )
    notes = notes[:_MAX_NOTES]

    rounded_scores = {
        _SCORE_FIELDS[name]: round(scores[name], _ROUND) for name in SIGNAL_NAMES
    }
    result: dict[str, Any] = {
        "confidence": round(confidence, _ROUND),
        "weights": weights,
        "base_weights": base,
        "signals": {
            **rounded_scores,
            "weights": dict(weights),
            "notes": list(notes),
        },
        "available_signals": list(available),
        "missing_signals": [name for name in SIGNAL_NAMES if name not in available],
        "contradiction": contradiction,
        "contradiction_reasons": reasons,
        "notes": list(notes),
        "factors": {
            "base_confidence": round(base_mean, _ROUND),
            "agreement": round(agreement, _ROUND),
            "agreement_factor": round(agreement_factor, _ROUND),
            "coverage": round(coverage, _ROUND),
            "coverage_factor": round(coverage_factor, _ROUND),
            "penalty": round(penalty, _ROUND),
            "unpenalised_confidence": round(unpenalised, _ROUND),
        },
    }
    return json_safe(result)


def signal_breakdown(result: Mapping[str, Any]) -> SignalBreakdown:
    """Validate a fused result's ``signals`` block into a ``SignalBreakdown``.

    Fused results carry more than the schema holds - confidence, contradiction
    state, the factor breakdown - so the model is built from the ``signals``
    sub-mapping rather than from the whole record. Raises ``pydantic.ValidationError``
    if the contract is broken, which is the intended failure: a fused record
    that will not serialise must not reach a case file.
    """
    payload = _as_mapping(result, "result")
    block = payload.get("signals", payload)
    return SignalBreakdown.model_validate(dict(_as_mapping(block, "signals")))


# ---------------------------------------------------------------------------
# Actor evidence plumbing
# ---------------------------------------------------------------------------
def _actor_label(actor: Mapping[str, Any], default: str) -> str:
    """Extract a display label for an actor, falling back to a positional one."""
    index = _index_keys(actor)
    for key in ("handle", "actor_handle", "id", "name"):
        value = index.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return default


def _as_list(value: Any) -> list[Any]:
    """Wrap a scalar in a list; pass a list-like through; ``None`` becomes ``[]``."""
    if value is None:
        return []
    if isinstance(value, (str, bytes, bytearray, Mapping)):
        return [value]
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _probe_list(actor: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Collect an actor's probe dicts, dropping anything that is not a mapping."""
    index = _index_keys(actor)
    for key in ("probes", "infra_probes", "endpoints"):
        raw = index.get(key)
        if raw is None:
            continue
        return [item for item in _as_list(raw) if isinstance(item, Mapping)]
    return []


def _pgp_keys(actor: Mapping[str, Any], addresses: Sequence[str]) -> list[str]:
    """Collect an actor's PGP keys, including 40-hex addresses that are keys."""
    index = _index_keys(actor)
    keys: list[str] = []
    for key in ("pgp_fingerprints", "pgp_keys", "pgp"):
        keys.extend(_string_list(index, (key,)))
    keys.extend(address for address in addresses if _PGP_FINGERPRINT_RE.match(address))
    return _sorted_set(keys)


def _hostnames(
    actor: Mapping[str, Any],
    addresses: Sequence[str],
    probes: Sequence[Mapping[str, Any]],
) -> list[str]:
    """Collect every hostname attributable to an actor.

    Sources, in order: an explicit field, onion addresses, each probe's URL host
    and each probe's certificate SANs. The union is the honest picture, and a
    disjoint comparison against the other actor is only meaningful if both
    sides are gathered this way.
    """
    index = _index_keys(actor)
    hosts: list[str] = []
    for key in ("hostnames", "onion_hosts", "onions", "domains"):
        hosts.extend(_string_list(index, (key,)))
    hosts.extend(address for address in addresses if _ONION_RE.match(address))
    for probe in probes:
        url = str(probe.get("url") or "")
        if "://" in url:
            host = url.split("://", 1)[1].split("/", 1)[0]
            if host:
                hosts.append(host)
        certificate = probe.get("certificate")
        if isinstance(certificate, Mapping):
            hosts.extend(_string_list(certificate, ("san_hosts",)))
        hosts.extend(_string_list(probe, ("san_hosts",)))
    return _sorted_set(hosts)


def _cross_links(
    correlation: Mapping[str, Any], split: int
) -> list[Mapping[str, Any]]:
    """Select the links that actually connect persona A to persona B.

    :func:`infra_prober.correlate` scores the *whole* probe set it is given, so
    a pair whose two personas each cluster internally but never with each other
    would otherwise inherit a high infrastructure score. The engine still
    computes that score - it is preserved in the audit trail - but the signal
    fed to the fusion is restricted to the cross-persona links, which is the
    only evidence that speaks to this specific question.
    """
    identities = correlation.get("probes")
    index_of: dict[str, int] = {}
    if isinstance(identities, list):
        for position, identity in enumerate(identities):
            if isinstance(identity, Mapping):
                probe_id = identity.get("probe_id")
                if probe_id is not None:
                    index_of[str(probe_id)] = position
    links = correlation.get("links")
    if not isinstance(links, list):
        return []
    cross: list[Mapping[str, Any]] = []
    for link in links:
        if not isinstance(link, Mapping) or not link.get("linked"):
            continue
        left = index_of.get(str(link.get("a")))
        right = index_of.get(str(link.get("b")))
        if left is None or right is None:
            continue
        if (left < split) != (right < split):
            cross.append(link)
    return cross


def _cross_serials(cross: Sequence[Mapping[str, Any]]) -> list[str]:
    """Serial numbers shared by at least one cross-persona link."""
    serials = {
        str(reason).split("=", 1)[1]
        for link in cross
        for reason in link.get("reasons", [])
        if isinstance(reason, str) and reason.startswith("cert_serial=")
    }
    return sorted(serials)


def fuse_pair(actor_a: dict, actor_b: dict) -> dict[str, Any]:
    """Run all four engines over two actors' evidence and fuse the results.

    Each actor is a mapping of evidence::

        {
            "handle": "nightowl",
            "addresses": ["bc1q..."],          # BTC wallets for the crypto engine
            "probes": [{"url": ..., "status": "ok", "certificate": {...}}],
            "timestamps": ["2024-03-04T23:17:00Z", ...],
            "corpus": "raw message text, or a list of messages",
            "pgp_fingerprints": ["A1B2..."],   # optional, also read from addresses
            "hostnames": ["abc.onion"],        # optional, also read from probes
            "transactions": [{"txid": ..., "inputs": [...]}],  # optional
        }

    A signal is run **only when both actors carry the evidence it needs**, so an
    actor with wallet evidence alone contributes crypto at full redistributed
    weight rather than three spurious zeros. An engine that ran and found
    nothing contributes a genuine ``0.0``.

    The return value is the :func:`fuse` result plus ``raw`` (the untouched
    per-engine output for the audit trail), ``source_actor`` / ``target_actor``
    and an ``evidence`` census of what each side supplied. Everything is
    JSON-serialisable and reproducible.
    """
    left = _as_mapping(actor_a, "actor_a")
    right = _as_mapping(actor_b, "actor_b")

    handle_a = _actor_label(left, "A")
    handle_b = _actor_label(right, "B")

    left_index = _index_keys(left)
    right_index = _index_keys(right)

    addresses_a = _string_list(left_index, ("addresses", "wallets", "btc_addresses"))
    addresses_b = _string_list(right_index, ("addresses", "wallets", "btc_addresses"))
    timestamps_a = _as_list(left_index.get("timestamps"))
    timestamps_b = _as_list(right_index.get("timestamps"))
    corpus_a = left_index.get("corpus")
    corpus_b = right_index.get("corpus")
    probes_a = _probe_list(left_index)
    probes_b = _probe_list(right_index)

    transactions = left_index.get("transactions") or right_index.get("transactions")
    transactions = _as_list(transactions) or None

    raw: dict[str, Any] = {}
    payload: dict[str, Any] = {}

    if addresses_a and addresses_b:
        raw["crypto"] = crypto_engine.score_pair(
            addresses_a, addresses_b, transactions
        )
        payload["crypto"] = raw["crypto"]
    if timestamps_a and timestamps_b:
        raw["temporal"] = circadian_engine.score_pair(timestamps_a, timestamps_b)
        payload["temporal"] = raw["temporal"]
    if corpus_a and corpus_b:
        raw["stylometry"] = stylometry_engine.score_pair(corpus_a, corpus_b)
        payload["stylometry"] = raw["stylometry"]
    if probes_a and probes_b:
        correlation = infra_prober.correlate([*probes_a, *probes_b])
        raw["infra"] = correlation
        cross = _cross_links(correlation, len(probes_a))
        serials = _cross_serials(cross)
        if cross:
            payload["infra"] = correlation
        else:
            payload["infra"] = {
                "infra_score": 0.0,
                "rationale": (
                    "Both personas supplied probe evidence, but no shared "
                    "certificate serial, SAN or banner links one persona's "
                    "endpoints to the other's. Any clustering the engine found is "
                    "internal to a single persona and says nothing about the pair, "
                    "so the infrastructure signal is a real zero rather than an "
                    "absence."
                ),
            }
        if serials:
            payload["shared_cert_serials"] = serials
            payload["shared_cert_serial"] = True

    payload["hostnames_a"] = _hostnames(left_index, addresses_a, probes_a)
    payload["hostnames_b"] = _hostnames(right_index, addresses_b, probes_b)
    payload["pgp_keys_a"] = _pgp_keys(left_index, addresses_a)
    payload["pgp_keys_b"] = _pgp_keys(right_index, addresses_b)

    result = fuse(payload)
    result["source_actor"] = handle_a
    result["target_actor"] = handle_b
    result["actors"] = {"a": handle_a, "b": handle_b}
    result["raw"] = {name: raw[name] for name in SIGNAL_NAMES if name in raw}
    result["evidence"] = {
        "a": {
            "handle": handle_a,
            "addresses": len(addresses_a),
            "probes": len(probes_a),
            "timestamps": len(timestamps_a),
            "pgp_keys": len(payload["pgp_keys_a"]),
            "hostnames": len(payload["hostnames_a"]),
        },
        "b": {
            "handle": handle_b,
            "addresses": len(addresses_b),
            "probes": len(probes_b),
            "timestamps": len(timestamps_b),
            "pgp_keys": len(payload["pgp_keys_b"]),
            "hostnames": len(payload["hostnames_b"]),
        },
    }
    if transactions is not None:
        result["evidence"]["transactions"] = len(transactions)
    return json_safe(result)


# ---------------------------------------------------------------------------
# Ranking
# ---------------------------------------------------------------------------
def _canonical(entry: Mapping[str, Any]) -> str:
    """A stable, order-independent string form of a fused record."""
    return json.dumps(
        json_safe(entry), sort_keys=True, allow_nan=False, separators=(",", ":")
    )


def _identity(entry: Mapping[str, Any], canonical: str) -> str:
    """Pick the stable tie-break key for a fused record.

    Prefers the domain identifiers a record actually carries, falls back to the
    canonical form. Never falls back to mapping order or to ``id()``, because a
    ranking an examiner cannot reproduce is not evidence.
    """
    index = _index_keys(entry)
    for key in ("candidate_id", "id"):
        value = index.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    source = str(index.get("source_actor") or "").strip()
    target = str(index.get("target_actor") or "").strip()
    if source or target:
        return f"{source}->{target}"
    return canonical


def _rank_key(entry: Mapping[str, Any]) -> tuple[float, str, str]:
    """Sort key: descending confidence, then identity, then canonical form."""
    confidence = _as_float(entry.get("confidence"), 0.0)
    confidence = _clamp01(confidence) if math.isfinite(confidence) else 0.0
    canonical = _canonical(entry)
    return (-confidence, _identity(entry, canonical), canonical)


def rank_candidates(pairs: Iterable[dict]) -> list[dict]:
    """Order fused candidate links by descending confidence, deterministically.

    The input is returned unchanged (in a new list) - no copying, no mutation -
    so a caller holding the originals is unaffected. Ties break on
    ``candidate_id`` / ``id``, then on ``source_actor``/``target_actor``, then on
    a canonical JSON rendering of the record, which is stable across runs,
    processes and mapping orders. A record with a non-finite confidence is
    ranked as ``0.0`` rather than raising: a corrupt row must not stop an
    analyst from seeing the rest of the queue.

    Raises ``TypeError`` for a non-mapping element rather than silently
    translating it into a zero-confidence record.
    """
    ranked: list[dict] = []
    for position, entry in enumerate(pairs or ()):
        if not isinstance(entry, Mapping):
            raise TypeError(
                f"rank_candidates expected fused result mappings; element "
                f"{position} is {type(entry).__name__}"
            )
        ranked.append(entry)
    return sorted(ranked, key=_rank_key)


__all__ = [
    "fuse",
    "fuse_pair",
    "rank_candidates",
    "signal_breakdown",
    "json_safe",
    "SIGNAL_NAMES",
]
