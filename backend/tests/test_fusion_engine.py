"""Contract tests for the adjudication fusion engine.

The fusion layer is the only place in the platform where four independently
gathered kinds of evidence are summed into a single number an examiner will act
on. Three properties outrank every individual assertion here, and each gets
dedicated coverage:

1. **Missing evidence is never evidence against.** A channel that was not
   evaluated must contribute no weight and must be reported as unevaluated, while
   a channel that ran and found nothing keeps its weight as a genuine ``0.0``.
   Getting this backwards is the difference between "we know nothing" and "they
   are different people", so the tests assert the distinction on weights, on
   confidence and on the audit trail.
2. **Contradiction is surfaced, not averaged away.** Every rule must be
   conjunctive, the reasons must accumulate and deduplicate, and the penalty must
   be multiplicative, read from settings, and applied identically whether the
   contradiction was detected or supplied by the caller.
3. **The result is auditable and reproducible.** The emitted weights must let an
   examiner recompute the reported weighted mean from the emitted scores, the
   payload must survive ``json.dumps(..., allow_nan=False)``, and identical input
   must produce byte-identical output regardless of mapping order.

Everything here runs offline. The crypto engine defaults to its deterministic
seeded mode, and the infrastructure tests hand in probe fixtures rather than
dialing a host.
"""

from __future__ import annotations

import ast
import datetime as dt
import json
import math
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.config import settings  # noqa: E402
from backend.app.models.schemas import SignalBreakdown  # noqa: E402
from backend.app.services import (  # noqa: E402
    circadian_engine,
    crypto_engine,
    fusion_engine,
    infra_prober,
    stylometry_engine,
)
from backend.app.services.fusion_engine import (  # noqa: E402
    SIGNAL_NAMES,
    fuse,
    fuse_pair,
    json_safe,
    rank_candidates,
    signal_breakdown,
)

SCORE_FIELDS = {
    "crypto": "crypto_score",
    "infra": "infra_score",
    "temporal": "temporal_score",
    "stylometry": "stylometry_score",
}


# ---------------------------------------------------------------------------
# Fixtures: evidence shaped exactly as the real engines expect to receive it
# ---------------------------------------------------------------------------
A1 = "bc1qnightowlasset00000000000000000001"
A2 = "1NightOwlContinuationsAddress000000001"
B1 = "bc1qdayfoxasset0000000000000000000001"
B2 = "1DayFoxContinuationsAddress0000000001"

FINGERPRINT_A = "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"
FINGERPRINT_B = "FEDCBA98765432100123456789ABCDEF01234567"

#: Co-spend edge tying A1 and B1 into one wallet cluster, plus a private edge
#: that must not leak across personas.
SHARED_TX = {"txid": "tx-shared-01", "inputs": [A1, B1]}
PRIVATE_TX_A = {"txid": "tx-a-01", "inputs": [A1, A2]}

#: Persona A posts in the small hours; persona B has been diurnal for months.
NIGHT_TIMESTAMPS = [
    "2024-03-04T23:14:00Z",
    "2024-03-05T00:41:00Z",
    "2024-03-06T22:58:00Z",
    "2024-03-07T01:12:00Z",
    "2024-03-08T23:31:00Z",
    "2024-03-09T02:04:00Z",
]
SAME_RHYTHM_TIMESTAMPS = [
    "2024-03-04T23:19:00Z",
    "2024-03-05T00:38:00Z",
    "2024-03-06T23:02:00Z",
    "2024-03-07T01:09:00Z",
    "2024-03-08T23:27:00Z",
    "2024-03-09T02:11:00Z",
]
DAY_TIMESTAMPS = [
    "2024-03-04T09:14:00Z",
    "2024-03-05T12:41:00Z",
    "2024-03-06T10:58:00Z",
    "2024-03-07T13:12:00Z",
    "2024-03-08T09:31:00Z",
    "2024-03-09T11:04:00Z",
]

CORPUS_A = (
    "the same analysis arrives every friday and i never learn the names. "
    "we should probably write it down. again. it is not urgent but it is "
    "certainly going to be asked for at the worst possible moment. "
) * 30
CORPUS_B_SAME = (
    "the same analysis arrives every friday and i never learn the names. "
    "we should probably write it down. again. it is not urgent but it is "
    "certainly going to be asked for at the worst possible moment. "
) * 30
CORPUS_B_DIFFERENT = (
    "listen the invoice is wrong again and nobody upstream will admit it. "
    "i am done chasing this around the building. ship the corrected ledger "
    "or absorb the variance yourself, but do not ask me a third time. "
) * 30


def probe(host: str, serial: str, banner: str = "nginx/1.24.0") -> dict[str, Any]:
    """A probe fixture in the shape ``infra_prober._probe_identity`` reads.

    ``banner`` is a parameter because a shared server banner is itself a link in
    the correlation engine, so two personas that should be judged unlinked need
    distinguishable banners.
    """
    return {
        "url": f"http://{host}",
        "status": "ok",
        "serial_hex": serial,
        "san_hosts": [host],
        "banner": banner,
    }


UNIFORM = {"crypto": 0.8, "infra": 0.8, "temporal": 0.8, "stylometry": 0.8}


# ---------------------------------------------------------------------------
# Weight handling
# ---------------------------------------------------------------------------
def test_configured_weights_are_the_documented_ones():
    result = fuse(UNIFORM)

    assert result["weights"] == {
        "crypto": pytest.approx(settings.weight_crypto, abs=1e-6),
        "infra": pytest.approx(settings.weight_infra, abs=1e-6),
        "temporal": pytest.approx(settings.weight_temporal, abs=1e-6),
        "stylometry": pytest.approx(settings.weight_stylometry, abs=1e-6),
    }
    assert result["available_signals"] == list(SIGNAL_NAMES)
    assert result["missing_signals"] == []
    assert result["contradiction"] is False
    assert result["contradiction_reasons"] == []


def test_effective_weights_sum_to_one():
    result = fuse({"crypto": 0.7, "stylometry": 0.3})

    assert sum(result["weights"].values()) == pytest.approx(1.0, abs=1e-9)
    assert result["signals"]["weights"] == result["weights"]


def test_all_four_signals_fuse_into_a_bounded_confidence():
    result = fuse(UNIFORM)

    assert 0.0 < result["confidence"] < 1.0
    assert result["confidence"] == pytest.approx(0.8, abs=1e-6)
    assert result["factors"]["coverage"] == pytest.approx(1.0)
    assert result["factors"]["coverage_factor"] == pytest.approx(1.0)
    assert result["factors"]["agreement"] == pytest.approx(1.0)
    assert result["factors"]["penalty"] == pytest.approx(0.0)


def test_emitted_weights_reproduce_the_emitted_weighted_mean():
    """The breakdown is arithmetic: an examiner must be able to redo the sum."""
    result = fuse({"crypto": 0.91, "infra": 0.37, "temporal": 0.62})

    recomputed = sum(
        result["weights"][name] * result["signals"][SCORE_FIELDS[name]]
        for name in result["available_signals"]
    )
    assert recomputed == pytest.approx(result["factors"]["base_confidence"], abs=1e-6)


def test_single_signal_takes_all_the_weight_and_is_coverage_limited():
    result = fuse({"crypto": 0.9})

    assert result["weights"] == {
        "crypto": 1.0,
        "infra": 0.0,
        "temporal": 0.0,
        "stylometry": 0.0,
    }
    assert result["missing_signals"] == ["infra", "temporal", "stylometry"]

    # coverage 0.40 -> 0.50 + 0.50 * 0.40 = 0.70; one channel agrees with
    # itself perfectly, so only the coverage floor damps it.
    assert result["factors"]["coverage"] == pytest.approx(settings.weight_crypto)
    assert result["factors"]["coverage_factor"] == pytest.approx(0.70, abs=1e-6)
    assert result["confidence"] == pytest.approx(0.9 * 0.70, abs=1e-6)

    notes = " ".join(result["notes"])
    assert "redistributed pro rata" in notes
    assert "Not evaluated: infra, temporal, stylometry" in notes
    assert "single channel" in notes


def test_missing_weight_is_redistributed_pro_rata():
    result = fuse({"crypto": 0.6, "temporal": 0.4})

    mass = settings.weight_crypto + settings.weight_temporal
    assert result["weights"]["crypto"] == pytest.approx(
        settings.weight_crypto / mass, abs=1e-6
    )
    assert result["weights"]["temporal"] == pytest.approx(
        settings.weight_temporal / mass, abs=1e-6
    )
    assert result["weights"]["infra"] == 0.0
    assert result["weights"]["stylometry"] == 0.0


def test_weights_are_read_from_settings_at_call_time(monkeypatch):
    monkeypatch.setattr(settings, "weight_crypto", 1.0)
    monkeypatch.setattr(settings, "weight_infra", 0.0)
    monkeypatch.setattr(settings, "weight_temporal", 0.0)
    monkeypatch.setattr(settings, "weight_stylometry", 0.0)

    result = fuse(UNIFORM)

    # Only crypto carries weight, so the mean is the crypto score itself and a
    # full-weight channel is not coverage-limited.
    assert result["weights"] == {
        "crypto": 1.0,
        "infra": 0.0,
        "temporal": 0.0,
        "stylometry": 0.0,
    }
    assert result["base_weights"]["crypto"] == pytest.approx(1.0)
    assert result["factors"]["coverage"] == pytest.approx(1.0)
    assert result["confidence"] == pytest.approx(0.8, abs=1e-6)


def test_all_zero_weights_do_not_divide_by_zero(monkeypatch):
    for attribute in (
        "weight_crypto",
        "weight_infra",
        "weight_temporal",
        "weight_stylometry",
    ):
        monkeypatch.setattr(settings, attribute, 0.0)

    result = fuse(UNIFORM)

    assert result["weights"] == {name: 0.25 for name in SIGNAL_NAMES}
    assert sum(result["weights"].values()) == pytest.approx(1.0, abs=1e-9)
    assert 0.0 < result["confidence"] <= 1.0


# ---------------------------------------------------------------------------
# Missing is not zero
# ---------------------------------------------------------------------------
def test_an_evaluated_zero_keeps_its_weight_but_a_missing_signal_releases_it():
    evaluated_zero = fuse({"crypto": 0.9, "stylometry": 0.0})
    omitted = fuse({"crypto": 0.9})

    # Stylometry ran and found nothing: it keeps its configured share.
    assert evaluated_zero["available_signals"] == ["crypto", "stylometry"]
    assert evaluated_zero["weights"]["stylometry"] == pytest.approx(
        settings.weight_stylometry
        / (settings.weight_crypto + settings.weight_stylometry),
        abs=1e-6,
    )
    assert evaluated_zero["signals"]["stylometry_score"] == 0.0

    # Stylometry was never gathered: it keeps nothing at all.
    assert omitted["available_signals"] == ["crypto"]
    assert omitted["weights"]["stylometry"] == 0.0

    # A single strong channel that the others failed to support must not be
    # dragged down by evidence nobody collected.
    assert omitted["confidence"] > evaluated_zero["confidence"]


def test_none_valued_signal_is_treated_as_unevaluated():
    assert fuse({"crypto": 0.9, "stylometry": None}) == fuse({"crypto": 0.9})


def test_unreadable_signal_is_unevaluated_with_a_note_and_never_a_silent_zero():
    result = fuse({"crypto": 0.9, "stylometry": "high"})

    assert result["available_signals"] == ["crypto"]
    assert result["missing_signals"] == ["infra", "temporal", "stylometry"]
    assert any("could not be read as a score" in note for note in result["notes"])
    assert any(
        "not evaluated rather than as a zero" in note for note in result["notes"]
    )


def test_empty_engine_payload_counts_as_unevaluated():
    result = fuse({"crypto": 0.9, "stylometry": {"notes": ["no corpus"]}})

    assert result["available_signals"] == ["crypto"]
    assert result["missing_signals"] == ["infra", "temporal", "stylometry"]


def test_out_of_range_score_is_clamped_and_reported():
    result = fuse({"crypto": 1.4, "temporal": -0.2})

    assert result["signals"]["crypto_score"] == 1.0
    assert result["signals"]["temporal_score"] == 0.0
    assert any("clamped" in note for note in result["notes"])
    assert 0.0 <= result["confidence"] <= 1.0


def test_no_evidence_at_all_yields_zero_without_raising():
    result = fuse({})

    assert result["confidence"] == 0.0
    assert result["available_signals"] == []
    assert result["missing_signals"] == list(SIGNAL_NAMES)
    assert sum(result["weights"].values()) == pytest.approx(1.0, abs=1e-9)
    assert any("No signal engine produced a usable score" in n for n in result["notes"])


def test_agreement_tempering_collapses_widely_split_channels():
    agreeing = fuse({"crypto": 0.9, "stylometry": 0.9, "temporal": 0.9, "infra": 0.9})
    split = fuse({"crypto": 1.0, "stylometry": 0.0, "temporal": 1.0, "infra": 0.0})

    assert agreeing["confidence"] > split["confidence"]
    assert agreeing["factors"]["agreement_factor"] == pytest.approx(1.0, abs=1e-6)
    assert split["factors"]["agreement"] < agreeing["factors"]["agreement"]


# ---------------------------------------------------------------------------
# Contradiction detection
# ---------------------------------------------------------------------------
def test_shared_crypto_with_disjoint_circadian_and_split_pgp_keys_is_flagged():
    result = fuse(
        {
            "crypto": {
                "crypto_score": 0.5,
                "shared_cluster_ids": ["cluster-0000"],
            },
            "temporal": 0.05,
            "stylometry": 0.9,
            "pgp_keys_a": [FINGERPRINT_A],
            "pgp_keys_b": [FINGERPRINT_B],
        }
    )

    assert result["contradiction"] is True
    reasons = result["contradiction_reasons"]
    assert any(reason.startswith("STYLE_VS_CIRCADIAN") for reason in reasons)
    assert any(reason.startswith("CRYPTO_VS_PGP") for reason in reasons)
    assert any("cluster-0000" in reason for reason in reasons)
    assert any("no key in common" in reason for reason in reasons)


def test_style_against_circadian_needs_both_channels_to_oppose():
    """A rule requires two channels in opposition, never one low score."""
    def contradicts(result: dict[str, Any]) -> bool:
        return any(
            reason.startswith("STYLE_VS_CIRCADIAN")
            for reason in result["contradiction_reasons"]
        )

    assert contradicts(fuse({"stylometry": 0.9, "temporal": 0.2}))
    # Rhythms that merely differ are not disjoint profiles.
    assert not contradicts(fuse({"stylometry": 0.9, "temporal": 0.5}))
    # A low stylometry score is inconclusive, not opposed.
    assert not contradicts(fuse({"stylometry": 0.5, "temporal": 0.1}))
    # A single channel, however low, is never a contradiction.
    assert fuse({"temporal": 0.0})["contradiction_reasons"] == []
    # One side of the pair missing entirely cannot contradict anything.
    assert not contradicts(fuse({"stylometry": 0.9}))


def test_shared_clusters_with_overlapping_pgp_keys_are_not_contradictory():
    result = fuse(
        {
            "crypto": {"crypto_score": 0.5, "shared_cluster_ids": ["cluster-0000"]},
            "pgp_keys_a": [FINGERPRINT_A],
            "pgp_keys_b": [FINGERPRINT_A],
        }
    )

    assert not any(
        reason.startswith("CRYPTO_VS_PGP") for reason in result["contradiction_reasons"]
    )


def test_empty_pgp_sets_never_contradict():
    result = fuse(
        {
            "crypto": {"crypto_score": 0.5, "shared_cluster_ids": ["cluster-0000"]},
            "pgp_keys_a": [],
            "pgp_keys_b": [FINGERPRINT_B],
        }
    )

    assert not any(
        reason.startswith("CRYPTO_VS_PGP") for reason in result["contradiction_reasons"]
    )


def test_different_authors_verdict_against_shared_clusters_is_flagged():
    result = fuse(
        {
            "crypto": {"crypto_score": 0.5, "shared_cluster_ids": ["cluster-0000"]},
            "stylometry": {
                "stylometry_score": 0.4,
                "verdict": "DIFFERENT_AUTHORS_PROBABLE",
            },
        }
    )

    assert any(
        reason.startswith("STYLE_VERDICT_VS_CRYPTO")
        for reason in result["contradiction_reasons"]
    )
    assert any(
        "DIFFERENT_AUTHORS_PROBABLE" in reason
        for reason in result["contradiction_reasons"]
    )


def test_shared_serial_with_disjoint_hostnames_is_flagged():
    result = fuse(
        {
            "infra": {"infra_score": 0.7},
            "shared_cert_serial": True,
            "hostnames_a": ["aaa.onion"],
            "hostnames_b": ["bbb.onion"],
        }
    )

    assert any(
        reason.startswith("INFRA_SERIAL_VS_HOSTS")
        for reason in result["contradiction_reasons"]
    )


def test_shared_serial_with_overlapping_hostnames_is_not_flagged():
    result = fuse(
        {
            "infra": {"infra_score": 0.8},
            "shared_cert_serial": True,
            "hostnames_a": ["aaa.onion", "shared.onion"],
            "hostnames_b": ["shared.onion", "bbb.onion"],
        }
    )

    assert not any(
        reason.startswith("INFRA_SERIAL_VS_HOSTS")
        for reason in result["contradiction_reasons"]
    )


def test_wide_signal_spread_is_caught_as_a_backstop():
    result = fuse({"crypto": 0.95, "temporal": 0.05})

    assert any(
        reason.startswith("SIGNAL_SPREAD") for reason in result["contradiction_reasons"]
    )


def test_caller_reasons_are_appended_after_detected_ones_and_deduplicated():
    payload = {"stylometry": 0.9, "temporal": 0.2}

    result = fuse(
        payload,
        contradictions=["MANUAL_REVIEW", "MANUAL_REVIEW", "  ", "MISSING_EVIDENCE"],
    )

    assert result["contradiction"] is True
    reasons = result["contradiction_reasons"]
    assert reasons[0].startswith("STYLE_VS_CIRCADIAN")
    assert reasons[-2:] == ["MANUAL_REVIEW", "MISSING_EVIDENCE"]
    assert len(reasons) == len(set(reasons))
    assert all(reason.strip() for reason in reasons)


def test_caller_reason_duplicating_a_detected_reason_is_collapsed():
    detected = fuse({"stylometry": 0.9, "temporal": 0.2})["contradiction_reasons"]
    result = fuse({"stylometry": 0.9, "temporal": 0.2}, contradictions=detected)

    assert result["contradiction_reasons"] == detected


# ---------------------------------------------------------------------------
# Contradiction penalty
# ---------------------------------------------------------------------------
def test_penalty_is_multiplicative_and_read_from_settings():
    clean = fuse(UNIFORM)
    flagged = fuse(UNIFORM, contradictions=["MANUAL_REVIEW"])

    penalty = settings.contradiction_penalty
    assert flagged["confidence"] == pytest.approx(
        clean["confidence"] * (1.0 - penalty), abs=1e-6
    )
    assert flagged["factors"]["penalty"] == pytest.approx(penalty)
    assert flagged["factors"]["unpenalised_confidence"] == pytest.approx(
        clean["confidence"], abs=1e-6
    )
    assert flagged["confidence"] < clean["confidence"]
    assert any("CONTRADICTION" in note for note in flagged["notes"])


def test_penalty_magnitude_tracks_the_configured_value(monkeypatch):
    monkeypatch.setattr(settings, "contradiction_penalty", 0.5)
    half = fuse(UNIFORM, contradictions=["MANUAL_REVIEW"])
    monkeypatch.setattr(settings, "contradiction_penalty", 0.9)
    almost = fuse(UNIFORM, contradictions=["MANUAL_REVIEW"])

    assert half["confidence"] == pytest.approx(0.8 * 0.5, abs=1e-6)
    assert almost["confidence"] == pytest.approx(0.8 * 0.1, abs=1e-6)


def test_out_of_range_penalty_is_clamped_rather_than_inverting_the_verdict(monkeypatch):
    monkeypatch.setattr(settings, "contradiction_penalty", 5.0)
    result = fuse(UNIFORM, contradictions=["MANUAL_REVIEW"])

    assert result["factors"]["penalty"] == pytest.approx(1.0)
    assert result["confidence"] == pytest.approx(0.0, abs=1e-9)
    assert 0.0 <= result["confidence"] <= 1.0


def test_no_contradiction_means_no_penalty_applied():
    result = fuse(UNIFORM, contradictions=[])

    assert result["contradiction"] is False
    assert result["factors"]["penalty"] == pytest.approx(0.0)
    assert not any("CONTRADICTION" in note for note in result["notes"])


# ---------------------------------------------------------------------------
# fuse_pair against the real engines
# ---------------------------------------------------------------------------
def test_fuse_pair_consumes_real_engine_output():
    actor_a = {
        "handle": "nightowl",
        "addresses": [A1, A2],
        "timestamps": NIGHT_TIMESTAMPS,
        "corpus": CORPUS_A,
        "probes": [probe("aaa.onion", "aa11bb22")],
        "pgp_fingerprints": [FINGERPRINT_A],
        "transactions": [SHARED_TX, PRIVATE_TX_A],
    }
    actor_b = {
        "handle": "dayfox",
        "addresses": [B1, B2],
        "timestamps": SAME_RHYTHM_TIMESTAMPS,
        "corpus": CORPUS_B_SAME,
        "probes": [probe("bbb.onion", "aa11bb22")],
        "pgp_fingerprints": [FINGERPRINT_B],
    }

    result = fuse_pair(actor_a, actor_b)

    # The audit trail holds what the engines actually returned, not a
    # reconstruction of it.
    expected_crypto = crypto_engine.score_pair(
        [A1, A2], [B1, B2], [SHARED_TX, PRIVATE_TX_A]
    )
    assert result["raw"]["crypto"] == json_safe(expected_crypto)
    assert result["raw"]["temporal"] == json_safe(
        circadian_engine.score_pair(NIGHT_TIMESTAMPS, SAME_RHYTHM_TIMESTAMPS)
    )
    assert result["raw"]["stylometry"] == json_safe(
        stylometry_engine.score_pair(CORPUS_A, CORPUS_B_SAME)
    )
    assert result["raw"]["infra"] == json_safe(
        infra_prober.correlate(
            [probe("aaa.onion", "aa11bb22"), probe("bbb.onion", "aa11bb22")]
        )
    )

    # A shared wallet cluster is real crypto evidence, and it reaches the mean.
    assert result["signals"]["crypto_score"] == pytest.approx(
        expected_crypto["crypto_score"], abs=1e-6
    )
    assert result["signals"]["crypto_score"] > 0.0
    assert result["available_signals"] == list(SIGNAL_NAMES)
    assert result["source_actor"] == "nightowl"
    assert result["target_actor"] == "dayfox"
    assert 0.0 < result["confidence"] < 1.0


def test_fuse_pair_only_runs_a_signal_when_both_actors_supply_its_evidence():
    result = fuse_pair(
        {"handle": "walletonly", "addresses": [A1]},
        {"handle": "walletonly2", "addresses": [B1]},
    )

    assert sorted(result["raw"]) == ["crypto"]
    assert result["available_signals"] == ["crypto"]
    assert result["missing_signals"] == ["infra", "temporal", "stylometry"]
    # The lone channel is judged alone, at the redistributed weight, and is not
    # diluted by three zeros that were never measured.
    assert result["weights"]["crypto"] == 1.0
    assert result["weights"]["temporal"] == 0.0
    assert result["evidence"]["a"]["timestamps"] == 0
    assert result["evidence"]["b"]["probes"] == 0


def test_fuse_pair_records_the_evidence_census_per_actor():
    result = fuse_pair(
        {
            "handle": "nightowl",
            "addresses": [A1, A2],
            "timestamps": NIGHT_TIMESTAMPS,
            "probes": [probe("aaa.onion", "aa11")],
        },
        {
            "handle": "dayfox",
            "addresses": [B1],
            "timestamps": SAME_RHYTHM_TIMESTAMPS,
            "probes": [probe("bbb.onion", "aa11")],
        },
    )

    assert result["evidence"]["a"]["handle"] == "nightowl"
    assert result["evidence"]["a"]["addresses"] == 2
    assert result["evidence"]["a"]["timestamps"] == len(NIGHT_TIMESTAMPS)
    assert result["evidence"]["b"]["addresses"] == 1


def test_fuse_pair_with_no_evidence_is_zero_and_json_safe():
    result = fuse_pair({"handle": "empty"}, {"handle": "empty2"})

    assert result["confidence"] == 0.0
    assert result["available_signals"] == []
    json.dumps(result, allow_nan=False)


def test_identical_persona_pair_outscores_a_divergent_pair():
    twin_b = {
        "handle": "nightowl-twin",
        "addresses": [B1],
        "timestamps": SAME_RHYTHM_TIMESTAMPS,
        "corpus": CORPUS_B_SAME,
        "transactions": [SHARED_TX],
    }
    stranger = {
        "handle": "dayfox",
        "addresses": [B2],
        "timestamps": DAY_TIMESTAMPS,
        "corpus": CORPUS_B_DIFFERENT,
    }
    actor = {
        "handle": "nightowl",
        "addresses": [A1, A2],
        "timestamps": NIGHT_TIMESTAMPS,
        "corpus": CORPUS_A,
        "transactions": [SHARED_TX, PRIVATE_TX_A],
    }

    aligned = fuse_pair(actor, twin_b)
    diverged = fuse_pair(actor, stranger)

    assert aligned["confidence"] > diverged["confidence"]
    assert aligned["signals"]["temporal_score"] > diverged["signals"]["temporal_score"]
    assert (
        aligned["signals"]["stylometry_score"]
        > diverged["signals"]["stylometry_score"]
    )
    assert aligned["signals"]["crypto_score"] > diverged["signals"]["crypto_score"]


def test_infrastructure_clustered_inside_one_persona_scores_zero_for_the_pair():
    """A pair that only clusters with itself has not shared infrastructure."""
    internal_a = {
        "handle": "aaa",
        "probes": [
            probe("a1.onion", "s1", "nginx/1.24.0"),
            probe("a2.onion", "s1", "nginx/1.24.0"),
        ],
    }
    internal_b = {
        "handle": "bbb",
        "probes": [
            probe("b1.onion", "s2", "caddy/2.6"),
            probe("b2.onion", "s2", "caddy/2.6"),
        ],
    }

    result = fuse_pair(internal_a, internal_b)

    # The engine is not re-run or second-guessed: it found two strong internal
    # clusters and that output is preserved verbatim in the audit trail. Neither
    # cluster crosses the persona boundary, so the signal fed to the fusion is a
    # real zero rather than an inherited internal correlation.
    assert len(result["raw"]["infra"]["clusters"]) == 2
    assert result["raw"]["infra"]["infra_score"] > 0.0
    assert result["signals"]["infra_score"] == 0.0
    assert result["available_signals"] == ["infra"]
    assert any("internal to a single persona" in n for n in result["notes"])


def test_shared_serial_across_personas_with_disjoint_hosts_is_contradictory():
    result = fuse_pair(
        {"handle": "nightowl", "probes": [probe("aaa.onion", "shared99")]},
        {"handle": "dayfox", "probes": [probe("bbb.onion", "shared99")]},
    )

    assert result["signals"]["infra_score"] > 0.0
    assert any(
        reason.startswith("INFRA_SERIAL_VS_HOSTS")
        for reason in result["contradiction_reasons"]
    )
    # The shared serial is attributed to the pair; neither persona supplied a PGP
    # key, so the PGP contradiction cannot be raised off empty sets.
    assert result["evidence"]["a"]["pgp_keys"] == 0
    assert result["evidence"]["b"]["pgp_keys"] == 0
    assert not any(
        reason.startswith("CRYPTO_VS_PGP")
        for reason in result["contradiction_reasons"]
    )


def test_one_cross_persona_serial_is_enough_to_establish_shared_infrastructure():
    """A single shared serial links the personas even when B has one endpoint."""
    well_clustered = {
        "handle": "aaa",
        "probes": [
            probe("a1.onion", "s1", "nginx/1.24.0"),
            probe("a2.onion", "s1", "nginx/1.24.0"),
            probe("b1.onion", "s1", "caddy/2.6"),
        ],
    }
    thin = {"handle": "bbb", "probes": [probe("b1.onion", "s1", "caddy/2.6")]}

    result = fuse_pair(well_clustered, thin)

    assert result["signals"]["infra_score"] > 0.0
    assert result["available_signals"] == ["infra"]
    assert result["evidence"]["a"]["probes"] == 3
    assert result["evidence"]["b"]["probes"] == 1


def test_fuse_pair_output_can_be_re_fused_when_every_channel_was_evaluated():
    """Round trip: an emitted breakdown is a valid input to a later ``fuse``.

    The identity holds when the pair raised no contradiction, because
    ``SignalBreakdown`` carries scores, weights and notes but not the artefact
    evidence that the contradiction rules read; see the penalty test below.
    """
    result = fuse_pair(
        {
            "handle": "nightowl",
            "addresses": [A1],
            "timestamps": NIGHT_TIMESTAMPS,
            "corpus": CORPUS_A,
            "probes": [probe("shared.onion", "aa11")],
            "transactions": [SHARED_TX],
        },
        {
            "handle": "dayfox",
            "addresses": [B1],
            "timestamps": SAME_RHYTHM_TIMESTAMPS,
            "corpus": CORPUS_B_SAME,
            "probes": [probe("shared.onion", "aa11")],
        },
    )

    assert result["contradiction"] is False
    assert result["available_signals"] == list(SIGNAL_NAMES)

    again = fuse(result["signals"])

    assert again["available_signals"] == list(SIGNAL_NAMES)
    assert again["weights"] == result["weights"]
    assert again["confidence"] == pytest.approx(result["confidence"], abs=1e-6)
    assert again["contradiction_reasons"] == result["contradiction_reasons"]


def test_a_contradiction_raised_from_artefact_evidence_does_not_survive_a_re_fuse():
    """A breakdown cannot re-derive an artefact contradiction, so re-fusing differs."""
    result = fuse_pair(
        {"handle": "nightowl", "probes": [probe("aaa.onion", "aa11")]},
        {"handle": "dayfox", "probes": [probe("bbb.onion", "aa11")]},
    )

    assert result["contradiction"] is True
    assert any(
        reason.startswith("INFRA_SERIAL_VS_HOSTS")
        for reason in result["contradiction_reasons"]
    )
    assert result["factors"]["penalty"] == pytest.approx(settings.contradiction_penalty)

    again = fuse(result["signals"])

    # The hostnames and shared serial live beside the scores, not inside the
    # schema, so a re-fused record cannot re-derive the artefact contradiction
    # that produced the penalty and has to be re-adjudicated. The channels that
    # were never evaluated re-read as zeros, which is the separate trap pinned in
    # the test above, and is why the re-fused record is not interchangeable with
    # the original.
    assert not any(
        reason.startswith("INFRA_SERIAL_VS_HOSTS")
        for reason in again["contradiction_reasons"]
    )
    assert again["contradiction_reasons"] != result["contradiction_reasons"]


def test_an_unevaluated_channel_re_reads_as_an_evaluated_zero():
    """The trap the design warns about, pinned deliberately.

    ``SignalBreakdown`` has no way to say "not evaluated", so an emitted
    breakdown fills an absent channel with ``0.0``. Re-fusing that block therefore
    reads the absent channel as evidence *against* the link. It is a real property
    of the payload shape, not a bug, and it is why ``available_signals`` and
    ``missing_signals`` are part of the contract: a re-fused record must be
    checked against them before it is trusted.
    """
    result = fuse_pair(
        {
            "handle": "nightowl",
            "addresses": [A1],
            "timestamps": NIGHT_TIMESTAMPS,
            "transactions": [SHARED_TX],
        },
        {"handle": "dayfox", "addresses": [B1], "timestamps": SAME_RHYTHM_TIMESTAMPS},
    )

    assert result["missing_signals"] == ["infra", "stylometry"]
    assert result["signals"]["infra_score"] == 0.0

    again = fuse(result["signals"])

    assert again["available_signals"] == list(SIGNAL_NAMES)
    assert again["confidence"] < result["confidence"]


# ---------------------------------------------------------------------------
# Auditability
# ---------------------------------------------------------------------------
def test_signal_blockdown_validates_against_the_schema():
    result = fuse(UNIFORM)

    block = signal_breakdown(result)

    assert isinstance(block, SignalBreakdown)
    assert block.crypto_score == pytest.approx(0.8)
    assert block.weights == pytest.approx(result["weights"], abs=1e-6)
    assert block.notes


def test_signal_breakdown_rejects_a_broken_payload():
    with pytest.raises(Exception):
        signal_breakdown({"signals": {"crypto_score": "not a number"}})


def test_result_carries_the_full_audit_surface():
    result = fuse(UNIFORM)

    for key in (
        "confidence",
        "weights",
        "base_weights",
        "signals",
        "available_signals",
        "missing_signals",
        "contradiction",
        "contradiction_reasons",
        "notes",
        "factors",
    ):
        assert key in result

    for name in SIGNAL_NAMES:
        assert SCORE_FIELDS[name] in result["signals"]
    assert set(result["signals"]) == set(SCORE_FIELDS.values()) | {"weights", "notes"}


def test_engine_notes_are_carried_into_the_audit_trail():
    result = fuse(
        {
            "crypto": {
                "crypto_score": 0.5,
                "notes": ["Co-spend linkage is a heuristic."],
            }
        }
    )

    assert any("[crypto] Co-spend linkage" in note for note in result["notes"])


def test_suffixed_and_bare_spellings_are_equivalent():
    assert fuse(
        {
            "crypto_score": 0.5,
            "infra_score": 0.5,
            "temporal_score": 0.5,
            "stylometry_score": 0.5,
        }
    ) == fuse(
        {"crypto": 0.5, "infra": 0.5, "temporal": 0.5, "stylometry": 0.5}
    )


def test_numeric_strings_and_canonical_key_case_are_accepted():
    assert fuse({"crypto": "0.5", "stylometry": 0.5}) == fuse(
        {"Crypto-Score": 0.5, "STYLOMETRY_SCORE": 0.5}
    )


def test_fuse_rejects_a_non_mapping_payload():
    with pytest.raises(TypeError):
        fuse(["crypto", 0.9])  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# JSON hygiene and determinism
# ---------------------------------------------------------------------------
def test_result_survives_a_strict_json_round_trip():
    result = fuse(
        {"crypto": float("nan"), "infra": 0.8, "temporal": float("inf")},
        contradictions=["MANUAL_REVIEW"],
    )

    encoded = json.dumps(result, allow_nan=False)
    decoded = json.loads(encoded)

    assert decoded == result
    assert "NaN" not in encoded
    assert "Infinity" not in encoded
    # Non-finite evidence is not evidence, so it is unevaluated rather than a
    # zero - and it is reported as non-finite rather than as unreadable.
    assert decoded["available_signals"] == ["infra"]
    assert any("non-finite" in note for note in decoded["notes"])
    assert any("MANUAL_REVIEW" in reason for reason in decoded["contradiction_reasons"])


def test_numeric_strings_carrying_nan_or_inf_are_also_unevaluated():
    result = fuse({"crypto": "nan", "infra": 0.5})

    assert result["available_signals"] == ["infra"]
    assert any("non-finite" in note for note in result["notes"])


def test_json_safe_coerces_every_shape_the_engines_emit():
    payload = {
        "when": dt.datetime(2024, 3, 4, 23, 17, tzinfo=dt.timezone.utc),
        "day": dt.date(2024, 3, 4),
        "raw": b"probe",
        "members": {"b", "a"},
        "score": float("nan"),
        "scaled": float("inf"),
        "nested": [{"deep": {1: "numeric key"}}],
    }

    cleaned = json_safe(payload)

    assert cleaned["when"] == "2024-03-04T23:17:00Z"
    assert cleaned["day"] == "2024-03-04"
    assert cleaned["raw"] == "probe"
    assert cleaned["members"] == ["a", "b"]
    assert cleaned["score"] is None
    assert cleaned["scaled"] is None
    assert cleaned["nested"] == [{"deep": {"1": "numeric key"}}]
    json.dumps(cleaned, allow_nan=False)


def test_naive_datetimes_are_rendered_as_utc():
    assert json_safe({"t": dt.datetime(2024, 3, 4, 23, 17)})["t"] == (
        "2024-03-04T23:17:00Z"
    )


def test_fuse_is_deterministic_across_calls_and_mapping_order():
    payload = {
        "stylometry": 0.62,
        "temporal": 0.31,
        "crypto": 0.94,
        "infra": 0.12,
        "shared_cluster_ids": ["cluster-0001", "cluster-0000"],
        "pgp_keys_a": [FINGERPRINT_B, FINGERPRINT_A],
        "pgp_keys_b": [FINGERPRINT_B],
    }

    first = fuse(payload)
    second = fuse(dict(reversed(list(payload.items()))))
    third = fuse(payload)

    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert first == second == third


def test_fuse_pair_is_deterministic():
    actor_a = {
        "handle": "nightowl",
        "addresses": [A1, A2],
        "timestamps": NIGHT_TIMESTAMPS,
        "corpus": CORPUS_A,
        "probes": [probe("aaa.onion", "aa11")],
    }
    actor_b = {
        "handle": "dayfox",
        "addresses": [B1],
        "timestamps": SAME_RHYTHM_TIMESTAMPS,
        "corpus": CORPUS_B_SAME,
        "probes": [probe("bbb.onion", "aa11")],
    }

    first = fuse_pair(actor_a, actor_b)
    second = fuse_pair(actor_a, actor_b)

    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


# ---------------------------------------------------------------------------
# Ranking
# ---------------------------------------------------------------------------
def test_ranking_is_by_descending_confidence():
    ranked = rank_candidates(
        [
            {"id": "low", "confidence": 0.2},
            {"id": "high", "confidence": 0.9},
            {"id": "mid", "confidence": 0.5},
        ]
    )

    assert [entry["id"] for entry in ranked] == ["high", "mid", "low"]


def test_ties_break_on_stable_identity_not_input_order():
    entries = [
        {"candidate_id": "c-03", "confidence": 0.5},
        {"candidate_id": "c-01", "confidence": 0.5},
        {"candidate_id": "c-02", "confidence": 0.5},
    ]

    forward = rank_candidates(entries)
    backward = rank_candidates(list(reversed(entries)))

    assert [entry["candidate_id"] for entry in forward] == ["c-01", "c-02", "c-03"]
    assert forward == backward


def test_ties_without_identifiers_fall_back_to_the_actor_pair():
    entries = [
        {"confidence": 0.5, "source_actor": "b", "target_actor": "c"},
        {"confidence": 0.5, "source_actor": "a", "target_actor": "z"},
    ]

    assert [e["source_actor"] for e in rank_candidates(entries)] == ["a", "b"]


def test_identical_records_avoid_a_comparison_error():
    duplicate = {"confidence": 0.5, "candidate_id": "same"}
    ranked = rank_candidates([dict(duplicate), dict(duplicate)])

    assert len(ranked) == 2


def test_ranking_does_not_mutate_or_alias_the_input():
    entries = [{"id": "b", "confidence": 0.3}, {"id": "a", "confidence": 0.8}]
    snapshot = json.dumps(entries, sort_keys=True)

    ranked = rank_candidates(entries)

    assert json.dumps(entries, sort_keys=True) == snapshot
    assert ranked is not entries
    # The originals are returned, not copies of them.
    assert ranked == [entries[1], entries[0]]
    assert ranked[0] is entries[1]
    assert ranked[1] is entries[0]


def test_corrupt_confidence_is_ranked_last_rather_than_raising():
    ranked = rank_candidates(
        [
            {"candidate_id": "corrupt", "confidence": float("nan")},
            {"candidate_id": "sound", "confidence": 0.1},
        ]
    )

    assert [entry["candidate_id"] for entry in ranked] == ["sound", "corrupt"]


def test_ranking_rejects_a_non_mapping_element():
    with pytest.raises(TypeError):
        # type: ignore[list-item]
        rank_candidates([{"id": "ok", "confidence": 0.5}, "not a record"])


def test_ranking_handles_an_empty_queue():
    assert rank_candidates([]) == []


def test_ranking_orders_fused_pairs_by_real_evidence():
    actor = {
        "handle": "nightowl",
        "addresses": [A1, A2],
        "timestamps": NIGHT_TIMESTAMPS,
        "corpus": CORPUS_A,
        "transactions": [SHARED_TX, PRIVATE_TX_A],
    }
    twin = fuse_pair(
        actor,
        {
            "handle": "twin",
            "addresses": [B1],
            "timestamps": SAME_RHYTHM_TIMESTAMPS,
            "corpus": CORPUS_B_SAME,
        },
    )
    stranger = fuse_pair(
        actor,
        {
            "handle": "stranger",
            "addresses": [B2],
            "timestamps": DAY_TIMESTAMPS,
            "corpus": CORPUS_B_DIFFERENT,
        },
    )

    ranked = rank_candidates([stranger, twin])

    assert [entry["target_actor"] for entry in ranked] == ["twin", "stranger"]
    assert ranked[0]["confidence"] > ranked[1]["confidence"]
    assert ranked[0]["source_actor"] == "nightowl"


# ---------------------------------------------------------------------------
# Static guarantees
# ---------------------------------------------------------------------------
def test_module_exposes_a_complete_documented_public_api():
    source = Path(fusion_engine.__file__).read_text(encoding="utf-8")

    exported = set(fusion_engine.__all__)
    assert {"fuse", "fuse_pair", "rank_candidates", "signal_breakdown"} <= exported
    for name in exported:
        assert hasattr(fusion_engine, name), name

    defined: list[ast.stmt] = list(ast.parse(source).body)
    bound: set[str] = set()
    callables: list[ast.AST] = []
    for node in defined:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            bound.add(node.name)
            callables.append(node)
        elif isinstance(node, ast.Assign):
            bound.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            bound.add(node.target.id)

    # Every name promised by __all__ is actually defined at module level.
    assert exported <= bound, exported - bound

    # Every exported callable carries a docstring an examiner can read.
    for node in callables:
        if node.name in exported:
            assert ast.get_docstring(node), f"{node.name} is undocumented"


def test_module_contains_no_placeholders_or_stubs():
    source = Path(fusion_engine.__file__).read_text(encoding="utf-8")

    for marker in ("TODO", "FIXME", "XXX", "NotImplementedError", "pass  #"):
        assert marker not in source, marker

    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            body = [child for child in node.body if not isinstance(child, ast.Expr)]
            if len(body) == 1 and isinstance(body[0], ast.Pass):
                assert ast.get_docstring(node), f"{node.name} is an undocumented stub"


def test_module_reads_no_ambient_state_at_import_time():
    """Weights and penalties must be consulted per call, never cached at import."""
    source = Path(fusion_engine.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    calls = [
        node.value.func.id
        for node in tree.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
    ]

    assert "_base_weights" not in calls
    assert "_normalise_weights" not in calls
    assert "if __name__ ==" not in source


def test_no_module_under_test_reaches_the_network():
    """The fusion layer is pure adjudication: no sockets, no HTTP clients."""
    source = Path(fusion_engine.__file__).read_text(encoding="utf-8")
    for marker in ("import requests", "import httpx", "urllib.request", "socket."):
        assert marker not in source, marker


def test_emitted_confidence_is_always_within_the_unit_interval():
    for crypto in (0.0, 0.5, 1.0):
        for infra in (0.0, 1.0):
            for temporal in (0.0, 1.0):
                for stylometry in (0.0, 1.0):
                    result = fuse(
                        {
                            "crypto": crypto,
                            "infra": infra,
                            "temporal": temporal,
                            "stylometry": stylometry,
                        }
                    )
                    assert 0.0 <= result["confidence"] <= 1.0
                    assert not math.isnan(result["confidence"])
                    total = sum(result["weights"].values())
                    assert total == pytest.approx(1.0, abs=1e-9)
