"""Burrows' Delta authorship verification.

Burrows' Delta (2002) treats an author as a vector of relative frequencies over
the most common English function words. Those words carry almost no topical
meaning but very high stylistic signal, which is exactly why they survive topic
drift better than content words.

Method
------
1. Tokenise and count relative frequencies over a fixed 50-word function-word
   list (the canonical English stop-function set).
2. Standardise each corpus with a z-score transformation so corpora of very
   different lengths become comparable.
3. Delta between two authors is the mean absolute z-score difference. A delta of
   0 is identity, roughly 2.0 is the conventional "significant difference"
   threshold, and beyond 4.0 the corpora are effectively unrelated.
4. Convert to a normalised ``0.0-1.0`` similarity for the fusion engine.

Shallow n-gram similarity is deliberately *not* used: it flags topical overlap
and would mark two vendors selling the same commodity as the same person.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any, Iterable, Sequence

# The 50 most common English function words - the Burrows' Delta standard set.
FUNCTION_WORDS: tuple[str, ...] = (
    "the", "of", "and", "to", "in", "that", "is", "was", "he", "for", "it",
    "with", "as", "his", "on", "be", "at", "by", "i", "this", "had", "not",
    "are", "but", "from", "or", "have", "an", "they", "which", "one",
    "you", "were", "her", "all", "she", "there", "would", "their", "we", "him",
    "been", "has", "when", "who", "will", "no", "more", "if", "out", "so",
    "said", "what", "up", "its", "about", "into", "than", "them", "can", "only",
    "other", "new", "some", "could", "time", "these", "two", "may", "then",
    "do", "first", "any", "my", "now", "such", "like", "our", "over", "man",
    "me", "even", "most", "made", "after", "also", "did", "many", "before",
    "must", "through", "back", "years", "where", "much", "your", "way",
    "well", "down", "should", "because", "each", "just", "those", "people",
    "how", "too", "little", "state", "good", "very", "make", "world", "still",
    "own", "see", "men", "work", "long", "get", "here", "between", "both",
    "life", "being", "under", "never", "day", "same", "another", "know",
    "while", "last", "might", "us", "great", "old", "year", "off", "come",
    "since", "against", "go", "came", "right", "used", "take", "three",
)

# Deduplicate while preserving order, keeping the 50 strongest signals.
deduped = list(dict.fromkeys(w for w in FUNCTION_WORDS if w.isalpha()))
# The canonical Burrows' Delta set is exactly 50 function words.
FUNCTION_WORDS: tuple[str, ...] = tuple(deduped[:50])

_WORD_RE = re.compile(r"[A-Za-z']+")
_SENTENCE_RE = re.compile(r"[.!?]+(?:\s|$)")

# ---------------------------------------------------------------------------
# Reference corpus
# ---------------------------------------------------------------------------
# Burrows' Delta standardises z-scores against a *reference corpus* of the
# language, not against the two texts under comparison. Pooling variance over
# only two samples would mathematically cap delta at 2.0, making the
# conventional 4.0 "unrelated" threshold unreachable.
#
# The samples below are neutral English prose of differing genre, length and
# era. They define the baseline mean and standard deviation for each function
# word; a target text is then scored by how many standard deviations it sits
# from ordinary English usage.
_REFERENCE_CORPUS: tuple[str, ...] = (
    """The committee met on Tuesday to consider the report that had been prepared
    by the working group over the preceding six months. Members expressed a range
    of views about the proposal, and several asked for additional time to review
    the financial projections. The chair noted that the figures had been revised
    since the previous meeting and that a revised schedule would be circulated.
    There was no objection to the revised timetable, although one member asked
    that the matter be held over until the next session. The secretary was asked
    to record the discussion and to circulate the minutes to those unable to
    attend. It was agreed that the working group would report back before the end
    of the following quarter.""",
    """It is often said that the early morning is the best time to work, and many
    people who have tried it will tell you that the hours before nine are
    unusually quiet. The streets are empty, the coffee is cheap, and the light
    through the window falls across the desk in a way that makes the work seem
    possible. On the other hand, there are those who find that the early hours
    are the worst part of the day, when the mind is slow and the body has not
    yet understood what is required of it. Which of these views is correct
    probably depends more on the person than on the hour itself.""",
    """In the years after the war the factory stood empty for some time, and the
    building collected a particular kind of quiet that the men who had worked
    there remembered long afterwards. When it opened again the machines were
    newer and fewer, and the work that had once been done by ninety hands was
    done by twenty. The town itself changed more slowly. Children still went to
    the same school, and the same two shops stood on the corner, and the road
    that led to the station was no wider than it had been in any living memory.
    People adjusted, as people do, and after a few years nobody spoke about the
    old days except in the evenings.""",
    """A good editor reads the same sentence several times, and the reason is not
    that the sentence is difficult but that it can be made better. The first
    reading is for meaning. The second is for structure, and it is here that you
    notice that a paragraph has been asked to do two things at once. The third
    reading is for rhythm, because a sentence that cannot be said aloud in one
    breath is usually a sentence that has not yet found its shape. Only after
    these readings is it worth asking whether the words are right, and by then
    the choice among them is often obvious.""",
    """The library was built in 1874, and the reading room has changed very little.
    The tables are still long, the lamps are still green, and the windows still
    look north across the roofs toward the river. Students come here in the
    winter because it is warm, and in the summer because there is nowhere else
    that will let them sit without buying anything. The librarian remembers the
    years when the building was full from morning until closing, and she does not
    say that things are better now, only that they are different. The clock in
    the corner is still accurate to within a minute.""",
    """There are two ways to write a difficult subject clearly. The first is to
    begin with the difficulty itself, to put the reader in a room where the
    problem is visible from the start, and then to move across it in steps that
    each can be checked. The second is to begin somewhere else entirely, with an
    example that the reader already understands, and to let the general point
    arrive later. Neither method is always available. The first fails when the
    reader has no foothold at all, and the second fails when the example is
    taken to be the whole of the case.""",
    """What the survey found, when the results were finally assembled, was not the
    result that anyone had expected. The team had predicted growth in the
    smaller towns and decline in the larger ones, and the figures showed
    something close to the opposite. Rather than treat this as a problem, the
    authors suggested that it should be read as a correction, a reminder that
    the model had been built on assumptions about movement that no longer held.
    The report ended by saying that further work would be needed before any
    firm conclusion could be drawn, which is the sort of sentence that appears
    at the end of most reports and is usually correct.""",
    """He kept the letters in a wooden box under the bed, tied with a piece of
    string, and once or twice a year he took them out and read them through.
    The paper had gone brown at the edges. Some of the ink had faded to a pale
    blue that was difficult to make out, and a few of the sheets were torn where
    they had been folded too many times in the same place. He never wrote back.
    It was not that he had nothing to say, he told himself, but that the words
    he would have used had belonged to a version of himself that no longer
    existed, and sending them would have been a kind of lie.""",
    # --- Technical / procedural register ---------------------------------
    """The server must be restarted for the configuration change to take effect.
    If the service is managed by systemd, run systemctl daemon-reload before
    attempting to start the unit, otherwise the old configuration will be used.
    Verify that the port is listening with ss -tlnp, and check the journal for
    errors. When the process exits immediately, the most common cause is a
    permission error on the socket path, so confirm that the user running the
    service can write to the directory. Do not edit the configuration file while
    the service is running, because the file will be rewritten on exit. After
    any change you should confirm that the health endpoint returns the expected
    status code, and only then consider the deployment complete.""",
    """The patient was admitted with a three day history of fever and productive
    cough. Examination revealed consolidation in the lower zone of the right lung
    and reduced air entry over the same area. Chest radiography showed patchy
    airspace opacification. Blood tests demonstrated an elevated white cell count
    and a raised C reactive protein. Antibiotics were commenced empirically, since
    the clinical picture was consistent with community acquired pneumonia. The
    patient improved over the following forty eight hours, defervescence
    occurring on the third day, and was discharged on oral antibiotics with
    outpatient follow up arranged in two weeks.""",
    """First of all you have to understand that the thing does not work the way you
    think it does. People come in here expecting some kind of easy answer and then
    they get told that there is not one, and that is basically the whole point.
    You can look at it from every angle you like and the answer is going to be
    the same. Now, I am not saying that there is nothing to be done here, because
    clearly there is. But if you go in expecting to walk out with everything
    sorted then you are going to be disappointed. That is just how it is. Take
    the time you need, read what is there, and then come back and talk to us.""",
    """Chapter One. The letter had been on the table for three days before she opened
    it. It was not that she had not wanted to, exactly. There had simply been no
    reason, and then there had been too many, and by the time the reasons had
    thinned out again the letter had been there so long that it had become part
    of the furniture. She knew the handwriting on the envelope without picking it
    up. She had seen it on the outside of every letter that had arrived that
    year, and on the list of names in the hall, and once, memorably, on a
    telegram. It was not a letter she had been expecting. That was the trouble
    with them. The ones you expected you could always answer.""",
    """def parse_config(path):
    # load and merge the configuration files
    cfg = load_defaults()
    for layer in discover_layers(path):
        cfg.update(read_layer(layer))
    # validate the merged result before returning it
    errors = validate(cfg)
    if errors:
        raise ConfigError(errors)
    return cfg

class ConfigError(Exception):
    # raised when a configuration file fails validation
    def __init__(self, errors):
        self.errors = errors
        super().__init__(f"{len(errors)} configuration errors")""",
)

# Memoisation slot for the reference distribution, filled on first use.
_REFERENCE_STATS: dict[str, dict[str, float]] = {}


def _reference_stats() -> dict[str, dict[str, float]]:
    """Memoised mean/stdev of each function word across the reference corpus.

    Computed on first use rather than at import time, because it depends on
    ``FUNCTION_WORDS`` and the frequency helper being defined first.
    """
    if not _REFERENCE_STATS:
        per_sample = [_relative_frequencies(text) for text in _REFERENCE_CORPUS]
        means: dict[str, float] = {}
        stdevs: dict[str, float] = {}
        for word in FUNCTION_WORDS:
            values = [sample[word] for sample in per_sample]
            mean = sum(values) / len(values)
            variance = sum((v - mean) ** 2 for v in values) / len(values)
            means[word] = mean
            stdevs[word] = math.sqrt(variance)
        _REFERENCE_STATS["means"] = means
        _REFERENCE_STATS["stdevs"] = stdevs
    return _REFERENCE_STATS



# ---------------------------------------------------------------------------
# Calibration
# ---------------------------------------------------------------------------
# Burrows' published scale (delta 2.0 = significant difference, 4.0 = unrelated)
# was calibrated against large 18th-century corpora. Absolute delta depends
# entirely on the variance of the reference distribution, so those constants
# carry no meaning for short social-media-style samples, where function-word
# frequencies are dominated by sampling noise.
#
# Instead of asserting a fixed scale, this module uses Burrows' own significance
# procedure: a split-half null. Each corpus is divided in two and the delta
# between its own halves is measured. That value is the expected distance
# between two samples from the *same* author, and therefore the noise floor.
# The observed cross-author delta is then judged against it.
#
#   within_author_delta : expected sampling noise
#   observed_delta      : measured distance between the two authors
#   separation          : observed / within  (>1 means the pair is further apart
#                        than same-author sampling would explain)
#
# Separations beyond ~2x are treated as significant. This is data-derived and
# stays meaningful for any corpus size.
DELTA_IDENTICAL = 0.0
DELTA_SIGNIFICANT_BURROWS = 2.0
DELTA_UNRELATED_BURROWS = 4.0

# How many times the same-author noise floor a cross-author delta must reach
# before the pair is reported as significantly different.
SIGNIFICANT_SEPARATION = 2.0
STRONG_SEPARATION = 3.0

# Below this delta the two function-word profiles are effectively identical.
_DEGENERATE_NULL = 1e-6

# Upper bound on the separation ratio, so results stay JSON-serialisable and
# the scale does not run away on near-zero noise floors.
_MAX_SEPARATION = 99.0

MIN_CORPUS_TOKENS = 50


def tokenize(text: str) -> list[str]:
    """Lowercase alphabetic tokenisation, apostrophes preserved."""
    return [match.group(0).lower() for match in _WORD_RE.finditer(text or "")]


def _relative_frequencies(text: str) -> dict[str, float]:
    """Relative frequency of each function word in ``text``."""
    tokens = tokenize(text)
    if not tokens:
        return {word: 0.0 for word in FUNCTION_WORDS}

    counts = Counter(tokens)
    total = len(tokens)
    return {word: counts.get(word, 0) / total for word in FUNCTION_WORDS}


def _zscore_vectors(
    corpus_a: str, corpus_b: str
) -> tuple[dict[str, float], dict[str, float]]:
    """Standardise both corpora against the reference distribution.

    Using the built-in reference corpus (rather than the two texts pooled) is
    what preserves the full 0-4+ Burrows' Delta range: z-scores express how far
    an author sits from ordinary English usage, not merely from each other.
    """
    freq_a = _relative_frequencies(corpus_a)
    freq_b = _relative_frequencies(corpus_b)

    def _standardize(freqs: dict[str, float]) -> dict[str, float]:
        out: dict[str, float] = {}
        for word in FUNCTION_WORDS:
            stats = _reference_stats()
            sd = stats["stdevs"][word]
            # A word with no variation in the reference set carries no
            # discriminating power; pin it to zero rather than divide by noise.
            out[word] = (
                (freqs[word] - stats["means"][word]) / sd if sd > 1e-12 else 0.0
            )
        return out

    return _standardize(freq_a), _standardize(freq_b)


def burrows_delta(corpus_a: str, corpus_b: str) -> float:
    """Mean absolute z-score distance over the 50 function words."""
    z_a, z_b = _standardize_vectors(corpus_a, corpus_b)
    return sum(abs(z_a[w] - z_b[w]) for w in FUNCTION_WORDS) / len(FUNCTION_WORDS)


def _standardize_vectors(corpus_a: str, corpus_b: str):
    return _zscore_vectors(corpus_a, corpus_b)


def split_half_delta(text: str) -> Optional[float]:
    """Delta between the two halves of a single corpus (the same-author null).

    Half 1 and half 2 are by construction from the same author, so this delta
    measures how much apparent difference sampling noise alone can produce.
    Returns ``None`` when the corpus is too short to split meaningfully.
    """
    tokens = tokenize(text)
    if len(tokens) < MIN_CORPUS_TOKENS:
        return None

    midpoint = len(tokens) // 2
    # Split on a sentence boundary when possible, to keep each half coherent.
    sentences = [s for s in _SENTENCE_RE.split(text or "") if s.strip()]
    if len(sentences) >= 4:
        middle = len(sentences) // 2
        half_a = " ".join(sentences[:middle])
        half_b = " ".join(sentences[middle:])
    else:
        half_a = " ".join(tokens[:midpoint])
        half_b = " ".join(tokens[midpoint:])

    if len(tokenize(half_a)) < 20 or len(tokenize(half_b)) < 20:
        return None
    return burrows_delta(half_a, half_b)


def significance(corpus_a: str, corpus_b: str) -> dict[str, Any]:
    """Burrows-style split-half significance test for the author hypothesis."""
    observed = burrows_delta(corpus_a, corpus_b)

    null_a = split_half_delta(corpus_a)
    null_b = split_half_delta(corpus_b)
    usable = [value for value in (null_a, null_b) if value is not None]

    if not usable:
        return {
            "observed_delta": round(observed, 4),
            "within_author_delta": None,
            "separation": None,
            "significant": None,
            "verdict": "INSUFFICIENT_CORPUS",
            "basis": "Neither corpus was long enough to establish a same-author null.",
        }

    # Use the mean of the available nulls as the noise floor.
    within = sum(usable) / len(usable)

    # A null of exactly zero means the corpus is internally repetitive (a
    # duplicated block, a boilerplate loop), so the halves carry no independent
    # information. Fall back to the reference spread, otherwise the ratio
    # divides by zero and identical corpora would look maximally different.
    degenerate = within <= _DEGENERATE_NULL
    if degenerate:
        within = max(reference_delta_distribution()["mean"] * 0.5, _DEGENERATE_NULL)

    separation = round(min(observed / within, _MAX_SEPARATION), 4) if within > 0 else _MAX_SEPARATION

    if observed <= _DEGENERATE_NULL:
        # Function-word profiles are indistinguishable: same author.
        verdict = "SAME_AUTHOR_PROBABLE"
    elif separation >= STRONG_SEPARATION:
        verdict = "DIFFERENT_AUTHORS_PROBABLE"
    elif separation >= SIGNIFICANT_SEPARATION:
        verdict = "DIFFERENT_AUTHORS_POSSIBLE"
    elif separation >= 0.5:
        # Observable difference, but within the range that short-sample
        # sampling noise alone can produce. Author cannot be determined.
        verdict = "INDETERMINATE"
    else:
        # The two texts are barely distinguishable from each other.
        verdict = "SAME_AUTHOR_PROBABLE"

    return {
        "observed_delta": round(observed, 4),
        "within_author_delta": round(within, 4),
        "separation": separation,
        "degenerate_null": degenerate,
        # ``significant`` is strictly "can we reject the common-author
        # hypothesis", which is never true below the significant threshold.
        "significant": separation >= SIGNIFICANT_SEPARATION,
        "verdict": verdict,
        "basis": (
            f"Split-half null for same-author sampling noise is "
            f"{within:.3f}; observed cross-author delta is {observed:.3f} "
            f"({separation:.2f}x the noise floor). Verdicts below the significant "
            f"ratio {SIGNIFICANT_SEPARATION} do not reject the common-author "
            f"hypothesis."
            + (
                " The corpus was internally repetitive, so the reference spread "
                "was used as the noise floor."
                if degenerate
                else ""
            )
        ),
    }


def reference_delta_distribution() -> dict[str, float]:
    """Delta spread among reference samples (diagnostic context only)."""
    deltas: list[float] = []
    for i, sample_a in enumerate(_REFERENCE_CORPUS):
        for sample_b in _REFERENCE_CORPUS[i + 1:]:
            deltas.append(burrows_delta(sample_a, sample_b))

    if not deltas:
        return {"mean": 0.0, "max": 0.0, "n": 0}

    return {
        "mean": round(sum(deltas) / len(deltas), 4),
        "max": round(max(deltas), 4),
        "n": len(deltas),
    }


def delta_to_similarity(delta: float) -> float:
    """Map delta onto ``[0, 1]`` against the reference spread.

    Falls back to a ratio against the reference inter-sample delta, which is a
    sane linear approximation when no same-author null can be computed.
    """
    stats = reference_delta_distribution()
    scale = max(stats["mean"] * 2.0, 1e-6)
    bounded = max(0.0, float(delta))
    return round(max(0.0, min(1.0, 1.0 - bounded / scale)), 4)


# ---------------------------------------------------------------------------
# Syntactic markers
# ---------------------------------------------------------------------------


def syntactic_profile(text: str) -> dict[str, Any]:
    """Structural rhythm metrics that complement function-word frequency.

    Content words cannot see these, and for a vendor posting in a fixed house
    style they are highly discriminative.
    """
    tokens = tokenize(text)
    sentences = [s.strip() for s in _SENTENCE_RE.split(text or "") if s.strip()]
    sentence_lengths = [len(tokenize(s)) for s in sentences] or [0]

    mean_len = sum(sentence_lengths) / len(sentence_lengths)
    variance = (
        sum((length - mean_len) ** 2 for length in sentence_lengths)
        / len(sentence_lengths)
    )
    stdev = math.sqrt(variance)

    punctuation = Counter(ch for ch in (text or "") if ch in ",.;:!?-_/()[]{}'\"")
    total_chars = len(text or "") or 1
    punctuation_rhythm = {
        char: round(count / total_chars, 6)
        for char, count in sorted(punctuation.items())
    }

    contractions = len(re.findall(r"\b[A-Za-z]+['’][A-Za-z]+\b", text or ""))
    exclamations = (text or "").count("!")
    questions = (text or "").count("?")
    ellipses = len(re.findall(r"\.\.\.", text or ""))

    # Type-token ratio: vocabulary richness, a classic authorship marker.
    ttr = (len(set(tokens)) / len(tokens)) if tokens else 0.0

    return {
        "token_count": len(tokens),
        "sentence_count": len(sentences),
        "sentence_length_mean": round(mean_len, 3),
        "sentence_length_stdev": round(stdev, 3),
        "sentence_length_variance": round(variance, 3),
        "avg_words_per_sentence": round(mean_len, 2),
        "punctuation_rhythm": punctuation_rhythm,
        "punctuation_entropy": round(_entropy(punctuation_rhythm), 4),
        "type_token_ratio": round(ttr, 4),
        "contraction_rate": round(contractions / len(sentences), 4) if sentences else 0.0,
        "exclamation_rate": round(exclamations / total_chars, 5),
        "question_rate": round(questions / total_chars, 5),
        "ellipsis_count": ellipses,
    }


def _syntax_components(
    profile_a: dict[str, Any], profile_b: dict[str, Any]
) -> dict[str, float]:
    """Per-marker syntax similarity, surfaced in the adjudication UI."""
    return _syntax_similarity(profile_a, profile_b, explain=True)


def _syntax_similarity(
    profile_a: dict[str, Any],
    profile_b: dict[str, Any],
    explain: bool = False,
):
    """Blend structural markers into a single ``[0, 1]`` similarity.

    Sentence-length distribution dominates because it is the most stable
    stylistic habit; punctuation entropy and vocabulary richness corroborate.
    """
    def _ratio_closeness(a: float, b: float, tolerance: float) -> float:
        spread = abs(a - b)
        scale = max(abs(a), abs(b), tolerance)
        return max(0.0, 1.0 - spread / scale)

    def _gaussian_similarity(a: float, b: float, sigma: float) -> float:
        """1.0 at equality, decaying smoothly with distance."""
        return math.exp(-((a - b) ** 2) / (2 * sigma ** 2)) if sigma > 0 else 0.0

    components = {
        # Mean sentence length within ~1 standard deviation counts as close.
        "sentence_length": _ratio_closeness(
            profile_a["avg_words_per_sentence"],
            profile_b["avg_words_per_sentence"],
            tolerance=4.0,
        ),
        # Rhythm: matching sentence-length spread implies matching cadence.
        "rhythm": _gaussian_similarity(
            profile_a["sentence_length_stdev"],
            profile_b["sentence_length_stdev"],
            sigma=6.0,
        ),
        "punctuation": _gaussian_similarity(
            profile_a["punctuation_entropy"],
            profile_b["punctuation_entropy"],
            sigma=1.2,
        ),
        "lexical_richness": _ratio_closeness(
            profile_a["type_token_ratio"],
            profile_b["type_token_ratio"],
            tolerance=0.15,
        ),
        "contraction": _gaussian_similarity(
            profile_a["contraction_rate"],
            profile_b["contraction_rate"],
            sigma=0.5,
        ),
    }

    weights = {
        "sentence_length": 0.35,
        "rhythm": 0.25,
        "punctuation": 0.20,
        "lexical_richness": 0.12,
        "contraction": 0.08,
    }
    weighted = sum(components[k] * weights[k] for k in components)
    score = round(max(0.0, min(1.0, weighted)), 4)
    if explain:
        return {**{k: round(v, 4) for k, v in components.items()}, "weighted": score}
    return score


def _entropy(distribution: dict[str, float]) -> float:
    total = sum(distribution.values())
    if total <= 0:
        return 0.0
    entropy = 0.0
    for probability in distribution.values():
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return entropy


def _fingerprint(text: str) -> list[float]:
    """Flat z-vector of a single text against a neutral reference corpus.

    Used for cross-text comparison without a paired partner.
    """
    freqs = _relative_frequencies(text)
    values = [freqs[word] for word in FUNCTION_WORDS]
    mean = sum(values) / len(values)
    sd = math.sqrt(sum((v - mean) ** 2 for v in values) / len(values))
    if sd < 1e-12:
        return [0.0] * len(values)
    return [(v - mean) / sd for v in values]


def compare(
    corpus_a: str | Sequence[str],
    corpus_b: str | Sequence[str],
) -> dict[str, Any]:
    """Full stylometric comparison of two author corpora.

    Accepts either a string or a sequence of messages, which is how the graph
    engine supplies every message attributed to a persona.
    """
    text_a = _join(corpus_a)
    text_b = _join(corpus_b)

    tokens_a = len(tokenize(text_a))
    tokens_b = len(tokenize(text_b))

    delta = burrows_delta(text_a, text_b)

    # Data-derived significance test (split-half null).
    stats = significance(text_a, text_b)
    verdict = stats["verdict"]
    separation = stats.get("separation")

    profile_a = syntactic_profile(text_a)
    profile_b = syntactic_profile(text_b)

    syntax_components = _syntax_components(profile_a, profile_b)
    syntax_similarity = _syntax_similarity(profile_a, profile_b)

    # Function-word similarity, rescaled by the significance test. Delta alone
    # is a distance, not a probability, and for short samples it saturates well
    # inside the same-author noise range. Rescaling by separation keeps the
    # score honest: only once a pair is measurably further apart than same-author
    # noise allows does similarity fall meaningfully.
    similarity = _separation_adjusted_similarity(delta, separation)

    combined = round(0.75 * similarity + 0.25 * syntax_similarity, 4)

    if tokens_a < MIN_CORPUS_TOKENS or tokens_b < MIN_CORPUS_TOKENS:
        verdict = "INSUFFICIENT_CORPUS"
        combined = round(combined * 0.5, 4)  # discount thin evidence
    elif verdict == "DIFFERENT_AUTHORS_PROBABLE":
        # Syntax agreement can never fully overcome a rejected author
        # hypothesis, but it should temper the strength of the claim.
        combined = min(combined, 0.45 + 0.25 * syntax_similarity)

    return {
        "burrows_delta": round(delta, 4),
        "similarity": similarity,
        "syntax_similarity": syntax_similarity,
        "syntax_components": syntax_components,
        "stylometry_score": combined,
        "verdict": verdict,
        "significance": stats,
        "thresholds": {
            "identical": DELTA_IDENTICAL,
            "significant_separation_ratio": SIGNIFICANT_SEPARATION,
            "strong_separation_ratio": STRONG_SEPARATION,
            "burrows_canonical": {
                "delta_significant": DELTA_SIGNIFICANT_BURROWS,
                "delta_unrelated": DELTA_UNRELATED_BURROWS,
            },
        },
        "corpus_a": {"tokens": tokens_a, "characters": len(text_a), "profile": profile_a},
        "corpus_b": {"tokens": tokens_b, "characters": len(text_b), "profile": profile_b},
        "top_discriminating_words": top_discriminators(text_a, text_b, limit=8),
        "evidence_note": (
            f"Corpus A has {tokens_a} tokens, corpus B has {tokens_b}. "
            + (
                stats["basis"]
                if stats.get("basis")
                else "Significance test unavailable for this corpus size."
            )
        ),
    }


def _separation_adjusted_similarity(delta: float, separation: float | None) -> float:
    """Convert delta into similarity, anchored on the same-author noise floor.

    A delta of ``within`` is exactly what one author produces by chance, so
    similarity at that point should sit at the mid-point of the scale rather
    than near 1.0. Above the significant ratio the score decays toward 0.
    """
    if separation is None or not math.isfinite(separation):
        return delta_to_similarity(delta)

    # Map the ratio of interest onto the score: 0 -> 0.95, significant ratio
    # -> 0.5, strong ratio -> 0.15, and beyond that -> 0.0.
    if separation <= 0.25:
        return 0.95
    if separation <= 1.0:
        return round(0.95 - 0.45 * (separation - 0.25) / 0.75, 4)
    if separation <= SIGNIFICANT_SEPARATION:
        span = SIGNIFICANT_SEPARATION - 1.0
        return round(0.5 - 0.35 * (separation - 1.0) / span, 4)
    if separation <= STRONG_SEPARATION:
        span = STRONG_SEPARATION - SIGNIFICANT_SEPARATION
        return round(0.15 - 0.15 * (separation - SIGNIFICANT_SEPARATION) / span, 4)
    return 0.0


def top_discriminators(
    corpus_a: str, corpus_b: str, limit: int = 8
) -> list[dict[str, Any]]:
    """Function words with the largest z-score divergence between corpora."""
    z_a, z_b = _standardize_vectors(corpus_a, corpus_b)
    ranked = sorted(
        (
            {"word": word, "z_difference": round(abs(z_a[word] - z_b[word]), 4)}
            for word in FUNCTION_WORDS
        ),
        key=lambda item: item["z_difference"],
        reverse=True,
    )
    return ranked[:limit]


def score_pair(
    corpus_a: str | Sequence[str],
    corpus_b: str | Sequence[str],
) -> dict[str, Any]:
    """Stylometry sub-score for two candidate personas (fusion engine input)."""
    result = compare(corpus_a, corpus_b)
    return {
        "stylometry_score": result["stylometry_score"],
        "burrows_delta": result["burrows_delta"],
        "verdict": result["verdict"],
        "detail": result,
    }


def _join(value: str | Sequence[str]) -> str:
    if isinstance(value, str):
        return value
    return "\n".join(str(part) for part in value)


__all__ = [
    "compare",
    "burrows_delta",
    "delta_to_similarity",
    "significance",
    "split_half_delta",
    "syntactic_profile",
    "score_pair",
    "top_discriminators",
    "tokenize",
    "FUNCTION_WORDS",
    "DELTA_IDENTICAL",
    "DELTA_SIGNIFICANT_BURROWS",
    "DELTA_UNRELATED_BURROWS",
    "SIGNIFICANT_SEPARATION",
    "STRONG_SEPARATION",
    "reference_delta_distribution",
    "MIN_CORPUS_TOKENS",
]
