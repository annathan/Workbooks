"""Fuzzy-match software names across CMDB, Armis, and HECVAT sources.

The same software rarely has the same name in every system ("Microsoft
Teams" vs "Teams" vs "MS Teams"), so this scores names token-by-token
instead of requiring exact equality.
"""
from dataclasses import dataclass

from rapidfuzz import fuzz, process

DEFAULT_THRESHOLD = 82


def normalize(name: str) -> str:
    return " ".join(name.lower().replace("&", "and").split())


@dataclass
class MatchResult:
    query: str
    match: str | None
    score: float


def best_match(name: str, candidates: list[str], threshold: float = DEFAULT_THRESHOLD) -> MatchResult:
    if not candidates:
        return MatchResult(name, None, 0.0)

    normalized_candidates = [normalize(c) for c in candidates]
    result = process.extractOne(normalize(name), normalized_candidates, scorer=fuzz.WRatio)
    if result is None:
        return MatchResult(name, None, 0.0)

    _, score, idx = result
    if score < threshold:
        return MatchResult(name, None, score)
    return MatchResult(name, candidates[idx], score)
