"""Fusing three retrievers into one ranking.

In:   ranked result lists from ripgrep, FTS5, and the vector index.
Out:  one ranking, with per-source provenance attached to every hit.
Fail: cannot fail; an empty list from any source simply contributes nothing.

The problem: the three scores are not comparable
------------------------------------------------
====================  ==========================================================
ripgrep               No score at all. A line either matches the pattern or does
                      not. Ordering is by file traversal, which is arbitrary.
FTS5 (BM25)           Unbounded negative reals. Magnitude depends on corpus
                      statistics, document length, and term rarity. A -12 in one
                      query means nothing relative to a -12 in another.
sqlite-vec            Cosine/L2 distance, bounded, but distances cluster tightly:
                      in a 256-dim space the gap between the 1st and 50th result
                      is often a couple of percent.
====================  ==========================================================

So the obvious approach — normalise each to 0..1 and take a weighted sum — is wrong in
a way that is easy to miss. Min-max normalisation is computed *over the returned
window*, so the worst result in every list is forced to 0 and the best to 1, regardless
of whether the list was excellent or garbage. A query where the vector index found
nothing relevant still contributes a confident 1.0 for its least-bad hit. Normalisation
manufactures agreement that the underlying scores do not support.

The fix: rank instead of score
------------------------------
**Reciprocal Rank Fusion.** Discard the scores; use only each list's ordering.

    RRF(d) = Σ over sources s:  weight[s] / (k + rank[s](d))

with ``rank`` 1-based and ``k = 60``.

Why this is the right shape:

* **It only needs an ordering**, which is the one thing all three retrievers genuinely
  produce. ripgrep's lack of a score stops being a special case.
* **It is scale-free.** No calibration between BM25 and cosine distance, and no
  recalibration when the corpus grows or the embedding model changes.
* **It rewards agreement.** A chunk ranked 3rd by two retrievers beats one ranked 1st
  by a single retriever — precisely the behaviour you want from a hybrid index, since
  independent methods agreeing is real evidence.
* **k=60 flattens the head.** Rank 1 scores 1/61 and rank 2 scores 1/62 — only 1.6%
  apart. Without the constant, rank 1 would be twice rank 2, and a single retriever's
  top hit would dominate everything. The 60 is from Cormack et al. (2009); it is a
  blunt instrument and the tests pin behaviour, not the constant.

Weights, and why they are not equal
-----------------------------------
``exact`` is weighted highest. If someone searches for a literal identifier and it
exists verbatim, that is the answer — no amount of semantic similarity should outrank
it. ``fts`` is next: stemming and multi-term relevance handle the common case.
``vector`` is weighted lowest **and is currently backed by a placeholder embedder**
(see :mod:`.embed`), so weighting it equally would be presenting hash collisions as
understanding.

When a real embedding model lands, ``vector`` should be re-weighted upward — and that
is a measurement to run, not a number to guess. :func:`fuse` takes weights as an
argument so the change is a config edit, not a code edit.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum

from .store import ChunkHit

__all__ = ["DEFAULT_WEIGHTS", "FusedHit", "RRF_K", "Source", "fuse"]

#: Cormack et al. (2009). Damps the head of each list so no single retriever dominates.
RRF_K = 60


class Source(StrEnum):
    EXACT = "exact"
    FTS = "fts"
    VECTOR = "vector"


DEFAULT_WEIGHTS: dict[Source, float] = {
    Source.EXACT: 1.0,
    Source.FTS: 0.8,
    # Deliberately low while the embedder is a placeholder. Raise it, after measuring,
    # once apps/core supplies a real model.
    Source.VECTOR: 0.4,
}


@dataclass
class FusedHit:
    path: str
    start_line: int
    end_line: int
    score: float
    #: Which retrievers found this, and at what rank. This is the evidence link the UI
    #: needs for invariant 20 — a result must be able to say why it is here.
    ranks: dict[Source, int] = field(default_factory=dict)
    snippet: str = ""

    @property
    def sources(self) -> list[Source]:
        return sorted(self.ranks, key=lambda s: self.ranks[s])

    @property
    def agreement(self) -> int:
        """How many independent retrievers surfaced this. Higher is stronger evidence."""
        return len(self.ranks)

    def explain(self) -> str:
        parts = ", ".join(f"{s.value}#{self.ranks[s]}" for s in self.sources)
        return f"{self.path}:{self.start_line}-{self.end_line} [{parts}] score={self.score:.5f}"


def _key(hit: ChunkHit) -> tuple[str, int, int]:
    """Identity for fusion.

    Keyed on (path, start_line, end_line) rather than chunk id, because ripgrep results
    have no chunk id — they are line numbers from a separate process. Overlapping chunks
    from the same file therefore stay distinct, which is intended: they are different
    windows of the file and cite different lines.
    """
    return (hit.path, hit.start_line, hit.end_line)


def fuse(
    results: dict[Source, Sequence[ChunkHit]],
    *,
    weights: dict[Source, float] | None = None,
    limit: int = 20,
    k: int = RRF_K,
) -> list[FusedHit]:
    """Combine ranked lists by weighted reciprocal rank.

    Only the ordering within each list is used. The scores on the incoming hits are
    ignored on purpose — see the module docstring.
    """
    weights = weights or DEFAULT_WEIGHTS
    accumulated: dict[tuple[str, int, int], FusedHit] = {}

    for source, hits in results.items():
        weight = weights.get(source, 0.0)
        if weight == 0.0:
            continue
        for position, hit in enumerate(hits, start=1):
            identity = _key(hit)
            existing = accumulated.get(identity)
            if existing is None:
                existing = FusedHit(
                    path=hit.path,
                    start_line=hit.start_line,
                    end_line=hit.end_line,
                    score=0.0,
                    snippet=hit.snippet,
                )
                accumulated[identity] = existing
            existing.score += weight / (k + position)
            existing.ranks[source] = position
            if not existing.snippet and hit.snippet:
                existing.snippet = hit.snippet

    ranked = sorted(
        accumulated.values(),
        # Ties broken by agreement, then by position, so ordering is deterministic —
        # a search that returns results in a different order run to run is unusable
        # for the evidence links in invariant 20.
        key=lambda h: (-h.score, -h.agreement, h.path, h.start_line),
    )
    return ranked[:limit]
