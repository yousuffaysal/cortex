"""The embedding seam.

In:   text chunks.
Out:  fixed-width float vectors.
Fail: an embedder that cannot produce a vector raises; the indexer records the chunk
      without one rather than dropping the file.

Why this is an interface and not a Gemini call
----------------------------------------------
CLAUDE.md invariant 31: all model access goes through the single provider interface in
``apps/core``. No module outside it imports a vendor SDK or constructs a provider HTTP
call. The indexer is very obviously outside it.

So the indexer depends on :class:`Embedder` — a protocol — and something else supplies
the implementation. When ``apps/core`` exists, its provider satisfies this protocol and
nothing here changes. That is the point of invariant 31: swapping Gemini for Anthropic
is a one-file change, and this file is not that file.

:class:`HashingEmbedder` exists so chunking, storage, fusion, and ranking are all
testable and benchmarkable *today*, with no network, no API key, and no cost. It is a
deterministic bag-of-token-hashes projection — a real vector space with real geometry,
just a weak one. It is explicitly not a semantic model, and
:attr:`Embedder.is_semantic` says so, so nothing downstream can quietly present its
results as semantic search.
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import Protocol, runtime_checkable

__all__ = ["Embedder", "HashingEmbedder", "chunk_text"]

_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]+")


@runtime_checkable
class Embedder(Protocol):
    """What the indexer needs from whatever produces vectors."""

    @property
    def dimensions(self) -> int: ...

    @property
    def name(self) -> str: ...

    @property
    def is_semantic(self) -> bool:
        """False for placeholders. The UI must not label placeholder hits 'semantic'."""
        ...

    def embed(self, texts: list[str]) -> list[list[float]]: ...


class HashingEmbedder:
    """Deterministic, offline, dependency-free stand-in for a real embedding model.

    Hashes each token into a bucket and accumulates a sub-linear term weight, then
    L2-normalises. Two chunks sharing vocabulary land near each other; two that do not,
    do not. That is enough geometry to exercise sqlite-vec, the chunk pipeline, and the
    fusion ranker end to end.

    It emphatically does not capture meaning: "car" and "automobile" are orthogonal
    here. Anything claiming otherwise would be measuring the wrong thing.
    """

    def __init__(self, dimensions: int = 256) -> None:
        self._dimensions = dimensions

    @property
    def dimensions(self) -> int:
        return self._dimensions

    @property
    def name(self) -> str:
        return f"hashing-{self._dimensions}"

    @property
    def is_semantic(self) -> bool:
        return False

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._embed_one(text) for text in texts]

    def _embed_one(self, text: str) -> list[float]:
        vector = [0.0] * self._dimensions
        counts: dict[str, int] = {}
        for match in _TOKEN.finditer(text.lower()):
            token = match.group(0)
            counts[token] = counts.get(token, 0) + 1

        for token, count in counts.items():
            digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
            bucket = int.from_bytes(digest[:4], "little") % self._dimensions
            sign = 1.0 if digest[4] & 1 else -1.0
            vector[bucket] += sign * (1.0 + math.log(count))

        norm = math.sqrt(sum(value * value for value in vector))
        if norm == 0.0:
            return vector
        return [value / norm for value in vector]


def chunk_text(
    text: str, *, target_lines: int = 40, overlap_lines: int = 8
) -> list[tuple[int, int, str]]:
    """Split into overlapping line windows. Returns (start_line, end_line, text).

    Line-based rather than token-based because every result has to point at somewhere a
    human can open — a chunk that begins mid-line is not a citation. The overlap keeps a
    match from being lost when it straddles a boundary, which is the usual failure of
    naive fixed-size chunking.
    """
    lines = text.splitlines()
    if not lines:
        return []
    if len(lines) <= target_lines:
        return [(1, len(lines), text)]

    stride = max(1, target_lines - overlap_lines)
    chunks: list[tuple[int, int, str]] = []
    start = 0
    while start < len(lines):
        end = min(start + target_lines, len(lines))
        chunks.append((start + 1, end, "\n".join(lines[start:end])))
        if end == len(lines):
            break
        start += stride
    return chunks
