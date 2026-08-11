"""Orchestration: walk, chunk, embed, store, and search.

In:   approved roots.
Out:  a populated :class:`IndexStore`, and fused search results over it.
Fail: a single unreadable or undecodable file is skipped and counted, never fatal. One
      bad file in 200,000 must not abort an index.

Incremental is the default, not an optimisation
------------------------------------------------
:meth:`Indexer.index_root` compares mtime and size against what is stored and does no
work for unchanged files. A re-index of an untouched tree is therefore one indexed
lookup per file — no reads, no hashing, no embedding. This is what makes the watcher
viable: it can call the same code path for a single changed file.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .embed import Embedder, HashingEmbedder, chunk_text
from .exact import ExactSearcher, RipgrepMissing
from .fusion import DEFAULT_WEIGHTS, FusedHit, Source, fuse
from .store import ChunkHit, IndexStore, read_chunk_text
from .walker import FileRecord, WalkStats, walk

__all__ = ["IndexReport", "Indexer"]


@dataclass
class IndexReport:
    root: str
    files_indexed: int = 0
    files_unchanged: int = 0
    files_removed: int = 0
    chunks_written: int = 0
    errors: int = 0
    seconds: float = 0.0
    walk_stats: dict[str, int] = field(default_factory=dict)

    @property
    def files_per_second(self) -> float:
        return self.files_indexed / self.seconds if self.seconds > 0 else 0.0

    def __str__(self) -> str:
        return (
            f"{self.root}: {self.files_indexed} indexed, {self.files_unchanged} unchanged, "
            f"{self.files_removed} removed, {self.chunks_written} chunks, "
            f"{self.errors} errors in {self.seconds:.2f}s "
            f"({self.files_per_second:.0f} files/s)"
        )


class Indexer:
    def __init__(
        self,
        store: IndexStore,
        embedder: Embedder | None = None,
        *,
        exact: ExactSearcher | None = None,
        embed_batch: int = 128,
    ) -> None:
        self.store = store
        self.embedder = embedder or HashingEmbedder(dimensions=store.dimensions)
        self.embed_batch = embed_batch
        self._exact = exact
        if self.embedder.dimensions != store.dimensions:
            raise ValueError(
                f"embedder produces {self.embedder.dimensions} dimensions but the store "
                f"was created for {store.dimensions}; they must match"
            )

    # -- exact search is optional ------------------------------------------------

    @property
    def exact(self) -> ExactSearcher | None:
        """None when ripgrep is absent. Search degrades rather than failing entirely."""
        if self._exact is None:
            try:
                self._exact = ExactSearcher()
            except RipgrepMissing:
                return None
        return self._exact

    # -- indexing ----------------------------------------------------------------

    def index_file(self, record: FileRecord, root: Path) -> int:
        """Index one file. Returns chunks written, or 0 if it was skipped."""
        try:
            text = record.path.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeDecodeError):
            # Not text after all, or vanished between walk and read. Both are normal.
            return 0

        chunks = chunk_text(text)
        if not chunks:
            return 0

        vectors: list[list[float]] | None = None
        try:
            vectors = []
            for start in range(0, len(chunks), self.embed_batch):
                batch = [c[2] for c in chunks[start : start + self.embed_batch]]
                vectors.extend(self.embedder.embed(batch))
        except Exception:  # noqa: BLE001 - an embedder failure must not lose the file
            # Full-text and exact search still work without a vector. Losing semantic
            # recall for one file beats losing the file from the index entirely.
            vectors = None

        return self.store.upsert_file(
            path=str(record.path),
            root=str(root),
            size=record.size,
            mtime_ns=record.mtime_ns,
            content_hash=hashlib.blake2b(text.encode("utf-8"), digest_size=16).hexdigest(),
            indexed_at=time.time(),
            chunks=chunks,
            vectors=vectors,
        )

    def index_root(
        self, root: Path, *, prune_missing: bool = True, commit_every: int = 500
    ) -> IndexReport:
        """Bring the index up to date for one approved root."""
        root = Path(root).resolve()
        started = time.perf_counter()
        report = IndexReport(root=str(root))
        stats = WalkStats()
        present: set[str] = set()

        pending = 0
        for record in walk(root, stats=stats):
            present.add(record.key)
            if not self.store.needs_reindex(record.key, record.mtime_ns, record.size):
                report.files_unchanged += 1
                continue
            written = self.index_file(record, root)
            if written == 0:
                report.errors += 1
                continue
            report.files_indexed += 1
            report.chunks_written += written
            pending += 1
            if pending >= commit_every:
                self.store.commit()
                pending = 0

        if prune_missing:
            known = {
                str(row["path"])
                for row in self.store.connection.execute(
                    "SELECT path FROM files WHERE root=?", (str(root),)
                )
            }
            for stale in known - present:
                self.store.delete_file(stale)
                report.files_removed += 1

        self.store.commit()
        report.seconds = time.perf_counter() - started
        report.walk_stats = stats.as_dict()
        return report

    def remove_path(self, path: Path | str) -> None:
        self.store.delete_file(str(Path(path).resolve()))
        self.store.commit()

    # -- retrieval ---------------------------------------------------------------

    def search(
        self,
        query: str,
        roots: Sequence[Path] | None = None,
        *,
        limit: int = 20,
        per_source: int = 50,
        weights: dict[Source, float] | None = None,
        use_exact: bool = True,
        use_fts: bool = True,
        use_vector: bool = True,
    ) -> list[FusedHit]:
        """Hybrid search. Each retriever contributes a ranking; RRF fuses them."""
        results: dict[Source, list[ChunkHit]] = {}

        if use_exact and roots:
            searcher = self.exact
            if searcher is not None:
                raw = searcher.search(query, list(roots), limit=per_source)
                results[Source.EXACT] = self._align_to_chunks(raw)

        if use_fts:
            results[Source.FTS] = self.store.search_fts(_fts_query(query), limit=per_source)

        if use_vector:
            vector = self.embedder.embed([query])[0]
            results[Source.VECTOR] = self.store.search_vector(vector, limit=per_source)

        fused = fuse(results, weights=weights or DEFAULT_WEIGHTS, limit=limit)
        for hit in fused:
            if not hit.snippet:
                text = read_chunk_text(hit.path, hit.start_line, hit.end_line)
                hit.snippet = text[:400]
        return fused

    def _align_to_chunks(self, hits: Sequence[ChunkHit]) -> list[ChunkHit]:
        """Snap ripgrep's line hits onto the chunks that contain them.

        Without this, fusion can never merge an exact hit with a full-text or vector
        hit: ripgrep reports line 7, the other two report the chunk spanning lines
        1-40, and keyed on (path, start, end) those are three different results. The
        agreement bonus that justifies RRF would then be unreachable by construction.

        Order is preserved, because RRF uses rank and nothing else. Duplicates are
        collapsed — several matching lines inside one chunk are one piece of evidence
        about that chunk, not several.
        """
        aligned: list[ChunkHit] = []
        seen: set[tuple[str, int, int]] = set()

        for hit in hits:
            row = self.store.connection.execute(
                "SELECT c.id, c.start_line, c.end_line FROM chunks c "
                "JOIN files f ON f.id = c.file_id "
                "WHERE f.path = ? AND c.start_line <= ? AND c.end_line >= ? "
                "ORDER BY c.start_line LIMIT 1",
                (hit.path, hit.start_line, hit.start_line),
            ).fetchone()

            if row is None:
                # File matched on disk but is not in the index — a root that was
                # searched but never indexed. Keep the line hit; it is still a result.
                identity = (hit.path, hit.start_line, hit.end_line)
                if identity not in seen:
                    seen.add(identity)
                    aligned.append(hit)
                continue

            identity = (hit.path, int(row["start_line"]), int(row["end_line"]))
            if identity in seen:
                continue
            seen.add(identity)
            aligned.append(
                ChunkHit(
                    chunk_id=int(row["id"]),
                    path=hit.path,
                    start_line=int(row["start_line"]),
                    end_line=int(row["end_line"]),
                    score=hit.score,
                    snippet=hit.snippet,
                )
            )
        return aligned


def _fts_query(query: str) -> str:
    """Turn free text into a safe FTS5 MATCH expression.

    FTS5 has its own query syntax, so a user typing ``foo(bar)`` or an unbalanced quote
    is a syntax error rather than a search. Each bare word is quoted and the words are
    ANDed, which is what a person means by a multi-word search.
    """
    words = [w for w in _split_words(query) if w]
    if not words:
        return '""'
    return " AND ".join(f'"{w}"' for w in words)


def _split_words(query: str) -> list[str]:
    out: list[str] = []
    current: list[str] = []
    for char in query:
        if char.isalnum() or char == "_":
            current.append(char)
        elif current:
            out.append("".join(current))
            current = []
    if current:
        out.append("".join(current))
    return out
