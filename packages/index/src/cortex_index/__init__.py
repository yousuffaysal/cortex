"""Incremental file index with hybrid retrieval.

    >>> from cortex_index import IndexStore, Indexer
    >>> with IndexStore("index.sqlite") as store:          # doctest: +SKIP
    ...     hits = Indexer(store).search("connection pool", roots=[Path("~/dev")])
"""

from .embed import Embedder, HashingEmbedder, chunk_text
from .exact import ExactSearcher, RipgrepMissing, find_ripgrep
from .fusion import DEFAULT_WEIGHTS, RRF_K, FusedHit, Source, fuse
from .indexer import Indexer, IndexReport
from .store import ChunkHit, IndexStore, VectorUnavailable
from .walker import FileRecord, WalkStats, walk
from .watch import IndexWatcher, WatchStats

__all__ = [
    "DEFAULT_WEIGHTS",
    "RRF_K",
    "ChunkHit",
    "Embedder",
    "ExactSearcher",
    "FileRecord",
    "FusedHit",
    "HashingEmbedder",
    "IndexReport",
    "IndexStore",
    "IndexWatcher",
    "Indexer",
    "RipgrepMissing",
    "Source",
    "VectorUnavailable",
    "WalkStats",
    "WatchStats",
    "chunk_text",
    "find_ripgrep",
    "fuse",
    "walk",
]
