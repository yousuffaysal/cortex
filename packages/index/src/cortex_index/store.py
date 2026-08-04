"""The index itself: SQLite with FTS5 and sqlite-vec side by side.

In:   file records and their chunks.
Out:  ranked chunk ids from either retriever.
Fail: opening a store on an interpreter without ``enable_load_extension`` raises with an
      explanation rather than an AttributeError — see :func:`_load_vec`.

Why one database and not two
----------------------------
FTS5 and sqlite-vec are both SQLite virtual tables, so full-text and vector search live
in the same file, under the same transaction, next to the ``files`` and ``chunks``
tables they both reference. A chunk cannot be present in one index and missing from the
other, because inserting it does both in one transaction. Two separate stores would
drift the first time a write failed halfway.

Schema shape
------------
``files``  — one row per path, with the mtime and content hash that make incremental
             updates possible: unchanged file, no work.
``chunks`` — overlapping line windows, each pointing back at a file and a line range so
             every hit can be opened at the right place.
``chunks_fts``     — FTS5 over chunk text, external-content against ``chunks``.
``chunk_vectors``  — vec0 over chunk embeddings.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType

import sqlite_vec

__all__ = ["ChunkHit", "IndexStore", "VectorUnavailable"]


class VectorUnavailable(RuntimeError):
    """Raised when sqlite-vec cannot be loaded on this interpreter."""


@dataclass(frozen=True)
class ChunkHit:
    chunk_id: int
    path: str
    start_line: int
    end_line: int
    score: float
    snippet: str = ""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    id            INTEGER PRIMARY KEY,
    path          TEXT    NOT NULL UNIQUE,
    root          TEXT    NOT NULL,
    size          INTEGER NOT NULL,
    mtime_ns      INTEGER NOT NULL,
    content_hash  TEXT    NOT NULL,
    indexed_at    REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_files_root ON files(root);

CREATE TABLE IF NOT EXISTS chunks (
    id         INTEGER PRIMARY KEY,
    file_id    INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    start_line INTEGER NOT NULL,
    end_line   INTEGER NOT NULL,
    text       TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chunks_file ON chunks(file_id);

-- External-content FTS5: the text lives in `chunks`, the index only stores postings.
-- Roughly halves the on-disk cost versus a self-contained FTS table.
CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts
USING fts5(text, content='chunks', content_rowid='id', tokenize='porter unicode61');

CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


def _load_vec(conn: sqlite3.Connection) -> None:
    if not hasattr(conn, "enable_load_extension"):
        raise VectorUnavailable(
            "This Python's sqlite3 was built without enable_load_extension, so "
            "sqlite-vec cannot be loaded and semantic search is unavailable.\n\n"
            "1. Use a uv-managed CPython 3.12 (uv python install 3.12), which has it "
            "enabled.\n"
            "2. The locally installed CPython 3.13 does NOT — this package pins 3.12 "
            "in .python-version for exactly this reason."
        )
    conn.enable_load_extension(True)
    sqlite_vec.load(conn)
    conn.enable_load_extension(False)


class IndexStore:
    def __init__(self, path: Path | str, dimensions: int = 256) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.dimensions = dimensions
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        # WAL so the watcher can write while a search reads. NORMAL rather than FULL:
        # this is a derived cache, not the audit log — losing the tail of an index on
        # power loss costs a re-scan, not evidence.
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        _load_vec(self._conn)
        self._conn.execute(
            f"CREATE VIRTUAL TABLE IF NOT EXISTS chunk_vectors "
            f"USING vec0(embedding float[{dimensions}])"
        )
        self._conn.commit()

    # -- lifecycle --------------------------------------------------------------

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> IndexStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    @property
    def connection(self) -> sqlite3.Connection:
        return self._conn

    # -- writing ----------------------------------------------------------------

    def needs_reindex(self, path: str, mtime_ns: int, size: int) -> bool:
        """Cheap staleness check: mtime and size, no hashing, no reading.

        This is what makes an incremental pass fast — for an unchanged tree it is one
        indexed lookup per file and nothing else.
        """
        row = self._conn.execute(
            "SELECT mtime_ns, size FROM files WHERE path=?", (path,)
        ).fetchone()
        if row is None:
            return True
        return int(row["mtime_ns"]) != mtime_ns or int(row["size"]) != size

    def delete_file(self, path: str) -> None:
        row = self._conn.execute("SELECT id FROM files WHERE path=?", (path,)).fetchone()
        if row is None:
            return
        file_id = int(row["id"])
        chunk_ids = [
            int(r["id"])
            for r in self._conn.execute("SELECT id FROM chunks WHERE file_id=?", (file_id,))
        ]
        for chunk_id in chunk_ids:
            # External-content FTS5 requires the 'delete' command with the old text.
            old = self._conn.execute(
                "SELECT text FROM chunks WHERE id=?", (chunk_id,)
            ).fetchone()
            if old is not None:
                self._conn.execute(
                    "INSERT INTO chunks_fts(chunks_fts, rowid, text) VALUES('delete', ?, ?)",
                    (chunk_id, old["text"]),
                )
            self._conn.execute("DELETE FROM chunk_vectors WHERE rowid=?", (chunk_id,))
        self._conn.execute("DELETE FROM chunks WHERE file_id=?", (file_id,))
        self._conn.execute("DELETE FROM files WHERE id=?", (file_id,))

    def upsert_file(
        self,
        path: str,
        root: str,
        size: int,
        mtime_ns: int,
        content_hash: str,
        indexed_at: float,
        chunks: list[tuple[int, int, str]],
        vectors: list[list[float]] | None = None,
    ) -> int:
        """Replace a file's rows atomically. Returns the number of chunks written."""
        self.delete_file(path)
        cursor = self._conn.execute(
            "INSERT INTO files(path, root, size, mtime_ns, content_hash, indexed_at) "
            "VALUES (?,?,?,?,?,?)",
            (path, root, size, mtime_ns, content_hash, indexed_at),
        )
        file_id = int(cursor.lastrowid or 0)

        for position, (start_line, end_line, text) in enumerate(chunks):
            chunk_cursor = self._conn.execute(
                "INSERT INTO chunks(file_id, start_line, end_line, text) VALUES (?,?,?,?)",
                (file_id, start_line, end_line, text),
            )
            chunk_id = int(chunk_cursor.lastrowid or 0)
            self._conn.execute(
                "INSERT INTO chunks_fts(rowid, text) VALUES (?,?)", (chunk_id, text)
            )
            if vectors is not None and position < len(vectors):
                self._conn.execute(
                    "INSERT INTO chunk_vectors(rowid, embedding) VALUES (?,?)",
                    (chunk_id, sqlite_vec.serialize_float32(vectors[position])),
                )
        return len(chunks)

    def commit(self) -> None:
        self._conn.commit()

    # -- reading ----------------------------------------------------------------

    def search_fts(self, query: str, limit: int = 50) -> list[ChunkHit]:
        """BM25 full-text. Handles stemming and multi-term relevance; no fuzzy matching."""
        try:
            rows = self._conn.execute(
                "SELECT c.id, f.path, c.start_line, c.end_line, "
                "       bm25(chunks_fts) AS score, "
                "       snippet(chunks_fts, 0, '', '', '…', 12) AS snip "
                "FROM chunks_fts "
                "JOIN chunks c ON c.id = chunks_fts.rowid "
                "JOIN files  f ON f.id = c.file_id "
                "WHERE chunks_fts MATCH ? ORDER BY score LIMIT ?",
                (query, limit),
            ).fetchall()
        except sqlite3.OperationalError:
            # Malformed FTS5 query (unbalanced quote, bare operator). An unparseable
            # query is zero results, never a crash in the middle of a search.
            return []
        # bm25() returns *negative* numbers, better matches more negative. Flip it so
        # every retriever in this package agrees that higher means better.
        return [
            ChunkHit(
                chunk_id=int(r["id"]), path=str(r["path"]),
                start_line=int(r["start_line"]), end_line=int(r["end_line"]),
                score=-float(r["score"]), snippet=str(r["snip"] or ""),
            )
            for r in rows
        ]

    def search_vector(self, vector: list[float], limit: int = 50) -> list[ChunkHit]:
        """k-nearest-neighbour over chunk embeddings."""
        rows = self._conn.execute(
            "SELECT v.rowid AS id, v.distance AS distance, f.path, c.start_line, c.end_line "
            "FROM chunk_vectors v "
            "JOIN chunks c ON c.id = v.rowid "
            "JOIN files  f ON f.id = c.file_id "
            "WHERE v.embedding MATCH ? AND k = ? "
            "ORDER BY v.distance",
            (sqlite_vec.serialize_float32(vector), limit),
        ).fetchall()
        # Distance: lower is closer. Negate for the same higher-is-better convention.
        return [
            ChunkHit(
                chunk_id=int(r["id"]), path=str(r["path"]),
                start_line=int(r["start_line"]), end_line=int(r["end_line"]),
                score=-float(r["distance"]),
            )
            for r in rows
        ]

    # -- stats ------------------------------------------------------------------

    def counts(self) -> dict[str, int]:
        files = self._conn.execute("SELECT COUNT(*) AS n FROM files").fetchone()["n"]
        chunks = self._conn.execute("SELECT COUNT(*) AS n FROM chunks").fetchone()["n"]
        vectors = self._conn.execute("SELECT COUNT(*) AS n FROM chunk_vectors").fetchone()["n"]
        return {"files": int(files), "chunks": int(chunks), "vectors": int(vectors)}

    def size_bytes(self) -> int:
        """Total on-disk footprint, including the WAL sidecar."""
        return sum(
            candidate.stat().st_size
            for candidate in self.path.parent.glob(self.path.name + "*")
            if candidate.is_file()
        )
