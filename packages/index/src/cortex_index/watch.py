"""Incremental updates via watchdog.

In:   filesystem events under approved roots.
Out:  index mutations, applied on a background thread.
Fail: an event for a file that vanished, or that policy forbids, is dropped silently.
      Those are normal, not errors.

Debouncing is the whole design
------------------------------
Editors do not emit one event per save. A single Vim write produces a create, a rename,
and two modifies; a build tool can emit thousands in a second. Indexing on every raw
event would mean re-reading and re-embedding the same file several times per keystroke.

So events are coalesced into a pending set and flushed after a quiet period. The
practical effect is that the cost of a burst is proportional to the number of distinct
files touched, not to the number of events — which is what makes the sub-200ms
incremental target achievable at all.

Threading note: watchdog calls handlers on its own observer thread. SQLite connections
are not shareable across threads, so the flush loop owns the writes and the handler
only ever mutates an in-memory set behind a lock.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from watchdog.events import (
    FileSystemEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from .indexer import Indexer
from .walker import FileRecord

__all__ = ["IndexWatcher", "WatchStats"]


@dataclass
class WatchStats:
    events_seen: int = 0
    files_updated: int = 0
    files_removed: int = 0
    flushes: int = 0
    last_flush_seconds: float = 0.0


class _Collector(FileSystemEventHandler):
    """Runs on watchdog's thread. Only touches the pending sets."""

    def __init__(self, changed: set[str], removed: set[str], lock: threading.Lock,
                 stats: WatchStats) -> None:
        self._changed = changed
        self._removed = removed
        self._lock = lock
        self._stats = stats

    def _record(self, path: str, deleted: bool) -> None:
        with self._lock:
            self._stats.events_seen += 1
            if deleted:
                self._changed.discard(path)
                self._removed.add(path)
            else:
                self._removed.discard(path)
                self._changed.add(path)

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._record(str(event.src_path), deleted=False)

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._record(str(event.src_path), deleted=False)

    def on_deleted(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._record(str(event.src_path), deleted=True)

    def on_moved(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._record(str(event.src_path), deleted=True)
            destination = getattr(event, "dest_path", None)
            if destination:
                self._record(str(destination), deleted=False)


class IndexWatcher:
    """Keeps an index current under one or more roots."""

    def __init__(
        self,
        indexer: Indexer,
        roots: list[Path],
        *,
        debounce_seconds: float = 0.25,
        on_flush: Callable[[WatchStats], None] | None = None,
    ) -> None:
        self.indexer = indexer
        self.roots = [Path(r).resolve() for r in roots]
        self.debounce_seconds = debounce_seconds
        self.stats = WatchStats()
        self._on_flush = on_flush

        self._changed: set[str] = set()
        self._removed: set[str] = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._observer = Observer()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        handler = _Collector(self._changed, self._removed, self._lock, self.stats)
        for root in self.roots:
            self._observer.schedule(handler, str(root), recursive=True)
        self._observer.start()
        self._thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._observer.stop()
        self._observer.join(timeout=5)
        if self._thread is not None:
            self._thread.join(timeout=5)

    def __enter__(self) -> IndexWatcher:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # -- flushing -----------------------------------------------------------------

    def _take_pending(self) -> tuple[set[str], set[str]]:
        with self._lock:
            changed, removed = set(self._changed), set(self._removed)
            self._changed.clear()
            self._removed.clear()
        return changed, removed

    def flush(self) -> int:
        """Apply everything pending. Returns the number of paths touched.

        Public so tests can drive it deterministically instead of sleeping and hoping.
        """
        changed, removed = self._take_pending()
        if not changed and not removed:
            return 0

        started = time.perf_counter()
        for path in removed:
            self.indexer.store.delete_file(path)
            self.stats.files_removed += 1

        for path in changed:
            candidate = Path(path)
            root = self._root_for(candidate)
            if root is None:
                continue
            record = self._record_for(candidate)
            if record is None:
                # Deleted between the event and the flush, or filtered by policy.
                self.indexer.store.delete_file(path)
                continue
            if not self.indexer.store.needs_reindex(record.key, record.mtime_ns, record.size):
                continue
            if self.indexer.index_file(record, root) > 0:
                self.stats.files_updated += 1

        self.indexer.store.commit()
        self.stats.flushes += 1
        self.stats.last_flush_seconds = time.perf_counter() - started
        if self._on_flush is not None:
            self._on_flush(self.stats)
        return len(changed) + len(removed)

    def _flush_loop(self) -> None:
        while not self._stop.wait(self.debounce_seconds):
            try:
                self.flush()
            except Exception:  # noqa: BLE001 - the watcher must outlive one bad file
                continue

    def _root_for(self, path: Path) -> Path | None:
        for root in self.roots:
            if path == root or root in path.parents:
                return root
        return None

    def _record_for(self, path: Path) -> FileRecord | None:
        """Re-apply the walker's filters to a single path.

        The watcher must not become a hole in the denylist: an event for a file inside
        an approved root still has to clear invariant 10, .gitignore, size, and binary
        checks before it is indexed.
        """
        from .walker import _SKIP_EXTENSIONS, looks_binary  # noqa: PLC0415
        from cortex_policy.paths import PathSensitivity, sensitivity  # noqa: PLC0415

        if sensitivity(path) is not PathSensitivity.NORMAL:
            return None
        if path.suffix.lower() in _SKIP_EXTENSIONS:
            return None
        try:
            info = path.lstat()
        except OSError:
            return None
        if not path.is_file() or path.is_symlink():
            return None
        if info.st_size == 0 or info.st_size > 2 * 1024 * 1024:
            return None
        if looks_binary(path):
            return None
        return FileRecord(path=path, size=info.st_size, mtime_ns=info.st_mtime_ns)
