"""Deciding what may be indexed.

In:   an approved root.
Out:  a stream of :class:`FileRecord` for files that are safe and useful to index.
Fail: never raises on a single unreadable file; it is skipped and counted.

Three filters, in this order, because the cheap ones must run first on 200k files:

1. **The hard denylist** — CLAUDE.md invariant 10, via ``cortex_policy.sensitivity``.
   SSH keys, GPG keyrings, browser credential stores, password vaults. Not
   user-overridable and not merely a .gitignore default. ``.env`` files are excluded
   too: they need per-file approval, and an indexer is by definition not asking.
2. **.gitignore** — PRD §10. Honoured per-directory and cumulatively, the way git does
   it, so a nested ignore file applies below itself.
3. **Practical filters** — binary content, oversize files, and directories nobody wants
   in a search index.

Ordering note: the denylist is checked against every file *and* pruned at directory
level. Pruning alone would be wrong (a stray key file elsewhere would slip through) and
per-file alone would be slow (we would descend into ~/.ssh before rejecting).
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pathspec
from cortex_policy.paths import PathSensitivity, sensitivity

__all__ = ["FileRecord", "WalkStats", "walk"]

#: Never descended into. Cheap wins that .gitignore usually covers but not always.
_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__",
        ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".gradle",
        "dist", "build", "target", ".next", ".nuxt", ".parcel-cache",
        ".DS_Store", "Pods", ".terraform", ".cargo", ".rustup",
    }
)

#: Extensions we never read: their bytes are not text and embedding them is noise.
_SKIP_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tiff", ".heic",
        ".mp3", ".mp4", ".mov", ".avi", ".mkv", ".wav", ".flac", ".m4a",
        ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".dmg", ".iso",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".so", ".dylib", ".dll", ".a", ".o", ".pyc", ".pyo", ".class", ".jar",
        ".woff", ".woff2", ".ttf", ".otf", ".eot",
        ".sqlite", ".sqlite3", ".db", ".pack", ".idx",
    }
)

_DEFAULT_MAX_BYTES = 2 * 1024 * 1024
_BINARY_SNIFF_BYTES = 8192


@dataclass(frozen=True)
class FileRecord:
    path: Path
    size: int
    mtime_ns: int

    @property
    def key(self) -> str:
        return str(self.path)


@dataclass
class WalkStats:
    """Counters, so a slow or empty index can be explained rather than guessed at."""

    seen: int = 0
    indexed: int = 0
    skipped_denylist: int = 0
    skipped_gitignore: int = 0
    skipped_binary: int = 0
    skipped_too_large: int = 0
    skipped_unreadable: int = 0
    dirs_pruned: int = 0
    reasons: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, int]:
        return {
            "seen": self.seen,
            "indexed": self.indexed,
            "skipped_denylist": self.skipped_denylist,
            "skipped_gitignore": self.skipped_gitignore,
            "skipped_binary": self.skipped_binary,
            "skipped_too_large": self.skipped_too_large,
            "skipped_unreadable": self.skipped_unreadable,
            "dirs_pruned": self.dirs_pruned,
        }


def _load_gitignore(directory: Path) -> pathspec.PathSpec | None:
    candidate = directory / ".gitignore"
    if not candidate.is_file():
        return None
    try:
        lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    return pathspec.PathSpec.from_lines("gitwildmatch", lines)


def _is_ignored(specs: list[tuple[Path, pathspec.PathSpec]], path: Path, is_dir: bool) -> bool:
    """Test against every .gitignore in scope, nearest-last, like git."""
    for base, spec in specs:
        try:
            relative = path.relative_to(base).as_posix()
        except ValueError:
            continue
        if is_dir:
            relative += "/"
        if spec.match_file(relative):
            return True
    return False


def looks_binary(path: Path) -> bool:
    """A NUL byte in the first 8 KB. Crude, fast, and what git itself uses."""
    try:
        with path.open("rb") as handle:
            return b"\x00" in handle.read(_BINARY_SNIFF_BYTES)
    except OSError:
        return True


def walk(
    root: Path,
    *,
    max_bytes: int = _DEFAULT_MAX_BYTES,
    respect_gitignore: bool = True,
    stats: WalkStats | None = None,
) -> Iterator[FileRecord]:
    """Yield indexable files under ``root``.

    ``root`` must already be an approved root — this function does not decide what the
    user consented to index, only what is safe to index within it.
    """
    stats = stats if stats is not None else WalkStats()
    root = Path(root).resolve()

    if sensitivity(root) is PathSensitivity.PROTECTED:
        stats.skipped_denylist += 1
        return

    specs: list[tuple[Path, pathspec.PathSpec]] = []
    if respect_gitignore:
        root_spec = _load_gitignore(root)
        if root_spec is not None:
            specs.append((root, root_spec))

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current = Path(dirpath)

        if respect_gitignore and current != root:
            nested = _load_gitignore(current)
            if nested is not None:
                specs.append((current, nested))

        kept: list[str] = []
        for name in dirnames:
            child = current / name
            if name in _SKIP_DIRS:
                stats.dirs_pruned += 1
                continue
            # Prune at the directory level so we never descend into ~/.ssh at all.
            if sensitivity(child) is PathSensitivity.PROTECTED:
                stats.skipped_denylist += 1
                stats.dirs_pruned += 1
                continue
            if respect_gitignore and _is_ignored(specs, child, is_dir=True):
                stats.skipped_gitignore += 1
                stats.dirs_pruned += 1
                continue
            kept.append(name)
        dirnames[:] = kept

        for name in filenames:
            path = current / name
            stats.seen += 1

            # Checked per-file as well as per-directory: a key file can live anywhere.
            level = sensitivity(path)
            if level is not PathSensitivity.NORMAL:
                stats.skipped_denylist += 1
                continue

            if path.suffix.lower() in _SKIP_EXTENSIONS:
                stats.skipped_binary += 1
                continue

            if respect_gitignore and _is_ignored(specs, path, is_dir=False):
                stats.skipped_gitignore += 1
                continue

            try:
                info = path.lstat()
            except OSError:
                stats.skipped_unreadable += 1
                continue

            if not os.path.isfile(path) or os.path.islink(path):
                continue
            if info.st_size > max_bytes:
                stats.skipped_too_large += 1
                continue
            if info.st_size == 0:
                continue
            if looks_binary(path):
                stats.skipped_binary += 1
                continue

            stats.indexed += 1
            yield FileRecord(path=path, size=info.st_size, mtime_ns=info.st_mtime_ns)
