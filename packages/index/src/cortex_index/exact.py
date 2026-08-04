"""Exact and glob search, via ripgrep.

In:   a pattern and a set of approved roots.
Out:  ranked :class:`ChunkHit` values, one per matching line.
Fail: a guided error when ripgrep is absent. Never a FileNotFoundError.

Why shell out rather than use a Python regex walk
--------------------------------------------------
ripgrep is a parallel, SIMD-accelerated, mmap-based matcher that skips binary files and
honours .gitignore natively. A Python equivalent is roughly two orders of magnitude
slower on a large tree, which is the difference between a search feeling instant and
feeling broken. This is the one place in the index where a subprocess is clearly right.

*Not* passed through the shell: argv is a list, so a pattern containing ``;`` or ``$()``
is a pattern, not a command. Search input is attacker-controllable in the sense that
matters — it can come from a model that read an untrusted file (invariant 5).

Denylist note
-------------
ripgrep does not know about invariant 10, so results are filtered against
``cortex_policy.sensitivity`` after the fact. Belt and braces: ``--glob '!...'``
exclusions are also passed so ripgrep never opens those files in the first place.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from cortex_policy.paths import PathSensitivity, sensitivity

from .store import ChunkHit

__all__ = ["RipgrepMissing", "ExactSearcher", "find_ripgrep"]

_CANDIDATES = (
    "/opt/homebrew/bin/rg",
    "/usr/local/bin/rg",
    "/usr/bin/rg",
    "/home/linuxbrew/.linuxbrew/bin/rg",
)

#: Passed to ripgrep so it never even opens a credential store. Mirrors invariant 10.
_DENY_GLOBS = (
    "!.ssh/**", "!.gnupg/**", "!.password-store/**", "!**/Keychains/**",
    "!**/1Password*/**", "!**/Login Data*", "!**/logins.json", "!**/key[34].db",
    "!**/*.kdbx", "!**/id_rsa*", "!**/id_ed25519*", "!**/id_ecdsa*", "!**/.env",
    "!**/.env.*",
)


class RipgrepMissing(RuntimeError):
    """ripgrep is not installed. Carries remediation, not a stack trace."""

    def __init__(self, searched: list[str]) -> None:
        super().__init__(
            "ripgrep is not installed, so exact and glob search are unavailable.\n\n"
            "Cortex uses ripgrep because a Python equivalent is ~100x slower on a large "
            "tree, which is the difference between search feeling instant and feeling "
            "broken. Full-text and semantic search still work without it.\n\n"
            "1. Install it: brew install ripgrep\n"
            "2. Re-run the search. Cortex re-checks each time; no restart needed.\n\n"
            "Looked in:\n" + "\n".join(f"  {p}" for p in searched)
        )


def find_ripgrep() -> str:
    """Locate the ripgrep binary.

    Note the deliberate check that we did not find a *shim*: some tools install an `rg`
    that is really a wrapper around something else entirely, and silently searching with
    the wrong engine would be worse than not searching.
    """
    found = shutil.which("rg")
    candidates = [found] if found else []
    candidates += list(_CANDIDATES)

    for candidate in candidates:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            try:
                result = subprocess.run(
                    [candidate, "--version"], capture_output=True, text=True, timeout=10
                )
            except (OSError, subprocess.TimeoutExpired):
                continue
            if result.returncode == 0 and result.stdout.startswith("ripgrep "):
                return candidate

    raise RipgrepMissing([c for c in candidates if c] + ["$PATH"])


@dataclass
class ExactSearcher:
    binary: str | None = None

    def __post_init__(self) -> None:
        self._binary = self.binary or find_ripgrep()

    def search(
        self,
        pattern: str,
        roots: list[Path],
        *,
        limit: int = 50,
        glob: str | None = None,
        fixed_string: bool = True,
        case_sensitive: bool = False,
        timeout: int = 30,
    ) -> list[ChunkHit]:
        """Run ripgrep and return one hit per matching line.

        ``fixed_string`` defaults True: most searches are for a literal identifier, and
        treating user input as a regex by default turns a stray ``(`` into an error and
        a ``.*`` into a very slow scan.
        """
        if not roots:
            return []

        argv = [
            self._binary,
            "--json",
            "--no-messages",       # unreadable files are skipped, not reported as errors
            "--max-count", str(limit),
            "--max-filesize", "2M",
            "--threads", "0",      # ripgrep picks; it knows better than we do
        ]
        if fixed_string:
            argv.append("--fixed-strings")
        argv.append("--case-sensitive" if case_sensitive else "--ignore-case")
        for deny in _DENY_GLOBS:
            argv += ["--glob", deny]
        if glob:
            argv += ["--glob", glob]
        argv += ["--regexp", pattern]
        argv += [str(root) for root in roots]

        try:
            result = subprocess.run(  # noqa: S603 - argv list, never shell=True
                argv, capture_output=True, text=True, timeout=timeout, check=False
            )
        except FileNotFoundError as exc:
            raise RipgrepMissing([self._binary]) from exc
        except subprocess.TimeoutExpired:
            return []

        return self._parse(result.stdout, limit)

    @staticmethod
    def _parse(stdout: str, limit: int) -> list[ChunkHit]:
        hits: list[ChunkHit] = []
        for line in stdout.splitlines():
            if not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("type") != "match":
                continue

            data = event["data"]
            path = data.get("path", {}).get("text")
            if not path:
                continue
            # Resolve symlinks so paths match what the walker stored. On macOS /var is
            # a symlink to /private/var, so ripgrep and the walker disagree on the same
            # file — and fusion, which keys on path, would never merge their hits.
            path = os.path.realpath(path)
            # ripgrep does not know about invariant 10; enforce it here regardless.
            if sensitivity(path) is not PathSensitivity.NORMAL:
                continue

            line_number = int(data.get("line_number") or 0)
            text = (data.get("lines", {}).get("text") or "").rstrip("\n")
            hits.append(
                ChunkHit(
                    chunk_id=-1,  # not a chunk: this came from a separate process
                    path=path,
                    start_line=line_number,
                    end_line=line_number,
                    # ripgrep produces no score. Fusion uses rank only, which is exactly
                    # why RRF was chosen — see fusion.py.
                    score=0.0,
                    snippet=text[:400],
                )
            )
            if len(hits) >= limit:
                break
        return hits
