"""Path scoping and the paths that are never readable.

In:   a path the agent proposes to touch, and the task's approved workspace roots.
Out:  whether the path is inside a workspace, and whether it is protected outright.
Fail: on anything it cannot resolve, it reports *not contained* and *sensitive*.
      Being wrong in the safe direction costs an approval click; being wrong in the
      other direction costs an SSH key.

CLAUDE.md invariant 10 lists what may never be indexed or read: ~/.ssh, GPG keyrings,
browser credential stores, password manager vaults. That list is enforced here and is
not user-overridable — there is no context object that can switch it off.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath

__all__ = [
    "Containment",
    "PathSensitivity",
    "contains",
    "resolve_for_policy",
    "sensitivity",
]


class PathSensitivity(str, Enum):
    NORMAL = "normal"
    #: PRD §11 / invariant 10: readable only with explicit per-file approval, every time.
    PER_FILE_APPROVAL = "per_file_approval"
    #: Never readable. No approval prompt is offered, because there is no yes.
    PROTECTED = "protected"


#: Directories under $HOME that hold credentials. Matched on any ancestor.
_HOME_PROTECTED_DIRS: tuple[str, ...] = (
    ".ssh",
    ".gnupg",
    ".password-store",
    "Library/Keychains",
    "Library/Application Support/1Password",
    "Library/Application Support/Bitwarden",
    "Library/Group Containers/2BUA8C4S2C.com.1password",
    ".config/1Password",
    ".mozilla",
    "Library/Application Support/Firefox/Profiles",
    "Library/Application Support/Google/Chrome",
    "Library/Application Support/Chromium",
    "Library/Application Support/BraveSoftware",
)

#: Absolute paths that are protected regardless of who owns them.
_ABS_PROTECTED: tuple[str, ...] = (
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/master.passwd",
    "/private/etc/master.passwd",
    "/private/etc/shadow",
    "/private/etc/sudoers",
)

#: Basenames that are private keys or vaults wherever they happen to live.
_PROTECTED_BASENAMES: frozenset[str] = frozenset(
    {
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "identity",
        "authorized_keys",
        "known_hosts",
        "secring.gpg",
        "trustdb.gpg",
        "login.keychain",
        "login.keychain-db",
        "logins.json",
        "key4.db",
        "key3.db",
        "cookies.sqlite",
        "Login Data",
        "Login Data For Account",
    }
)

_PROTECTED_SUFFIXES: frozenset[str] = frozenset({".kdbx", ".kdb", ".agilekeychain", ".opvault"})


def resolve_for_policy(path: Path | str) -> Path:
    """Expand ``~``, make absolute, and follow symlinks as far as the OS will.

    ``os.path.realpath`` resolves what exists and normalises the rest lexically, so
    this works for paths that have not been created yet.
    """
    return Path(os.path.realpath(os.path.expanduser(str(path))))


def _lexical(path: Path | str) -> Path:
    """Absolute and ``..``-normalised, but *without* following symlinks."""
    return Path(os.path.abspath(os.path.expanduser(str(path))))


def _relative_parts(path: Path, base: Path) -> tuple[str, ...] | None:
    try:
        return path.relative_to(base).parts
    except ValueError:
        return None


def sensitivity(path: Path | str, *, home: Path | None = None) -> PathSensitivity:
    """Classify a path against the non-overridable read denylist.

    Checked against both the lexical and the symlink-resolved form, so a symlink
    pointing into ``~/.ssh`` is caught by the resolved check even when the name given
    looks innocuous.
    """
    home = home or Path.home()
    candidates = {_lexical(path), resolve_for_policy(path)}

    for candidate in candidates:
        as_posix = candidate.as_posix()

        if as_posix in _ABS_PROTECTED:
            return PathSensitivity.PROTECTED
        if candidate.name in _PROTECTED_BASENAMES:
            return PathSensitivity.PROTECTED
        if candidate.suffix in _PROTECTED_SUFFIXES:
            return PathSensitivity.PROTECTED

        rel = _relative_parts(candidate, home)
        if rel is not None:
            rel_posix = PurePosixPath(*rel).as_posix()
            for protected in _HOME_PROTECTED_DIRS:
                if rel_posix == protected or rel_posix.startswith(protected + "/"):
                    return PathSensitivity.PROTECTED

    for candidate in candidates:
        name = candidate.name
        if name == ".env" or name.startswith(".env."):
            return PathSensitivity.PER_FILE_APPROVAL

    return PathSensitivity.NORMAL


@dataclass(frozen=True)
class Containment:
    inside: bool
    #: True when the path *looks* inside a workspace but resolves outside it. This is
    #: a symlink escape; the fs server has more to say about it, policy just refuses.
    symlink_escape: bool
    matched_workspace: Path | None


def contains(workspaces: "tuple[Path, ...] | list[Path]", path: Path | str) -> Containment:
    """Is ``path`` inside any approved workspace?

    Containment must hold *both* lexically and after symlink resolution. A path that
    passes one and fails the other is an escape attempt, not a near-miss.
    """
    lex = _lexical(path)
    real = resolve_for_policy(path)

    lexical_match: Path | None = None
    real_match: Path | None = None

    for workspace in workspaces:
        ws_lex = _lexical(workspace)
        ws_real = resolve_for_policy(workspace)
        if lexical_match is None and (lex == ws_lex or lex.is_relative_to(ws_lex)):
            lexical_match = ws_lex
        if real_match is None and (real == ws_real or real.is_relative_to(ws_real)):
            real_match = ws_real

    if real_match is not None and lexical_match is not None:
        return Containment(inside=True, symlink_escape=False, matched_workspace=real_match)
    if lexical_match is not None and real_match is None:
        return Containment(inside=False, symlink_escape=True, matched_workspace=None)
    return Containment(inside=False, symlink_escape=False, matched_workspace=None)
