"""The non-overridable denylist.

In:   the raw command string and its resolved commands.
Out:  a :class:`DenyMatch` or ``None``.
Fail: never raises.

CLAUDE.md invariant 4: this list is not user-overridable. Nothing in this module reads
:class:`~cortex_policy.risk.PolicyContext` — it cannot see the autonomy level, the
workspace, or the allowlist, so there is no argument any caller can pass that changes
its answer. That is the point, and it is why the signature deliberately does not take
a context.

A DENY is not an approval prompt with sterner wording. The UI renders it as refused,
with the matched rule, and offers no yes.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from .resolve import ResolvedCommand

__all__ = ["DenyMatch", "check"]


@dataclass(frozen=True)
class DenyMatch:
    rule: str
    reason: str


#: Paths where a recursive delete is unrecoverable and never intended.
_CRITICAL_ROOTS: frozenset[str] = frozenset(
    {
        "/",
        "/bin",
        "/sbin",
        "/boot",
        "/dev",
        "/etc",
        "/home",
        "/lib",
        "/opt",
        "/private",
        "/proc",
        "/sys",
        "/usr",
        "/usr/bin",
        "/usr/lib",
        "/usr/local",
        "/usr/sbin",
        "/var",
        "/Applications",
        "/Library",
        "/System",
        "/Users",
        "/Volumes",
    }
)

_RECURSIVE_FLAGS = ("-r", "-R", "--recursive")
_FORCE_FLAGS = ("-f", "--force")

#: `:(){ :|:& };:` and any renamed equivalent.
_FORK_BOMB = re.compile(r"([\w:]+)\s*\(\s*\)\s*\{[^}]*\|[^}]*&[^}]*\}\s*;?\s*\1?")

_FETCHERS: frozenset[str] = frozenset({"curl", "wget", "fetch", "aria2c", "httpie", "http"})
_SHELL_SINKS: frozenset[str] = frozenset(
    {"sh", "bash", "zsh", "dash", "ksh", "fish", "python", "python3", "perl", "ruby", "node"}
)

_BLOCK_DEVICE = re.compile(r"^/dev/(r?disk\d|sd[a-z]|hd[a-z]|nvme\d|vd[a-z]|md\d)")

_DISK_DESTROYERS: frozenset[str] = frozenset(
    {"mkfs", "newfs", "newfs_hfs", "newfs_apfs", "fdisk", "gpt", "zpool", "wipefs"}
)

_DISKUTIL_DESTRUCTIVE: frozenset[str] = frozenset(
    {"eraseDisk", "eraseVolume", "partitionDisk", "reformat", "zeroDisk", "secureErase"}
)


def _normalise_target(operand: str, home: Path) -> str | None:
    """Collapse a path operand to a comparable absolute form.

    Returns ``None`` for operands that contain unresolved pieces — those are the
    engine's problem, not the denylist's, and guessing here would be the whole bug.
    """
    if "<unresolved:" in operand or "<substitution>" in operand:
        return None
    expanded = os.path.expanduser(operand)
    if not expanded:
        return None
    if expanded.startswith("~"):
        expanded = str(home) + expanded[1:]
    norm = os.path.normpath(expanded)
    while norm.startswith("//"):
        norm = norm[1:]
    return norm


def _is_critical(operand: str, home: Path) -> bool:
    norm = _normalise_target(operand, home)
    if norm is None:
        return False
    critical = set(_CRITICAL_ROOTS) | {str(home)}
    if norm in critical:
        return True
    # `/*`, `/Users/*`, `~/*` — the glob's parent is what actually gets walked.
    if any(ch in norm for ch in "*?["):
        parent = os.path.normpath(os.path.dirname(norm))
        if parent in critical:
            return True
    return False


def check(
    raw_command: str,
    commands: list[ResolvedCommand],
    *,
    home: Path | None = None,
) -> DenyMatch | None:
    """Return the first matching denylist rule, or ``None``.

    Deliberately takes no policy context: there is no caller-supplied value that can
    change the outcome.
    """
    home = home or Path.home()

    if _FORK_BOMB.search(raw_command):
        return DenyMatch(
            rule="fork_bomb",
            reason=(
                "Matches a fork bomb: a self-recursive function piped into a "
                "background copy of itself."
            ),
        )

    for command in commands:
        if command.has_flag("--no-preserve-root"):
            return DenyMatch(
                rule="no_preserve_root",
                reason=(
                    "Uses --no-preserve-root, whose only purpose is to remove the "
                    "guard against deleting /."
                ),
            )

        program = command.program

        if program == "rm" and command.has_flag(*_RECURSIVE_FLAGS):
            for operand in command.operands:
                if _is_critical(operand, home):
                    return DenyMatch(
                        rule="rm_recursive_system_root",
                        reason=(
                            f"Recursive delete targeting {operand!r}, a system or "
                            "home root. Unrecoverable."
                        ),
                    )

        if program in _DISK_DESTROYERS or program.startswith("mkfs."):
            return DenyMatch(
                rule="filesystem_destroyer",
                reason=(
                    f"{program!r} formats or repartitions a device. Never runnable from an agent."
                ),
            )

        if program == "diskutil" and any(op in _DISKUTIL_DESTRUCTIVE for op in command.operands):
            return DenyMatch(
                rule="diskutil_destructive",
                reason="diskutil erase/partition destroys a volume irrecoverably.",
            )

        if program == "dd":
            for operand in command.operands:
                if operand.startswith("of=") and _BLOCK_DEVICE.match(operand[3:]):
                    return DenyMatch(
                        rule="dd_to_block_device",
                        reason=(
                            f"dd writing directly to {operand[3:]!r} destroys the disk's contents."
                        ),
                    )

        for target in command.redirects:
            if _BLOCK_DEVICE.match(target):
                return DenyMatch(
                    rule="redirect_to_block_device",
                    reason=f"Redirects output onto the raw block device {target!r}.",
                )

        if program in {"chmod", "chown"} and command.has_flag(*_RECURSIVE_FLAGS):
            for operand in command.operands:
                if _is_critical(operand, home):
                    return DenyMatch(
                        rule="recursive_permission_change_on_system_root",
                        reason=(
                            f"Recursive {program} on {operand!r} will break the "
                            "system's permissions irreparably."
                        ),
                    )

    # curl … | sh — fetch-and-execute in one step, the classic remote-code path.
    by_pipeline: dict[int, list[ResolvedCommand]] = {}
    for command in commands:
        by_pipeline.setdefault(command.pipeline_index, []).append(command)

    for stages in by_pipeline.values():
        stages.sort(key=lambda c: c.stage_index)
        for i, upstream in enumerate(stages):
            if upstream.program not in _FETCHERS:
                continue
            for downstream in stages[i + 1 :]:
                if downstream.stage_index == upstream.stage_index:
                    continue
                if downstream.program in _SHELL_SINKS:
                    return DenyMatch(
                        rule="fetch_piped_to_interpreter",
                        reason=(
                            f"Pipes {upstream.program} output straight into {downstream.program}. "
                            "The code that would run is never seen or reviewed."
                        ),
                    )

    return None
