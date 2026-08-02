"""Per-workspace toggles for the dangerous options.

In:   a workspace path.
Out:  a :class:`WorkspaceSettings` saying whether host execution and network are enabled.
Fail: a missing or malformed config reads as "everything off". Never as "on".

Where this file lives, and why it is not in the workspace
--------------------------------------------------------
The obvious place for per-workspace settings is inside the workspace — a
``.cortex/config.json`` next to the code. That is a privilege escalation waiting to
happen: the workspace is bind-mounted writable into the sandbox, and the agent can
write files there. An agent that wanted host execution could simply enable it, and the
"explicit user toggle" would be a toggle the agent flips for itself.

So the config lives in the user's application-support directory, keyed by absolute
workspace path, and is never mounted into any container. The sandbox cannot see it, let
alone write it. The toggle is only reachable from the host UI, which is the only place
a human is actually present to make the decision.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

__all__ = ["WorkspaceSettings", "config_path", "load_settings"]


def config_path() -> Path:
    """The settings file. Overridable by env var for tests only."""
    override = os.environ.get("CORTEX_CONFIG_DIR")
    if override:
        return Path(override) / "workspaces.json"
    return Path.home() / "Library" / "Application Support" / "Cortex" / "workspaces.json"


@dataclass(frozen=True)
class WorkspaceSettings:
    """Both defaults are the safe value. Absence of config means absence of permission."""

    host_execution_enabled: bool = False
    network_enabled: bool = False

    @property
    def any_isolation_disabled(self) -> bool:
        """Drives the persistent UI indicator: true means the user must be able to see
        that this workspace is running with reduced isolation, at all times."""
        return self.host_execution_enabled or self.network_enabled


def load_settings(workspace: Path) -> WorkspaceSettings:
    path = config_path()
    if not path.is_file():
        return WorkspaceSettings()

    try:
        raw = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        # A config we cannot read is a config we do not trust. Fail closed.
        return WorkspaceSettings()

    if not isinstance(raw, dict):
        return WorkspaceSettings()

    entry = raw.get(str(Path(workspace).resolve()))
    if not isinstance(entry, dict):
        return WorkspaceSettings()

    return WorkspaceSettings(
        host_execution_enabled=entry.get("host_execution_enabled") is True,
        network_enabled=entry.get("network_enabled") is True,
    )
