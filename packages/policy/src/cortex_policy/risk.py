"""Risk vocabulary for The Cortex.

In:   nothing (pure definitions).
Out:  the enums and models every other part of the policy package speaks in.
Fail: cannot fail at runtime; a change here is a change to the security contract.

The risk table is CLAUDE.md's, verbatim, and PRD §6.2's. It is duplicated in neither
place by accident: this module is the machine-readable copy, and any divergence from
the prose is a defect in this file, not in the prose.
"""

from __future__ import annotations

from enum import Enum, IntEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class RiskClass(str, Enum):
    """What kind of damage an operation can do.

    Ordered by severity via :data:`SEVERITY`. When one command implies several
    classes, the most severe wins — never the average, never the first match.
    """

    READ = "read"
    COMPUTE = "compute"
    WRITE_SCOPED = "write_scoped"
    WRITE_BROAD = "write_broad"
    EXEC_HOST = "exec_host"
    NETWORK = "network"
    IRREVERSIBLE = "irreversible"


#: Total order over risk classes. Used only to escalate, never to discount.
SEVERITY: dict[RiskClass, int] = {
    RiskClass.READ: 0,
    RiskClass.COMPUTE: 1,
    RiskClass.WRITE_SCOPED: 2,
    RiskClass.NETWORK: 3,
    RiskClass.EXEC_HOST: 4,
    RiskClass.WRITE_BROAD: 5,
    RiskClass.IRREVERSIBLE: 6,
}


def most_severe(classes: "list[RiskClass]") -> RiskClass:
    """Escalation rule: a compound operation is as risky as its worst part."""
    if not classes:
        return RiskClass.EXEC_HOST  # fail closed: an empty classification is not "safe"
    return max(classes, key=lambda c: SEVERITY[c])


class AutonomyLevel(IntEnum):
    """PRD §6.1. Higher is more autonomous; no level disables the denylist."""

    L0_OBSERVE = 0
    L1_CONFIRM_EACH = 1
    L2_CONFIRM_RISKY = 2
    L3_AUTONOMOUS = 3


class Verdict(str, Enum):
    """The only three answers the engine can give.

    ``DENY`` is not "approve with a scarier dialog". There is no UI path that turns a
    ``DENY`` into an execution — CLAUDE.md invariant 4.
    """

    ALLOW = "allow"
    APPROVE = "approve"
    DENY = "deny"


#: Which classes run without asking, per level. Anything absent requires approval.
#: ``IRREVERSIBLE`` and ``WRITE_BROAD`` appear at no level — invariant 3, PRD §6.1.
AUTO_AT_LEVEL: dict[AutonomyLevel, frozenset[RiskClass]] = {
    AutonomyLevel.L0_OBSERVE: frozenset(),
    AutonomyLevel.L1_CONFIRM_EACH: frozenset(),
    AutonomyLevel.L2_CONFIRM_RISKY: frozenset(
        {RiskClass.READ, RiskClass.COMPUTE, RiskClass.WRITE_SCOPED}
    ),
    AutonomyLevel.L3_AUTONOMOUS: frozenset(
        {
            RiskClass.READ,
            RiskClass.COMPUTE,
            RiskClass.WRITE_SCOPED,
            RiskClass.EXEC_HOST,
            RiskClass.NETWORK,
        }
    ),
}

#: Classes that a post-ingestion privilege drop re-gates even at L3.
#: CLAUDE.md invariant 7, PRD §6.4.3.
PRIVILEGE_DROP_CLASSES: frozenset[RiskClass] = frozenset(
    {RiskClass.EXEC_HOST, RiskClass.NETWORK, RiskClass.IRREVERSIBLE}
)


class FileAction(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    MOVE = "move"


class ShellOperation(BaseModel):
    """A command the agent proposes to run on the host shell."""

    model_config = ConfigDict(frozen=True)

    kind: str = "shell"
    command: str
    cwd: Path | None = None


class FileOperation(BaseModel):
    """A filesystem operation proposed through the fs MCP server (not the shell)."""

    model_config = ConfigDict(frozen=True)

    kind: str = "file"
    action: FileAction
    path: Path
    destination: Path | None = None


class NetworkOperation(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: str = "network"
    url: str
    method: str = "GET"


Operation = ShellOperation | FileOperation | NetworkOperation


class PolicyContext(BaseModel):
    """Everything the engine is allowed to consider besides the operation itself.

    ``approved_commands`` is the per-workspace allowlist from PRD §6.3. It can only
    ever downgrade an ``EXEC_HOST`` to automatic; it cannot touch the denylist and it
    cannot rescue an ``IRREVERSIBLE``.

    ``ingested_untrusted_content`` is set by the task runner the moment a task has
    consumed a file, PDF, web page, or email. It never goes back to False within a task.
    """

    model_config = ConfigDict(frozen=True)

    autonomy: AutonomyLevel = AutonomyLevel.L1_CONFIRM_EACH
    workspaces: tuple[Path, ...] = ()
    approved_commands: frozenset[str] = frozenset()
    ingested_untrusted_content: bool = False
    env: dict[str, str] = Field(default_factory=dict)


class Decision(BaseModel):
    """The engine's answer. Every field here is meant to be rendered in the approval
    card — invariant 20: a claim the UI makes must link to its evidence.
    """

    model_config = ConfigDict(frozen=True)

    verdict: Verdict
    risk: RiskClass
    #: Human-readable, ordered, most important first. Shown verbatim in the card.
    reasons: tuple[str, ...] = ()
    #: Identifier of the denylist or classifier rule that decided this, for the audit log.
    matched_rule: str | None = None
    #: Invariant 13. True whenever the operation mutates a file we could restore.
    requires_undo_snapshot: bool = False
    #: For exec_host: the exact string that must be shown to the user, unedited.
    display_command: str | None = None

    @property
    def is_automatic(self) -> bool:
        return self.verdict is Verdict.ALLOW
