"""Every operation this server performs, classified by packages/policy first.

In:   a proposed sandbox operation.
Out:  a ``Decision`` from the policy engine.
Fail: a classification that cannot be produced is not a reason to proceed.

CLAUDE.md invariant 1: no tool call executes without passing through packages/policy.
This module is how that holds for the Python server — there is no code path in
``server.py`` that reaches the runtime without coming through here first.

The awkward truth about approvals right now
-------------------------------------------
The approval card lives in the UI, and the UI does not exist yet. So this server cannot
*ask*. It can only classify and refuse.

The refusal is deliberately not "pass approved=True to continue". A tool argument is
model-controllable, so an approval flag in the tool schema is not an approval — it is a
bypass with a polite name, and the model can set it. Anything requiring approval is
therefore refused outright until the core can render a real approval card and carry an
out-of-band token. The one thing a user *can* pre-authorise today is a per-workspace
toggle in :mod:`.settings`, which lives outside the workspace where nothing in the
sandbox can reach it.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cortex_policy import (
    AutonomyLevel,
    NetworkOperation,
    PolicyContext,
    RiskClass,
    ShellOperation,
    Verdict,
    decide,
)

from .settings import WorkspaceSettings

__all__ = ["PolicyRefusal", "check_host_execution", "check_install"]


@dataclass
class PolicyRefusal(Exception):
    """A refusal carrying the engine's own reasoning, so the user sees why."""

    title: str
    risk: RiskClass
    reasons: tuple[str, ...]
    remediation: list[str]

    def __str__(self) -> str:
        parts = [self.title, ""]
        parts.extend(f"• {reason}" for reason in self.reasons)
        if self.remediation:
            parts.append("")
            parts.extend(f"{i}. {step}" for i, step in enumerate(self.remediation, 1))
        return "\n".join(parts)


def _context(workspace: Path, settings: WorkspaceSettings) -> PolicyContext:
    return PolicyContext(
        # The server never assumes autonomy it was not given. L1 is the install default
        # per PRD §6.1, and this server has no channel to learn the user's real setting
        # until the core exists.
        autonomy=AutonomyLevel.L1_CONFIRM_EACH,
        workspaces=(Path(workspace).resolve(),),
    )


def check_install(packages: list[str], workspace: Path, settings: WorkspaceSettings) -> None:
    """Package installation is `network` class and requires approval. PRD §6.2.

    Two independent things must both be true for an install to proceed: the policy
    engine must not require approval, and the workspace must have network enabled.
    Neither alone is sufficient, and the sandbox additionally runs with
    ``--network=none`` unless the second is set, so a mistake here fails at the
    container boundary too.
    """
    command = "pip install " + " ".join(packages)
    decision = decide(
        ShellOperation(command=command), _context(workspace, settings)
    )

    if not settings.network_enabled:
        raise PolicyRefusal(
            title="Installing packages needs network access, which is off for this workspace",
            risk=RiskClass.NETWORK,
            reasons=(
                f"`{command}` is classified {decision.risk.value}.",
                "The sandbox runs with --network=none, so the install would fail at the "
                "container boundary even if policy allowed it.",
                *decision.reasons[:2],
            ),
            remediation=[
                "Enable network for this workspace in Settings → Workspaces, if you want "
                "this task to be able to download packages.",
                "Or pre-build an image containing the packages and point the task at it.",
            ],
        )

    if decision.verdict is not Verdict.ALLOW:
        raise PolicyRefusal(
            title="Package installation requires approval",
            risk=decision.risk,
            reasons=decision.reasons,
            remediation=[
                "Approve the install when the approval card is available.",
                "Until then, pre-pull an image containing the packages you need.",
            ],
        )


def check_network_egress(url: str, workspace: Path, settings: WorkspaceSettings) -> None:
    """Any outbound request from a task is `network` class."""
    decision = decide(NetworkOperation(url=url), _context(workspace, settings))
    if decision.verdict is not Verdict.ALLOW or not settings.network_enabled:
        raise PolicyRefusal(
            title="Outbound network access requires approval",
            risk=decision.risk,
            reasons=decision.reasons,
            remediation=["Enable network for this workspace, or run without it."],
        )


def check_host_execution(workspace: Path, settings: WorkspaceSettings) -> None:
    """Host-mode execution: off by default, per-workspace toggle, never a tool argument.

    Note what this does *not* do: there is no argument a caller can pass to satisfy it.
    The only thing that enables host mode is state in the user's config directory, which
    the sandbox cannot see and the model cannot write.
    """
    if not settings.host_execution_enabled:
        raise PolicyRefusal(
            title="Host execution is not enabled for this workspace",
            risk=RiskClass.EXEC_HOST,
            reasons=(
                "Running on the host removes every isolation guarantee the sandbox "
                "provides: no memory ceiling, no network isolation, no filesystem "
                "confinement, no undo.",
                "This is off by default and can only be enabled per workspace, by you, "
                "from the host UI.",
            ),
            remediation=[
                f"Enable host execution for {workspace} in Settings → Workspaces if you "
                "genuinely intend this.",
                "Otherwise run the code in the sandbox, which is the default.",
            ],
        )
