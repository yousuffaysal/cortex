"""Guided failures for the container runtime.

In:   a probe result or a docker CLI failure.
Out:  a :class:`SandboxError` carrying a title, a plain explanation, and concrete
      numbered steps.
Fail: this module is the failure path; it has none of its own.

Why this module exists at all
-----------------------------
"Docker isn't running" is the single most common way this server fails, and it is a
condition the user can fix in about ten seconds *if they are told what to do*. A
stack trace ending in ``FileNotFoundError: [Errno 2] 'docker'`` is technically the
same information and useless.

Every error here answers three questions in order: what happened, why it stopped the
task, and what to do next. Nothing is a bare exception type.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

__all__ = [
    "SandboxError",
    "SandboxErrorCode",
    "docker_not_installed",
    "docker_not_running",
    "docker_permission_denied",
    "host_mode_not_enabled",
    "image_missing",
]


class SandboxErrorCode(StrEnum):
    DOCKER_NOT_INSTALLED = "docker_not_installed"
    DOCKER_NOT_RUNNING = "docker_not_running"
    DOCKER_PERMISSION_DENIED = "docker_permission_denied"
    IMAGE_MISSING = "image_missing"
    HOST_MODE_NOT_ENABLED = "host_mode_not_enabled"
    CONTAINER_FAILED = "container_failed"
    EXECUTION_TIMEOUT = "execution_timeout"
    MEMORY_EXCEEDED = "memory_exceeded"
    KERNEL_PROTOCOL_ERROR = "kernel_protocol_error"


@dataclass
class SandboxError(Exception):
    """An error the user can act on.

    ``remediation`` is a list of steps, not a paragraph. The UI renders them as a
    numbered list; the MCP text fallback joins them the same way.
    """

    code: SandboxErrorCode
    title: str
    explanation: str
    remediation: list[str] = field(default_factory=list)
    #: Anything machine-generated (a docker stderr line, an exit code). Rendered in
    #: JetBrains Mono per UI invariant 16, so it must be kept separate from prose.
    detail: str | None = None

    def __str__(self) -> str:
        parts = [self.title, "", self.explanation]
        if self.remediation:
            parts.append("")
            parts.extend(f"{i}. {step}" for i, step in enumerate(self.remediation, 1))
        if self.detail:
            parts.extend(["", "Details:", self.detail])
        return "\n".join(parts)


def docker_not_installed(searched: list[str]) -> SandboxError:
    return SandboxError(
        code=SandboxErrorCode.DOCKER_NOT_INSTALLED,
        title="Docker isn't installed",
        explanation=(
            "Cortex runs Python inside a container so that code it did not write cannot "
            "touch your machine. Without a container runtime there is no safe place to "
            "run it, and Cortex will not fall back to running it on the host."
        ),
        remediation=[
            "Install a container runtime. On Apple Silicon any of these work: "
            "OrbStack (lightest), Docker Desktop, or Colima (`brew install colima docker`).",
            "Start it and wait for the engine to report running.",
            "Re-run this task. Cortex re-checks on every run; no restart needed.",
        ],
        detail="Looked for the docker binary in:\n" + "\n".join(f"  {p}" for p in searched),
    )


def docker_not_running(stderr: str) -> SandboxError:
    return SandboxError(
        code=SandboxErrorCode.DOCKER_NOT_RUNNING,
        title="Docker is installed but the engine isn't running",
        explanation=(
            "The docker command exists, but nothing is listening on the Docker socket, "
            "so containers cannot be started."
        ),
        remediation=[
            "Open Docker Desktop (or run `colima start` if you use Colima).",
            "Wait until the status indicator reads 'Engine running'.",
            "Re-run this task.",
        ],
        detail=stderr.strip() or None,
    )


def docker_permission_denied(stderr: str) -> SandboxError:
    return SandboxError(
        code=SandboxErrorCode.DOCKER_PERMISSION_DENIED,
        title="Cortex isn't allowed to talk to the Docker socket",
        explanation=(
            "The Docker engine is running, but this process was refused access to its "
            "socket. This is a permissions problem, not a Cortex bug."
        ),
        remediation=[
            "Confirm Docker Desktop is running as your user, not as another account.",
            "If you use Colima or a rootless setup, check that DOCKER_HOST points at a "
            "socket you can read.",
            "Re-run this task.",
        ],
        detail=stderr.strip() or None,
    )


def image_missing(image: str) -> SandboxError:
    return SandboxError(
        code=SandboxErrorCode.IMAGE_MISSING,
        title=f"The sandbox image {image} isn't present locally",
        explanation=(
            "Pulling it downloads data from a registry, which is a network operation. "
            "Network operations require your approval — Cortex will not fetch anything "
            "on its own."
        ),
        remediation=[
            f"Approve the pull when prompted, or pre-pull it yourself: "
            f"docker pull --platform linux/arm64 {image}",
            "Re-run this task.",
        ],
    )


def host_mode_not_enabled(workspace: str) -> SandboxError:
    return SandboxError(
        code=SandboxErrorCode.HOST_MODE_NOT_ENABLED,
        title="Host execution is not enabled for this workspace",
        explanation=(
            "This code was asked to run directly on your machine instead of inside the "
            "container. That is off by default and must be turned on per workspace, "
            "deliberately, because it removes every isolation guarantee the sandbox provides."
        ),
        remediation=[
            f"Enable host mode for {workspace} in Settings → Workspaces, if you actually "
            "intend to run this code unsandboxed.",
            "Otherwise, re-run without requesting host mode.",
        ],
    )
