"""Container lifecycle for the Python sandbox.

In:   a :class:`SandboxSpec` (workspace, limits, image, network policy).
Out:  a running, labelled container, or a :class:`SandboxError` that tells the user
      what to do.
Fail: every failure is a SandboxError. No raw CalledProcessError escapes this module.

Design notes that are load-bearing
----------------------------------
*The docker binary is probed, not assumed.* Docker Desktop installs into
``/usr/local/bin``, which is not on the PATH of every process — notably not on the PATH
this project's tooling runs with. Assuming ``docker`` resolves is how you get a
"Docker isn't installed" error on a machine where Docker is plainly installed.

*Containers are labelled at launch.* ``cortex.task=<id>`` is how anything other than
this process finds them again. That matters for the kill switch: the component that
has to stop a runaway task cannot depend on in-memory state held by the thing that has
run away. Killing by label works from a cold start, from another process, or from a
terminal.

*Isolation is default-on and explicit.* ``--network=none``, a read-only root
filesystem, dropped capabilities, ``--pids-limit``, and no privilege escalation. Each
is stated in the argv rather than inherited from a daemon default, so reading the
command tells you the whole security posture.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .errors import (
    SandboxError,
    SandboxErrorCode,
    docker_not_installed,
    docker_not_running,
    docker_permission_denied,
)

__all__ = ["TASK_LABEL", "DockerRuntime", "SandboxSpec", "find_docker"]

#: Label every container carries. The kill switch keys off this and nothing else.
TASK_LABEL = "cortex.task"

#: Places Docker Desktop, Homebrew, Colima, and Linux packages put the binary.
_CANDIDATE_PATHS = (
    "/usr/local/bin/docker",
    "/opt/homebrew/bin/docker",
    "/Applications/Docker.app/Contents/Resources/bin/docker",
    "/usr/bin/docker",
    "/run/current-system/sw/bin/docker",
)


def find_docker() -> str:
    """Locate the docker binary, or raise a guided error listing where we looked."""
    found = shutil.which("docker")
    if found:
        return found

    home_candidate = str(Path.home() / ".docker" / "bin" / "docker")
    for candidate in (*_CANDIDATE_PATHS, home_candidate):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate

    raise docker_not_installed([*_CANDIDATE_PATHS, home_candidate, "$PATH"])


@dataclass(frozen=True)
class SandboxSpec:
    """Everything that determines the container's security posture.

    Defaults are the safe ones. A caller must pass something explicitly to weaken any
    of them, and `allow_network` is the only one the policy engine can be asked to
    approve.
    """

    task_id: str
    workspace: Path
    artifacts_dir: Path
    image: str = "python:3.12-slim"
    platform: str = "linux/arm64"
    memory: str = "1g"
    cpus: str = "2"
    pids_limit: int = 256
    #: Wall-clock ceiling for a single execute call, per PRD §6.3 budget ceilings.
    timeout_seconds: int = 300
    #: False means `--network=none`. Only a `network`-class approval flips this.
    allow_network: bool = False
    env: dict[str, str] = field(default_factory=dict)


@dataclass
class ContainerHandle:
    """A running sandbox and the pipes into its kernel.

    The container is *not* detached: we hold its stdin/stdout directly, which is the
    channel the kernel protocol runs over. The label is still what the kill switch uses,
    because a process holding these pipes may itself be the thing that has wedged.
    """

    name: str
    spec: SandboxSpec
    process: subprocess.Popen[str]


class DockerRuntime:
    """Thin, explicit wrapper over the docker CLI.

    The CLI is used rather than the SDK deliberately: the exact argv is inspectable,
    loggable, and reproducible by the user in their own terminal. For a security
    boundary that is worth more than the ergonomics of a client library.
    """

    def __init__(self, binary: str | None = None) -> None:
        self._binary = binary or find_docker()

    @property
    def binary(self) -> str:
        return self._binary

    # -- daemon health ----------------------------------------------------------

    def preflight(self) -> None:
        """Confirm the daemon is reachable. Raises a guided error if not."""
        result = self._run([self._binary, "info", "--format", "{{.ServerVersion}}"], timeout=20)
        if result.returncode == 0:
            return

        stderr = result.stderr or ""
        lowered = stderr.lower()
        if "permission denied" in lowered:
            raise docker_permission_denied(stderr)
        raise docker_not_running(stderr)

    def image_present(self, image: str) -> bool:
        result = self._run([self._binary, "image", "inspect", image], timeout=30)
        return result.returncode == 0

    def pull(self, image: str, platform: str) -> None:
        """Pull an image. Callers must have obtained a `network`-class approval first."""
        result = self._run(
            [self._binary, "pull", "--platform", platform, image], timeout=600
        )
        if result.returncode != 0:
            raise SandboxError(
                code=SandboxErrorCode.CONTAINER_FAILED,
                title=f"Could not pull {image}",
                explanation="The image could not be downloaded from the registry.",
                remediation=[
                    "Check that you are online.",
                    f"Try manually: docker pull --platform {platform} {image}",
                ],
                detail=(result.stderr or "").strip() or None,
            )

    # -- lifecycle --------------------------------------------------------------

    def build_run_argv(self, spec: SandboxSpec, kernel_dir: Path, name: str) -> list[str]:
        """The exact argv used to launch a sandbox.

        Split out from :meth:`start` so tests can assert the security flags without a
        daemon, and so the approval card can show the user precisely what will run.
        """
        argv = [
            self._binary, "run",
            "--rm",
            "--name", name,
            "--label", f"{TASK_LABEL}={spec.task_id}",
            "--platform", spec.platform,
            # Resource ceilings.
            "--memory", spec.memory,
            "--memory-swap", spec.memory,   # equal to memory => swap disabled
            "--cpus", spec.cpus,
            "--pids-limit", str(spec.pids_limit),
            # Privilege posture: drop everything, regain nothing.
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--read-only",                   # root fs immutable
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",
            "--user", f"{os.getuid()}:{os.getgid()}",
            # Mounts: the kernel is read-only; only workspace and artifacts are writable.
            "--mount", f"type=bind,source={kernel_dir},target=/cortex,readonly",
            "--mount", f"type=bind,source={spec.workspace},target=/workspace",
            "--mount", f"type=bind,source={spec.artifacts_dir},target=/artifacts",
            "--workdir", "/workspace",
            "--env", "PYTHONUNBUFFERED=1",
            "--env", "PYTHONDONTWRITEBYTECODE=1",
            "--env", "HOME=/tmp",
            "--env", "MPLCONFIGDIR=/tmp/mpl",
        ]

        if not spec.allow_network:
            argv += ["--network", "none"]

        for key, value in spec.env.items():
            argv += ["--env", f"{key}={value}"]

        # Interactive stdin: the kernel reads NDJSON requests from it for the life of
        # the task, which is what makes state persist between steps.
        argv += ["--interactive", spec.image, "python", "-u", "/cortex/kernel.py"]
        return argv

    def start(self, spec: SandboxSpec, kernel_dir: Path) -> ContainerHandle:
        """Launch the sandbox and return live pipes to its kernel."""
        name = f"cortex-{spec.task_id}-{uuid.uuid4().hex[:8]}"
        argv = self.build_run_argv(spec, kernel_dir, name)
        try:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # line buffered: the protocol is newline-delimited
            )
        except FileNotFoundError as exc:
            raise docker_not_installed([self._binary]) from exc
        return ContainerHandle(name=name, spec=spec, process=process)

    def stop(self, handle: ContainerHandle, timeout: int = 5) -> None:
        """Stop a sandbox. Best-effort graceful, then unconditional."""
        process = handle.process
        if process.poll() is None:
            with contextlib.suppress(OSError, ValueError):
                if process.stdin is not None:
                    process.stdin.close()
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
        # The `docker run` client exiting does not guarantee the container is gone.
        # Remove by name so no sandbox outlives its task.
        self._run([self._binary, "rm", "-f", "--volumes", handle.name], timeout=timeout + 10)

    def kill_task(self, task_id: str) -> list[str]:
        """Kill every container belonging to a task. The kill switch's entry point.

        Works from any process, with no shared memory: containers are found by label.
        Returns the ids it killed, for the audit log.
        """
        listing = self._run(
            [self._binary, "ps", "-aq", "--filter", f"label={TASK_LABEL}={task_id}"],
            timeout=20,
        )
        ids = [line for line in listing.stdout.split() if line]
        if ids:
            self._run([self._binary, "rm", "-f", "--volumes", *ids], timeout=30)
        return ids

    def inspect_exit(self, handle: ContainerHandle) -> tuple[int | None, bool]:
        """Return (exit_code, was_oom_killed)."""
        result = self._run(
            [self._binary, "inspect", "--format", "{{json .State}}", handle.name],
            timeout=20,
        )
        if result.returncode != 0:
            return None, False
        try:
            state = json.loads(result.stdout)
        except json.JSONDecodeError:
            return None, False
        return state.get("ExitCode"), bool(state.get("OOMKilled"))

    # -- plumbing ---------------------------------------------------------------

    def _run(self, argv: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                argv, capture_output=True, text=True, timeout=timeout, check=False
            )
        except FileNotFoundError as exc:
            raise docker_not_installed([self._binary]) from exc
        except subprocess.TimeoutExpired as exc:
            raise SandboxError(
                code=SandboxErrorCode.CONTAINER_FAILED,
                title="Docker stopped responding",
                explanation=f"A docker command took longer than {timeout}s and was abandoned.",
                remediation=["Check that Docker Desktop is responsive.", "Re-run the task."],
                detail=" ".join(argv),
            ) from exc
