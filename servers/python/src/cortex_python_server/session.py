"""Per-task sandbox session.

In:   a task id, a workspace, and code to run.
Out:  :class:`ExecutionResult` — stdout, stderr, the trailing expression's value,
      artifacts produced, and timing.
Fail: always a :class:`SandboxError`. Timeouts and OOM kills are reported as what they
      are, not as generic failures.

One session == one container == one Python namespace, alive for the task's duration.
Step 2 sees what step 1 defined.

How the timeout is actually enforced
------------------------------------
Not by ``signal.alarm`` inside the kernel. A signal handler only runs when the
interpreter regains control, so it does nothing for the cases that matter most — a
tight C loop in numpy, a blocking syscall, a runaway regex. Those are exactly the ways
real code hangs.

The enforcement is host-side and external: the reader thread waits with a deadline,
and when the deadline passes the *container* is destroyed. That requires no cooperation
from the code inside it, which is the only way a timeout is a guarantee rather than a
request.
"""

from __future__ import annotations

import json
import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .docker_runtime import ContainerHandle, DockerRuntime, SandboxSpec
from .errors import SandboxError, SandboxErrorCode, image_missing

__all__ = ["ExecutionResult", "SandboxSession"]

#: Where kernel.py lives on the host. Bind-mounted read-only into the container.
KERNEL_DIR = Path(__file__).parent / "kernel"


@dataclass
class ExecutionResult:
    ok: bool
    stdout: str = ""
    stderr: str = ""
    result_repr: str | None = None
    error: dict[str, Any] | None = None
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    execution_count: int = 0
    duration_seconds: float = 0.0


class _LineReader:
    """Reads a pipe on a background thread so the main thread can wait with a deadline.

    ``readline()`` on a pipe cannot be interrupted, so a blocking read would make the
    timeout unenforceable. The thread is a daemon: if everything else goes away, it
    does not keep the process alive.
    """

    def __init__(self, stream: Any) -> None:
        self._queue: queue.Queue[str | None] = queue.Queue()
        self._thread = threading.Thread(target=self._pump, args=(stream,), daemon=True)
        self._thread.start()

    def _pump(self, stream: Any) -> None:
        try:
            for line in stream:
                self._queue.put(line)
        except (ValueError, OSError):
            pass
        finally:
            self._queue.put(None)  # EOF sentinel

    def next_line(self, timeout: float) -> str | None:
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError from None


class SandboxSession:
    """A live container plus the kernel protocol running over its pipes."""

    def __init__(
        self,
        task_id: str,
        workspace: Path,
        artifacts_dir: Path,
        runtime: DockerRuntime | None = None,
        **spec_kwargs: Any,
    ) -> None:
        self.task_id = task_id
        self.runtime = runtime or DockerRuntime()
        self.spec = SandboxSpec(
            task_id=task_id,
            workspace=Path(workspace).resolve(),
            artifacts_dir=Path(artifacts_dir).resolve(),
            **spec_kwargs,
        )
        self._handle: ContainerHandle | None = None
        self._reader: _LineReader | None = None
        self._stderr_reader: _LineReader | None = None

    # -- lifecycle --------------------------------------------------------------

    def start(self) -> None:
        self.runtime.preflight()

        if not self.runtime.image_present(self.spec.image):
            # Pulling is a network operation. The caller must have obtained a
            # `network`-class approval and pre-pulled; we do not fetch silently.
            raise image_missing(self.spec.image)

        self.spec.workspace.mkdir(parents=True, exist_ok=True)
        self.spec.artifacts_dir.mkdir(parents=True, exist_ok=True)

        handle = self.runtime.start(self.spec, KERNEL_DIR)
        self._handle = handle
        assert handle.process.stdout is not None
        assert handle.process.stderr is not None
        self._reader = _LineReader(handle.process.stdout)
        self._stderr_reader = _LineReader(handle.process.stderr)

        # Wait for the kernel's readiness banner before accepting work.
        try:
            line = self._reader.next_line(timeout=60)
        except TimeoutError:
            self._fail_start("The sandbox started but its kernel never became ready.")
        if line is None:
            self._fail_start("The sandbox exited before its kernel became ready.")
        assert line is not None
        try:
            banner = json.loads(line)
        except json.JSONDecodeError:
            self._fail_start(f"The kernel sent something unreadable on startup: {line!r}")
        if banner.get("type") != "ready":
            self._fail_start(f"Unexpected kernel banner: {line!r}")

    def _fail_start(self, explanation: str) -> None:
        stderr = self._drain_stderr()
        self.close()
        raise SandboxError(
            code=SandboxErrorCode.CONTAINER_FAILED,
            title="The Python sandbox could not start",
            explanation=explanation,
            remediation=[
                "Check Docker Desktop is running and has memory allocated.",
                "Re-run the task.",
            ],
            detail=stderr or None,
        )

    def _drain_stderr(self) -> str:
        """Collect whatever docker/container stderr is available without blocking."""
        if self._stderr_reader is None:
            return ""
        lines: list[str] = []
        for _ in range(50):
            try:
                line = self._stderr_reader.next_line(timeout=0.05)
            except TimeoutError:
                break
            if line is None:
                break
            lines.append(line)
        return "".join(lines).strip()

    def close(self) -> None:
        if self._handle is not None:
            self.runtime.stop(self._handle)
            self._handle = None

    def __enter__(self) -> SandboxSession:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- execution --------------------------------------------------------------

    def execute(self, code: str, timeout: int | None = None) -> ExecutionResult:
        """Run code in the persistent namespace and return everything it produced."""
        if self._handle is None or self._reader is None:
            raise SandboxError(
                code=SandboxErrorCode.CONTAINER_FAILED,
                title="No sandbox is running",
                explanation="execute() was called before start().",
                remediation=["Call start(), or use the session as a context manager."],
            )

        limit = timeout if timeout is not None else self.spec.timeout_seconds
        request_id = uuid.uuid4().hex
        started = time.monotonic()

        stdin = self._handle.process.stdin
        assert stdin is not None
        try:
            stdin.write(json.dumps({"id": request_id, "kind": "execute", "code": code}) + "\n")
            stdin.flush()
        except (BrokenPipeError, ValueError) as exc:
            raise self._sandbox_died() from exc

        try:
            line = self._reader.next_line(timeout=limit)
        except TimeoutError:
            return self._on_timeout(limit)

        if line is None:
            raise self._sandbox_died()

        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SandboxError(
                code=SandboxErrorCode.KERNEL_PROTOCOL_ERROR,
                title="The sandbox kernel sent an unreadable response",
                explanation="A response line was not valid JSON. The session is not trustworthy.",
                remediation=["Re-run the task; a fresh sandbox will be created."],
                detail=line[:500],
            ) from exc

        return ExecutionResult(
            ok=bool(payload.get("ok")),
            stdout=payload.get("stdout", ""),
            stderr=payload.get("stderr", ""),
            result_repr=payload.get("result_repr"),
            error=payload.get("error"),
            artifacts=payload.get("artifacts", []),
            execution_count=payload.get("execution_count", 0),
            duration_seconds=round(time.monotonic() - started, 3),
        )

    def describe(self, timeout: int = 30) -> dict[str, Any]:
        """What names currently live in the session's namespace."""
        assert self._handle is not None and self._reader is not None
        stdin = self._handle.process.stdin
        assert stdin is not None
        request_id = uuid.uuid4().hex
        stdin.write(json.dumps({"id": request_id, "kind": "describe"}) + "\n")
        stdin.flush()
        line = self._reader.next_line(timeout=timeout)
        if line is None:
            raise self._sandbox_died()
        result: dict[str, Any] = json.loads(line)
        return result

    # -- failure paths ----------------------------------------------------------

    def _on_timeout(self, limit: int) -> ExecutionResult:
        """Destroy the container. No cooperation from the code inside is required."""
        killed = self.runtime.kill_task(self.task_id)
        self._handle = None
        self._reader = None
        raise SandboxError(
            code=SandboxErrorCode.EXECUTION_TIMEOUT,
            title=f"Execution exceeded its {limit}s limit and was stopped",
            explanation=(
                "The sandbox was destroyed rather than asked to stop, so the code had no "
                "opportunity to ignore the request. Any state held in the session is gone; "
                "files already written to the workspace and artifacts directory remain."
            ),
            remediation=[
                "Narrow the work — process a subset, or split it across steps.",
                "If the work legitimately needs longer, raise the timeout for this call.",
            ],
            detail=f"removed containers: {', '.join(killed) if killed else 'none'}",
        )

    def _sandbox_died(self) -> SandboxError:
        stderr = self._drain_stderr()
        exit_code: int | None = None
        oom = False
        if self._handle is not None:
            exit_code, oom = self.runtime.inspect_exit(self._handle)
            if exit_code is None and self._handle.process.poll() is not None:
                exit_code = self._handle.process.returncode

        if oom or exit_code == 137:
            return SandboxError(
                code=SandboxErrorCode.MEMORY_EXCEEDED,
                title=f"The sandbox ran out of memory (limit {self.spec.memory})",
                explanation=(
                    "The container was killed by the kernel's OOM killer for exceeding its "
                    "memory ceiling. The limit did its job: without it, this allocation "
                    "would have come out of your machine's memory."
                ),
                remediation=[
                    "Process the data in chunks rather than loading it all at once.",
                    f"Or raise the memory ceiling for this task above {self.spec.memory}.",
                ],
                detail=f"exit code {exit_code}, OOMKilled={oom}",
            )

        return SandboxError(
            code=SandboxErrorCode.CONTAINER_FAILED,
            title="The sandbox stopped unexpectedly",
            explanation="The container exited while a request was in flight.",
            remediation=["Re-run the task; a fresh sandbox will be created."],
            detail=f"exit code {exit_code}\n{stderr}".strip(),
        )
