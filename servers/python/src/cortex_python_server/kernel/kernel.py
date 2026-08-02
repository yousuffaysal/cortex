"""The in-container kernel. Runs INSIDE the sandbox; stdlib only.

In:   newline-delimited JSON requests on stdin.
Out:  newline-delimited JSON responses on stdout, one per request.
Fail: never exits on user error. A traceback is a normal response, not a crash.

This file is bind-mounted read-only at /cortex/kernel.py. It must import nothing
outside the standard library, because the base image has nothing else, and installing
anything is a `network`-class operation the user has to approve.

Why a long-lived process rather than `docker exec` per step
-----------------------------------------------------------
The requirement is that state carries across steps within a task: step 2 can use the
DataFrame step 1 built. `docker exec` gives you a fresh interpreter every time, so the
only way to carry state would be serialising it to disk between steps — which fails
for anything not picklable (open handles, sockets, models, generators).

So the container runs this loop for the life of the task, and `namespace` — one dict —
is the session. Same model as a Jupyter kernel, minus the parts we do not need.

stdout is the protocol channel, so user `print()` must never reach it directly. Every
execution redirects stdout and stderr into buffers that are returned inside the
response envelope.
"""

from __future__ import annotations

import ast
import contextlib
import io
import json
import os
import sys
import traceback
from typing import Any

ARTIFACTS_DIR = "/artifacts"
PROTOCOL_VERSION = 1


def _snapshot_artifacts() -> dict[str, float]:
    """Map of artifact path -> mtime, used to report what an execution produced."""
    seen: dict[str, float] = {}
    for root, _dirs, files in os.walk(ARTIFACTS_DIR):
        for name in files:
            path = os.path.join(root, name)
            try:
                seen[path] = os.path.getmtime(path)
            except OSError:
                continue
    return seen


def _new_artifacts(before: dict[str, float], after: dict[str, float]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for path, mtime in sorted(after.items()):
        if path not in before or before[path] != mtime:
            try:
                size = os.path.getsize(path)
            except OSError:
                size = -1
            out.append({"path": os.path.relpath(path, ARTIFACTS_DIR), "bytes": size})
    return out


def _compile_last_expression(code: str) -> tuple[Any, Any]:
    """Split source into (exec-able body, eval-able trailing expression | None).

    This is what makes the last line's value show up the way it does in a REPL, without
    making the caller write `print()` around everything.
    """
    tree = ast.parse(code, mode="exec")
    if tree.body and isinstance(tree.body[-1], ast.Expr):
        last = ast.Expression(tree.body[-1].value)
        body = ast.Module(body=tree.body[:-1], type_ignores=[])
        return compile(body, "<cortex>", "exec"), compile(last, "<cortex>", "eval")
    return compile(tree, "<cortex>", "exec"), None


class Kernel:
    def __init__(self) -> None:
        # One namespace for the whole task. This dict *is* the persistent state.
        self.namespace: dict[str, Any] = {
            "__name__": "__cortex__",
            "__doc__": None,
            "ARTIFACTS_DIR": ARTIFACTS_DIR,
        }
        self.execution_count = 0

    def execute(self, code: str) -> dict[str, Any]:
        self.execution_count += 1
        before = _snapshot_artifacts()
        out_buf, err_buf = io.StringIO(), io.StringIO()

        ok = True
        error: dict[str, Any] | None = None
        result_repr: str | None = None

        try:
            body, tail = _compile_last_expression(code)
        except SyntaxError as exc:
            return {
                "ok": False,
                "stdout": "",
                "stderr": "",
                "result_repr": None,
                "error": {
                    "type": "SyntaxError",
                    "message": str(exc),
                    "traceback": "".join(
                        traceback.format_exception_only(type(exc), exc)
                    ),
                },
                "artifacts": [],
                "execution_count": self.execution_count,
            }

        try:
            with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
                exec(body, self.namespace)
                if tail is not None:
                    value = eval(tail, self.namespace)
                    if value is not None:
                        self.namespace["_"] = value
                        result_repr = repr(value)
        except SystemExit as exc:
            # User code calling sys.exit() must not take the kernel down with it.
            ok = False
            error = {
                "type": "SystemExit",
                "message": f"Code called sys.exit({exc.code!r}). The session is still alive.",
                "traceback": "",
            }
        except BaseException as exc:
            ok = False
            tb = traceback.format_exception(type(exc), exc, exc.__traceback__)
            # Drop this file's frames; the user cares about their own code.
            error = {
                "type": type(exc).__name__,
                "message": str(exc),
                "traceback": "".join(tb),
            }

        after = _snapshot_artifacts()
        return {
            "ok": ok,
            "stdout": out_buf.getvalue(),
            "stderr": err_buf.getvalue(),
            "result_repr": result_repr,
            "error": error,
            "artifacts": _new_artifacts(before, after),
            "execution_count": self.execution_count,
        }

    def describe(self) -> dict[str, Any]:
        """What is currently in the session — used to show state carrying across steps."""
        names = sorted(
            k for k in self.namespace
            if not k.startswith("__") and k not in {"ARTIFACTS_DIR"}
        )
        return {
            "ok": True,
            "names": names,
            "execution_count": self.execution_count,
            "python_version": sys.version.split()[0],
        }


def main() -> None:
    kernel = Kernel()
    os.makedirs(ARTIFACTS_DIR, exist_ok=True)

    # Announce readiness so the host does not race the first request.
    print(json.dumps({"type": "ready", "protocol": PROTOCOL_VERSION}), flush=True)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            print(json.dumps({"id": None, "ok": False, "error": {
                "type": "ProtocolError", "message": str(exc), "traceback": ""}}), flush=True)
            continue

        request_id = request.get("id")
        kind = request.get("kind", "execute")

        if kind == "shutdown":
            print(json.dumps({"id": request_id, "ok": True, "type": "shutdown"}), flush=True)
            return
        if kind == "ping":
            response: dict[str, Any] = {"ok": True, "type": "pong"}
        elif kind == "describe":
            response = kernel.describe()
        else:
            response = kernel.execute(request.get("code", ""))

        response["id"] = request_id
        print(json.dumps(response), flush=True)


if __name__ == "__main__":
    main()
