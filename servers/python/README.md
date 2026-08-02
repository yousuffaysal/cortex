# servers/python

MCP server: sandboxed Python execution in an ephemeral, network-isolated container.

Invariant 11 — this is a capability, so it is an MCP server, not a function inside the
core. It runs standalone and is testable from Claude Desktop before any Cortex UI exists.

## Contract

**In:** MCP tool calls over stdio.
**Out:** text. Machine output (stdout, tracebacks, artifact listings) is wrapped in
delimiters so the UI can render it in JetBrains Mono (invariant 16) and so it is never
mistaken for instructions (invariant 5).
**Can fail:** every failure is a guided message with numbered remediation steps. No
stack trace reaches the model or the user.

| Tool | Risk class | Notes |
|---|---|---|
| `python_execute` | `compute` | Sandboxed. State persists per `task_id`. |
| `python_session_state` | `read` | Names defined in the session. |
| `python_install_packages` | `network` | Requires approval **and** workspace network toggle. |
| `python_run_on_host` | `exec_host` | Off unless enabled per workspace. Currently gated shut. |
| `python_end_session` | — | Destroys the container and its memory. |

## The sandbox posture

Every flag is stated explicitly in the argv rather than inherited from a daemon default,
so reading `build_run_argv` tells you the entire security posture:

```
--network none          # unless the workspace explicitly enables network
--memory 1g --memory-swap 1g   # equal values disable swap
--cpus 2 --pids-limit 256
--cap-drop ALL --security-opt no-new-privileges
--read-only             # root filesystem immutable
--tmpfs /tmp:rw,noexec,nosuid,size=256m
--user <host uid:gid>
--mount .../kernel -> /cortex (readonly)
--mount <workspace>  -> /workspace (rw)
--mount <artifacts>  -> /artifacts (rw)
--label cortex.task=<task_id>
--platform linux/arm64
```

Tests assert both halves: that the flags are present (no daemon needed) *and* that they
actually work (live, against a real daemon). A flag that is present but ineffective is
worse than a missing one, because it reads as covered.

## Three decisions worth knowing

**The persistent kernel is a long-lived process, not `docker exec` per step.** The
requirement is that step 2 can use the DataFrame step 1 built. `docker exec` gives a
fresh interpreter each time, so carrying state would mean serialising between steps —
which fails for anything unpicklable. Instead the container runs `kernel.py` for the
life of the task and one `namespace` dict *is* the session.

**The timeout is enforced by destroying the container, not by `signal.alarm`.** A signal
handler only runs when the interpreter regains control, so it does nothing for a tight
C loop in numpy, a blocking syscall, or a runaway regex — exactly how real code hangs.
The host waits with a deadline and kills the container, requiring no cooperation from
the code inside. That is what makes it a guarantee rather than a request.

**Workspace toggles live outside the workspace.** The obvious home for per-workspace
settings is `.cortex/config.json` next to the code. That is a privilege escalation: the
workspace is bind-mounted writable into the sandbox, so an agent that wanted host
execution could enable it for itself. Settings live in the user's application-support
directory instead, keyed by absolute path, never mounted into any container.

Related: there is no `approved=true` argument on any tool. A tool argument is
model-controllable, so an approval flag in the schema is a bypass with a polite name.
A test asserts no tool exposes one.

## The kill switch hook

Containers are labelled `cortex.task=<task_id>` at launch, and `DockerRuntime.kill_task`
finds them by that label alone. This matters because the component that has to stop a
runaway task cannot depend on in-memory state held by the thing that has run away.
Killing by label works from another process, from a cold start, or from your terminal:

```
docker ps -aq --filter label=cortex.task=<id> | xargs docker rm -f
```

The Cmd+. accelerator itself is a shell concern and does not exist yet.

## Running it

```
uv run pytest              # 32 tests; live Docker tests skip automatically without a daemon
uv run ruff check .
uv run mypy
uv run cortex-python-server   # stdio MCP server
```

Requires a container runtime: OrbStack, Docker Desktop, or Colima. Apple Silicon runs
`linux/arm64` natively — no emulation.

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cortex-python": {
      "command": "uv",
      "args": ["run", "--directory", "/Users/yusuf/dev/cortex/servers/python",
               "cortex-python-server"],
      "env": { "PATH": "/usr/local/bin:/usr/bin:/bin" }
    }
  }
}
```

The `PATH` entry is not optional. Docker Desktop installs its binary into
`/usr/local/bin`, which is not on the PATH every process inherits — GUI-launched apps in
particular. The server probes a list of known locations before giving up, but setting
PATH here avoids the guessing.

## Known gaps

- **Host mode is gated shut** even when a workspace enables it, because the persistent
  UI indicator that must accompany unsandboxed execution does not exist yet. Running
  without a visible always-on indicator is the exact failure the feature exists to
  prevent.
- **Approvals cannot be requested**, only refused. There is no approval card and no
  out-of-band token channel until the core exists, so `network`-class operations are
  declined rather than escalated.
- **Undo snapshots are not here.** Invariant 13 makes them a property of every workspace
  mutation, so they belong with `servers/fs`, not with the Python sandbox.
