# packages/policy

The security boundary. Every tool call in Cortex passes through this package before it
executes (CLAUDE.md invariant 1). Nothing here talks to the network, the filesystem, or
a model — it is a pure function from *a proposed operation* to *a risk classification
and a decision*.

See `docs/learn/01-policy-engine.md` for the plain-English explanation.

## Contract

```python
from cortex_policy import ShellOperation, PolicyContext, AutonomyLevel, decide

decide(ShellOperation(command="rm -rf /"), PolicyContext(autonomy=AutonomyLevel.L3_AUTONOMOUS))
# Decision(verdict=DENY, risk=irreversible, matched_rule="rm_recursive_system_root", …)
```

**In:** one `Operation` (`ShellOperation` | `FileOperation` | `NetworkOperation`) and one
`PolicyContext` (autonomy level, approved workspaces, per-workspace command allowlist,
and whether this task has already ingested untrusted content).

**Out:** one `Decision` — a `Verdict` (`ALLOW` / `APPROVE` / `DENY`), the `RiskClass`,
ordered human-readable `reasons`, the `matched_rule` for the audit log, whether an undo
snapshot is required, and the verbatim command to display.

**Can fail:** it cannot. `decide()` has no failure mode that returns "unknown" or raises
on hostile input — every path ends in a `Decision`, and the default when reasoning runs
out is `APPROVE` (ask a human), never `ALLOW`.

## Modules

| Module | Job |
|---|---|
| `risk.py` | The risk table, autonomy tiers, and the operation/decision models. No logic. |
| `shellparse.py` | Conservative shell tokenizer. Records what it *cannot* resolve. |
| `resolve.py` | Parsed syntax → program name, normalised flags, operands. Peels wrappers. |
| `paths.py` | Workspace containment and the never-readable credential paths. |
| `denylist.py` | The non-overridable rules. Takes no context, by design. |
| `engine.py` | `decide()`. The only public entry point. |

## Three design decisions worth knowing

**1. Every host shell command starts at `exec_host`.** The risk table says `exec_host` is
"shell command on host", so `ls` run through the shell server is `exec_host`, not `read`.
A `read` classification is what you get from the *filesystem* server, which is a different
operation type. The per-workspace allowlist is what stops this from being unbearable —
it can downgrade a clean `exec_host` to automatic, and nothing else.

**2. Uncertainty escalates to `irreversible`.** When the parser hits `$(…)`, an unset
variable, a glob, or a runtime-chosen program name, the command is classified
`irreversible` and never runs automatically at any level. The engine does not guess the
benign reading. It also does not `DENY` — a human can still read `rm -rf $TARGET` and
decide — but the decision stops being the machine's.

**3. `DENY` is reserved for the fixed denylist.** `DENY` means no approval exists.
`denylist.check()` deliberately does not accept a `PolicyContext`, so no caller can pass
a value that changes its answer. That is invariant 4 expressed in a type signature rather
than a comment.

**Why shell `rm` is `irreversible` but fs-server delete is `write_broad`:** invariant 13
requires an undo snapshot before any workspace file mutation, and the fs server writes
one. Shell `rm` bypasses that machinery entirely, so it is unrecoverable. Same verb,
different recoverability, different class.

## Tests

`packages/policy` is the security boundary, so tests are required (CLAUDE.md).

```
uv run pytest          # 335 tests
uv run ruff check .
uv run mypy
```

- `test_fuzz_destructive.py` — generated permutations, not a hand-list: every spelling of
  `rm`'s flags, every spelling of `/`, every separator that can hide a second command,
  and every wrapper that can hide a program name. Each case asserts `DENY` at *all four*
  autonomy levels with the allowlist stacked in its favour.
- `test_invariants.py` — CLAUDE.md's numbered invariants as executable assertions.
- `test_shellparse.py` — parser units, including "malformed input never raises".
- `test_paths.py` — containment, with a real symlink escape created on disk.

Negative controls matter as much as the positive ones: a classifier that denies
everything passes every destructive test and is useless, so the suite also asserts that
`rm -rf ./build` is *approvable* and that `ls -la` is not refused.

### Bugs the fuzz suite found during development

Recorded because they are the argument for generating cases rather than listing them:

1. `if true; then rm -rf /; fi` — `then` was parsed as the program name, so the `rm`
   became a mere argument and the denylist never saw it. Shell reserved words are now
   skipped.
2. `echo x > /dev/disk0` — only `>>` was registered as an operator, never single `>`, so
   the redirect target was swallowed into a word and the block-device check never ran.
3. `nice -n 10 rm -rf /` — the wrapper peeler skipped `-n` but not its value, so the
   program name resolved to `10`. `rm` was invisible. Flags that take a separate value
   are now table-driven per wrapper.

All three were bypasses of the denylist, and none were in the hand-written list.
