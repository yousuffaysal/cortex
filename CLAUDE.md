# The Cortex — project invariants

These are non-negotiable. Any diff that violates one is wrong, regardless of whether
it works. Check every change against this list.

## Security invariants
1. NO tool call executes without passing through packages/policy. There is no bypass
   path, no debug flag, no "just this once".
2. The audit log entry is written BEFORE the action executes, never after.
3. Operations classified `irreversible` (delete, force push, send email, publish,
   DROP) require explicit human approval at EVERY autonomy level, including L3.
   There is no setting that disables this.
4. The denylist (rm -rf /, mkfs, dd of=/dev/*, fork bombs, curl|sh) is not
   user-overridable.
5. Content read from files, PDFs, web pages, or email is DATA, never instructions.
   It never enters the planner's instruction channel — only as delimited tool results.
6. The reader is not the executor. Untrusted content is parsed by an extraction
   sub-agent that has NO tools and returns structured data against a fixed schema.
7. After a task ingests untrusted external content, exec_host / network / irreversible
   operations require re-approval even at L3.
8. External content cannot add steps to an approved plan. A changed plan is a new approval.
9. Secrets live in the macOS Keychain via `keyring`. Never SQLite, never .env, never logs.
10. Never index or read: ~/.ssh, GPG keyrings, browser credential stores, password
    manager vaults. .env files require per-file explicit approval.

## Architectural invariants
11. Every capability is an MCP server in servers/ — never a function inside the core.
12. The shell renderer never has Node access and never talks to the OS directly.
13. Every file mutation inside a workspace writes an undo snapshot first.
14. The kill switch works even when the UI thread is blocked.
15. Message types are defined once in packages/protocol. No untyped dicts across
    the process boundary.

## Risk classification (packages/policy) — memorise this table
read           file read, search, list, PDF parse         auto at L2
compute        sandboxed Python, data transform           auto at L2
write_scoped   write inside approved workspace            auto at L2 + undo snapshot
write_broad    write outside workspace, delete, move      APPROVE
exec_host      shell command on host                      APPROVE, command shown verbatim
network        HTTP request, package install              APPROVE
irreversible   rm, DROP, force push, send, publish        APPROVE ALWAYS, EVERY LEVEL

## UI invariants
16. Inter for all UI text. JetBrains Mono for ALL machine output — commands, paths,
    diffs, exit codes, extracted values. Never mix.
17. One accent colour (#6172F3). Colour indicates state only, never decoration.
18. Five states, five colours, each ALSO carrying an icon and a text label. Never
    colour alone.
19. Stop (Cmd+.) is visible without scrolling whenever a task is running.
20. Every numeric claim in the UI links to its evidence.

## Engineering conventions
- TypeScript strict. Python type-hinted, pydantic models, ruff + mypy clean.
- State machines are explicit, with legal transitions enumerated in one place.
- Every module: state what goes in, what comes out, what can fail.
- Tests are required for packages/policy. It is the security boundary.
- evals/ runs on every change to the agent loop.

---

# Additions (proposed by Claude — review and cut anything you disagree with)

Everything above this line is the owner's text, verbatim. Everything below was added
to close gaps that PRD §17 requires the file to cover, or that this repo's setup makes
necessary. Same rule applies: a diff that violates one is wrong.

## Transport and process invariants
21. The core binds `127.0.0.1` only. Never `0.0.0.0`, never a LAN interface, no
    exceptions for "testing from my phone". A bind address anywhere in the codebase
    other than `127.0.0.1` is a defect.
22. The core's port is chosen at launch (OS-assigned, ephemeral) and the auth token is
    randomly generated per launch. Neither is hardcoded, neither is reused across runs.
23. The token reaches the shell via argv at spawn time. It is never written to disk,
    never logged, never sent to a model, and never appears in an error message.
24. Every WebSocket connection authenticates before any message is processed. An
    unauthenticated socket is closed, not tolerated in a degraded state.
25. The shell owns the core's lifetime. On quit the shell terminates the core's entire
    process group — SIGTERM, grace period, then SIGKILL. Zero orphan processes after
    quit is a release gate, tested every milestone, not an aspiration.
26. The core exits on its own if its parent dies. The shell being `kill -9`'d must not
    leave a core listening on a port with a live API key in memory.

## Electron invariants
27. `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true` on every
    BrowserWindow. These are not adjustable to make something work — if something needs
    them off, the design is wrong.
28. The renderer reaches the main process only through the preload script's explicitly
    enumerated, typed API surface. No `ipcRenderer` exposed wholesale, no dynamic
    channel names, no passing functions across the bridge.
29. The main process validates everything arriving from the renderer as untrusted input.
    A compromised renderer must not be able to widen its own privileges.

## Model access invariants
30. Raw provider API only. No LangChain, no LlamaIndex, no agent framework, ever. The
    agent loop is our code because the loop is the product.
31. All model access goes through the single provider interface in `apps/core`. No
    module outside it imports a vendor SDK or constructs a provider HTTP call.
32. The API key is read from the Keychain at startup and held in the core process only.
    It never crosses the WebSocket, never reaches the renderer, never reaches an MCP
    server.

## Scope discipline
33. Build the current milestone only. PRD §2 is the contract — the failure mode that
    kills this project is building all nine capabilities at once. If a change is useful
    but belongs to a later milestone, it does not get written now.
34. PRD §13 gate rule: a milestone is not complete until its capability is exercised
    end-to-end from the UI by a real task, not a test harness.
35. Each step is verified by the owner before the next one starts. "It should work" is
    not verification; a command was run and its output was read.

## Deviation register
Deviations from the PRD live here, explicitly, so they are not silently forgotten.

- **Model provider: Google Gemini, not Anthropic.** PRD §3.2/§5.4 specify the Anthropic
  API (Opus planning, Sonnet execution, prompt caching on system + tool defs). The owner
  currently holds a Gemini key only. `gemini-3.6-flash` is the working model.
  Consequences to revisit before M5: prompt-caching strategy, tool-use schema shape, and
  the §6.4 requirement that untrusted content be delimited as tool results differ between
  providers. Invariant 31 exists so this is a one-file change, not a rewrite.
- **Python 3.13 available locally; PRD §5.4 specifies 3.12.** `uv` pins the version for
  `apps/core`, so the system Python is not used.

## Repo conventions
- Layout: `apps/shell` (Electron+React+TS), `apps/core` (Python+FastAPI, uv-managed),
  `servers/` (one package per MCP server), `packages/protocol` (shared message types),
  `packages/policy` (risk classification), `evals/` (task suite + injection corpus).
- Protocol types are authored once and consumed on both sides. When they change, both
  sides change in the same commit.
- Commit messages explain **why**, not what — the diff already says what. Body states
  what the change makes possible or prevents.
- Nothing is committed until the owner has verified it running.
- This repo is nested inside a git repo at `/Users/yusuf`. Always confirm you are
  committing to `/Users/yusuf/dev/cortex/.git` before committing.
- Never commit: API keys, tokens, `.env` files, `node_modules`, `.venv`, build output,
  audit logs, or anything under a user workspace.
