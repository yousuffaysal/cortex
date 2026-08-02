"""The decision engine.

In:   an :data:`~cortex_policy.risk.Operation` and a
      :class:`~cortex_policy.risk.PolicyContext`.
Out:  one :class:`~cortex_policy.risk.Decision`.
Fail: never raises. Every path through this module ends in a Decision, and the default
      when reasoning runs out is approval-required, never automatic execution.

Order of operations, which is itself a security property:

1. The denylist runs first and cannot be reached past. (invariant 4)
2. Uncertainty escalates. Anything the parser could not resolve is treated as the worst
   thing it could be. (the "I can't tell what this does" rule)
3. The risk class is the *most severe* contribution of any command in the line, so
   ``ls && rm -rf ~/work`` is classified by the ``rm``, not by the ``ls``.
4. Only then does autonomy level apply, and it can never rescue an ``irreversible``.

Every shell command starts at ``exec_host``, because that is what the risk table says a
shell command on the host is. Reads only become the ``read`` class when they arrive
through the filesystem MCP server, which is a different operation type entirely. The
per-workspace allowlist is what stops this from being unbearable in practice.
"""

from __future__ import annotations

from pathlib import Path

from . import denylist
from .paths import PathSensitivity, contains, sensitivity
from .resolve import ResolvedCommand, resolve_script
from .risk import (
    AUTO_AT_LEVEL,
    PRIVILEGE_DROP_CLASSES,
    Decision,
    FileAction,
    FileOperation,
    NetworkOperation,
    Operation,
    PolicyContext,
    RiskClass,
    ShellOperation,
    Verdict,
    most_severe,
)
from .shellparse import ParseProblem, parse

__all__ = ["decide"]


# --- program tables ----------------------------------------------------------------
# These say what a program *does*, not whether it is allowed. Allowed-ness is decided
# below, from the class plus the context.

_IRREVERSIBLE_PROGRAMS: frozenset[str] = frozenset(
    {"rm", "shred", "srm", "rmdir", "unlink", "dd", "truncate"}
)

_NETWORK_PROGRAMS: frozenset[str] = frozenset(
    {
        "curl",
        "wget",
        "fetch",
        "aria2c",
        "httpie",
        "http",
        "ssh",
        "scp",
        "sftp",
        "rsync",
        "nc",
        "netcat",
        "telnet",
        "ping",
        "dig",
        "nslookup",
        "host",
        "pip",
        "pip3",
        "npm",
        "npx",
        "yarn",
        "pnpm",
        "brew",
        "apt",
        "apt-get",
        "uv",
        "uvx",
        "cargo",
        "gem",
        "go",
        "poetry",
        "conda",
        "docker",
    }
)

_WRITE_PROGRAMS: frozenset[str] = frozenset(
    {"touch", "mkdir", "cp", "tee", "ln", "install", "mv", "chmod", "chown", "chgrp"}
)

_READ_PROGRAMS: frozenset[str] = frozenset(
    {
        "ls",
        "cat",
        "head",
        "tail",
        "less",
        "more",
        "grep",
        "egrep",
        "fgrep",
        "rg",
        "ag",
        "find",
        "fd",
        "wc",
        "file",
        "stat",
        "pwd",
        "tree",
        "du",
        "df",
        "diff",
        "cmp",
        "basename",
        "dirname",
        "realpath",
        "readlink",
        "which",
        "type",
        "printenv",
        "date",
        "whoami",
        "id",
        "uname",
        "ps",
    }
)

_COMPUTE_PROGRAMS: frozenset[str] = frozenset(
    {
        "echo",
        "printf",
        "jq",
        "awk",
        "sort",
        "uniq",
        "cut",
        "tr",
        "seq",
        "expr",
        "bc",
        "base64",
        "md5",
        "md5sum",
        "shasum",
        "sha256sum",
        "true",
        "false",
        "test",
    }
)

#: Programs whose operands are filesystem paths, so workspace scoping applies to them.
_PATH_OPERAND_PROGRAMS: frozenset[str] = (
    _IRREVERSIBLE_PROGRAMS | _WRITE_PROGRAMS | {"cat", "head", "tail", "less", "more", "sed"}
)

#: Subcommand-level escalations: (program, subcommand) that are irreversible.
_IRREVERSIBLE_SUBCOMMANDS: frozenset[tuple[str, str]] = frozenset(
    {
        ("npm", "publish"),
        ("cargo", "publish"),
        ("gem", "push"),
        ("twine", "upload"),
        ("gh", "release"),
        ("docker", "push"),
    }
)


def _git_class(command: ResolvedCommand) -> tuple[RiskClass, str] | None:
    """git is several risk classes wearing one name."""
    sub = command.operands[0] if command.operands else ""
    if sub == "push" and command.has_flag("-f", "--force", "--force-with-lease"):
        return RiskClass.IRREVERSIBLE, "git push --force rewrites published history."
    if sub == "push":
        return RiskClass.NETWORK, "git push contacts a remote."
    if sub in {"reset"} and command.has_flag("--hard"):
        return RiskClass.IRREVERSIBLE, "git reset --hard discards uncommitted work with no undo."
    if sub == "clean" and command.has_flag("-f", "--force"):
        return RiskClass.IRREVERSIBLE, "git clean -f deletes untracked files permanently."
    if sub in {"clone", "fetch", "pull", "remote", "submodule"}:
        return RiskClass.NETWORK, f"git {sub} contacts a remote."
    if sub in {"status", "log", "diff", "show", "branch", "blame"}:
        return RiskClass.READ, f"git {sub} only reads the repository."
    return None


def _program_class(command: ResolvedCommand) -> tuple[RiskClass, str]:
    program = command.program

    if program == "git":
        git = _git_class(command)
        if git is not None:
            return git
        return RiskClass.EXEC_HOST, "git subcommand with no specific classification."

    sub = command.operands[0] if command.operands else ""
    if (program, sub) in _IRREVERSIBLE_SUBCOMMANDS:
        return RiskClass.IRREVERSIBLE, f"{program} {sub} publishes irreversibly."

    if program in _IRREVERSIBLE_PROGRAMS:
        return RiskClass.IRREVERSIBLE, f"{program} destroys data with no undo snapshot."
    if program == "sed" and command.has_flag("-i", "--in-place"):
        return RiskClass.WRITE_BROAD, "sed -i rewrites files in place."
    if program in _WRITE_PROGRAMS:
        return RiskClass.WRITE_SCOPED, f"{program} modifies the filesystem."
    if program in _NETWORK_PROGRAMS:
        return RiskClass.NETWORK, f"{program} makes a network request."
    if program in _READ_PROGRAMS:
        return RiskClass.READ, f"{program} only reads."
    if program in _COMPUTE_PROGRAMS:
        return RiskClass.COMPUTE, f"{program} transforms data without touching the host."

    return RiskClass.EXEC_HOST, f"{program!r} is not in any classification table."


_PROBLEM_EXPLANATIONS: dict[ParseProblem, str] = {
    ParseProblem.COMMAND_SUBSTITUTION: (
        "Contains $(…) or backticks: the actual arguments are produced by running "
        "another command, so what this does cannot be known before it runs."
    ),
    ParseProblem.PROCESS_SUBSTITUTION: (
        "Contains <(…): an argument is the output of another command."
    ),
    ParseProblem.UNRESOLVED_VARIABLE: (
        "Uses a variable whose value is not set anywhere in this command, so the "
        "target cannot be determined."
    ),
    ParseProblem.DYNAMIC_COMMAND_NAME: (
        "The program being run is chosen at runtime (a variable, or via xargs/eval), "
        "so it cannot be classified."
    ),
    ParseProblem.GLOB_IN_ARGUMENT: (
        "Contains a glob, which expands to an unknown set of paths at run time."
    ),
    ParseProblem.UNBALANCED_QUOTE: "Has an unbalanced quote and does not parse cleanly.",
}


def _classify_shell(
    operation: ShellOperation, context: PolicyContext
) -> tuple[RiskClass, list[str], str | None, bool]:
    """Return (risk, reasons, matched_deny_rule, denied)."""
    script = parse(operation.command)
    commands = resolve_script(script, context.env)

    match = denylist.check(operation.command, commands)
    if match is not None:
        return RiskClass.IRREVERSIBLE, [match.reason], match.rule, True

    if not commands:
        return (
            RiskClass.EXEC_HOST,
            ["No executable command could be identified in this input."],
            None,
            False,
        )

    contributions: list[RiskClass] = []
    reasons: list[str] = []
    escalations: list[str] = []
    problems: set[ParseProblem] = set()

    for command in commands:
        risk, reason = _program_class(command)
        problems |= command.problems

        if command.privileged:
            risk = most_severe([risk, RiskClass.WRITE_BROAD])
            escalations.append(
                f"Runs under sudo, so {command.program!r} acts with administrator privileges."
            )

        # Workspace scoping: a write is only `write_scoped` if we can show it lands
        # inside an approved workspace. Anything we cannot place is broad.
        if command.program in _PATH_OPERAND_PROGRAMS and risk in {
            RiskClass.WRITE_SCOPED,
            RiskClass.READ,
        }:
            for operand in command.operands:
                if operand.startswith("-"):
                    continue
                where = contains(context.workspaces, _resolve_operand(operand, operation.cwd))
                if where.symlink_escape:
                    risk = most_severe([risk, RiskClass.WRITE_BROAD])
                    escalations.append(
                        f"{operand!r} looks like it is inside the workspace but "
                        "resolves outside it through a symlink."
                    )
                elif not where.inside:
                    risk = most_severe([risk, RiskClass.WRITE_BROAD])
                    escalations.append(f"{operand!r} is outside every approved workspace.")

        # Every host shell command is at least exec_host — PRD §6.2.
        contributions.append(most_severe([risk, RiskClass.EXEC_HOST]))
        reasons.append(f"`{command.raw or command.program}` — {reason}")

    risk = most_severe(contributions)

    if problems:
        risk = RiskClass.IRREVERSIBLE
        for problem in sorted(problems, key=lambda p: p.value):
            escalations.insert(0, _PROBLEM_EXPLANATIONS[problem])
        escalations.insert(
            0,
            "Cannot determine what this command does, so it is treated as irreversible "
            "and requires approval at every autonomy level.",
        )

    if len(commands) > 1:
        reasons.append(
            f"{len(commands)} commands in one line; classified by the most severe of them."
        )

    return risk, [*escalations, *reasons], None, False


def _resolve_operand(operand: str, cwd: Path | None) -> Path:
    path = Path(operand)
    if not path.is_absolute() and cwd is not None:
        return cwd / path
    return path


def _classify_file(
    operation: FileOperation, context: PolicyContext
) -> tuple[RiskClass, list[str], str | None, bool]:
    reasons: list[str] = []

    targets = [operation.path] + ([operation.destination] if operation.destination else [])

    for target in targets:
        level = sensitivity(target)
        if level is PathSensitivity.PROTECTED:
            return (
                RiskClass.IRREVERSIBLE,
                [
                    f"{str(target)!r} is a credential store. It is never readable or "
                    "writable, at any autonomy level, and no approval is offered."
                ],
                "protected_path",
                True,
            )
        if level is PathSensitivity.PER_FILE_APPROVAL:
            reasons.append(
                f"{str(target)!r} is an environment file: it requires explicit per-file "
                "approval every time, and is never automatic."
            )

    risk = RiskClass.READ
    if operation.action is FileAction.READ:
        risk = RiskClass.READ
    elif operation.action is FileAction.WRITE:
        risk = RiskClass.WRITE_SCOPED
    else:
        # Delete and move through the fs server are recoverable, because invariant 13
        # requires an undo snapshot first. That is the whole difference between this
        # and shell `rm`, which is irreversible.
        risk = RiskClass.WRITE_BROAD
        reasons.append(
            f"{operation.action.value} is recoverable only because an undo snapshot is "
            "written first."
        )

    for target in targets:
        where = contains(context.workspaces, target)
        if where.symlink_escape:
            risk = most_severe([risk, RiskClass.WRITE_BROAD])
            reasons.insert(
                0,
                f"{str(target)!r} resolves outside the workspace through a symlink.",
            )
        elif not where.inside:
            # PRD §6.3: "Access outside them is a write_broad operation regardless of
            # intent." That covers reads too, deliberately.
            risk = most_severe([risk, RiskClass.WRITE_BROAD])
            reasons.insert(0, f"{str(target)!r} is outside every approved workspace.")
        else:
            reasons.append(
                f"{str(target)!r} is inside approved workspace {where.matched_workspace}."
            )

    if any(sensitivity(t) is PathSensitivity.PER_FILE_APPROVAL for t in targets):
        risk = most_severe([risk, RiskClass.WRITE_BROAD])

    return risk, reasons, None, False


def decide(operation: Operation, context: PolicyContext | None = None) -> Decision:
    """Classify ``operation`` and decide whether it may run.

    This is the only entry point. CLAUDE.md invariant 1: no tool call executes without
    passing through here, and there is no parameter that skips the denylist.
    """
    context = context or PolicyContext()

    if isinstance(operation, ShellOperation):
        risk, reasons, rule, denied = _classify_shell(operation, context)
        display: str | None = operation.command
    elif isinstance(operation, FileOperation):
        risk, reasons, rule, denied = _classify_file(operation, context)
        display = None
    elif isinstance(operation, NetworkOperation):
        risk, reasons, rule, denied = (
            RiskClass.NETWORK,
            [f"{operation.method} {operation.url}"],
            None,
            False,
        )
        display = f"{operation.method} {operation.url}"
    else:  # pragma: no cover - the union is closed; this is a tripwire, not a branch.
        raise TypeError(f"unclassifiable operation type: {type(operation)!r}")

    if denied:
        return Decision(
            verdict=Verdict.DENY,
            risk=risk,
            reasons=tuple(reasons),
            matched_rule=rule,
            requires_undo_snapshot=False,
            display_command=display,
        )

    snapshot = risk in {RiskClass.WRITE_SCOPED, RiskClass.WRITE_BROAD}

    # The per-workspace allowlist. It can only ever turn an exec_host into automatic,
    # and only when the parse was clean. It cannot touch irreversible, it cannot touch
    # write_broad, and it never sees the denylist because that already returned.
    if (
        risk is RiskClass.EXEC_HOST
        and isinstance(operation, ShellOperation)
        and _allowlisted(operation, context)
    ):
        return Decision(
            verdict=Verdict.ALLOW,
            risk=risk,
            reasons=(
                "Every program in this command is on this workspace's approved list.",
                *reasons,
            ),
            matched_rule="workspace_allowlist",
            requires_undo_snapshot=snapshot,
            display_command=display,
        )

    # Invariant 7 / PRD §6.4.3: once untrusted content has been read, the dangerous
    # classes are re-gated even at L3.
    if context.ingested_untrusted_content and risk in PRIVILEGE_DROP_CLASSES:
        return Decision(
            verdict=Verdict.APPROVE,
            risk=risk,
            reasons=(
                "This task has already read untrusted external content, so host, network, "
                "and irreversible operations require fresh approval regardless of autonomy level.",
                *reasons,
            ),
            matched_rule="privilege_drop_after_ingestion",
            requires_undo_snapshot=snapshot,
            display_command=display,
        )

    automatic = risk in AUTO_AT_LEVEL[context.autonomy]
    return Decision(
        verdict=Verdict.ALLOW if automatic else Verdict.APPROVE,
        risk=risk,
        reasons=tuple(reasons),
        matched_rule=rule,
        requires_undo_snapshot=snapshot,
        display_command=display,
    )


def _allowlisted(operation: ShellOperation, context: PolicyContext) -> bool:
    if not context.approved_commands:
        return False
    script = parse(operation.command)
    commands = resolve_script(script, context.env)
    if not commands:
        return False
    return all(
        not command.problems
        and not command.privileged
        and command.program in context.approved_commands
        for command in commands
    )
