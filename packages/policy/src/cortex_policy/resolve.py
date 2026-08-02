"""Turn parsed shell syntax into commands with a name, flags, and operands.

In:   a :class:`~cortex_policy.shellparse.ParsedScript` and the task's environment.
Out:  a flat list of :class:`ResolvedCommand`, wrappers peeled off and flags normalised.
Fail: never raises. Unresolvable pieces stay attached as ``problems``.

Two jobs matter here, and both are places where naive implementations lose:

*Flag normalisation.* ``rm -rf``, ``rm -fr``, ``rm -r -f``, and ``rm --recursive
--force`` are the same command. Anything that compares argument *strings* sees four
different commands and catches whichever one it was written against.

*Wrapper peeling.* ``sudo rm``, ``env rm``, ``timeout 5 rm``, and ``bash -c 'rm …'``
all run ``rm``. The last one is not a wrapper at all — it is a whole new script inside
a quoted string — so it is re-parsed rather than unwrapped.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .shellparse import ParsedScript, ParseProblem, SimpleCommand, parse

__all__ = ["ResolvedCommand", "ResolvedPipeline", "resolve_script"]

#: Wrappers that run their remaining arguments as a command, with no argument of their
#: own to skip.
_TRANSPARENT_WRAPPERS: frozenset[str] = frozenset(
    {"command", "builtin", "exec", "nohup", "setsid", "time", "caffeinate"}
)

#: Wrappers that take a fixed number of positional arguments before the command.
_WRAPPERS_WITH_ARG: dict[str, int] = {"timeout": 1}

#: Wrappers whose own flags we skip, then run the rest.
_FLAG_TAKING_WRAPPERS: frozenset[str] = frozenset(
    {"sudo", "doas", "env", "nice", "ionice", "stdbuf"}
)

#: Per wrapper, the flags that consume the *next* argument as their value. Anything
#: missing from this table is assumed to be a standalone flag, which is the safe
#: assumption: it makes us stop peeling earlier, not later.
_WRAPPER_VALUE_FLAGS: dict[str, frozenset[str]] = {
    "sudo": frozenset({"-u", "-g", "-p", "-C", "-h", "-U", "-t", "-r"}),
    "doas": frozenset({"-u", "-C"}),
    "env": frozenset({"-u", "-C", "-S"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "ionice": frozenset({"-c", "-n", "-p", "-P", "-u"}),
    "stdbuf": frozenset({"-i", "-o", "-e"}),
    "timeout": frozenset({"-s", "-k", "--signal", "--kill-after"}),
}

_SHELLS: frozenset[str] = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish"})

#: Shell reserved words. These are not programs, so a command that begins with one has
#: its real program name further along: in `if true; then rm -rf /; fi`, the second
#: pipeline's argv is ["then", "rm", "-rf", "/"] and the `rm` is hiding behind `then`.
#: Skipping them is what stops control flow from being a place to hide a command.
_RESERVED_WORDS: frozenset[str] = frozenset(
    {
        "if", "then", "elif", "else", "fi",
        "while", "until", "do", "done",
        "for", "select", "in",
        "case", "esac",
        "function", "{", "}", "!",
    }
)

#: Commands that read a command from *input* and run it. The command name is known but
#: its arguments are not, so anything reached through one is permanently uncertain.
_INDIRECTION: frozenset[str] = frozenset({"xargs", "eval", "watch", "parallel"})


@dataclass
class ResolvedCommand:
    """One executable command, as close to "what will actually run" as we can get."""

    program: str
    """Basename of the executable: ``/bin/rm`` and ``rm`` both give ``rm``."""

    argv: list[str] = field(default_factory=list)
    flags: set[str] = field(default_factory=set)
    """Normalised: short flags as ``-r``, long as ``--recursive``. Clusters expanded."""

    operands: list[str] = field(default_factory=list)
    """Positional arguments, in order, with flags removed."""

    problems: set[ParseProblem] = field(default_factory=set)
    privileged: bool = False
    wrappers: list[str] = field(default_factory=list)
    redirects: list[str] = field(default_factory=list)
    raw: str = ""
    #: Position in the pipeline it came from, so ``curl | sh`` stays reconstructable.
    pipeline_index: int = 0
    stage_index: int = 0

    def has_flag(self, *names: str) -> bool:
        return any(name in self.flags for name in names)


@dataclass
class ResolvedPipeline:
    commands: list[ResolvedCommand] = field(default_factory=list)


def _normalise_flags(args: list[str]) -> tuple[set[str], list[str]]:
    """Split argv tail into normalised flags and operands.

    ``--`` ends flag parsing, exactly as getopt does — otherwise ``rm -- -rf`` would
    be read as recursive-force when it actually deletes a file named ``-rf``.
    """
    flags: set[str] = set()
    operands: list[str] = []
    end_of_flags = False

    for arg in args:
        if end_of_flags:
            operands.append(arg)
        elif arg == "--":
            end_of_flags = True
        elif arg.startswith("--") and len(arg) > 2:
            flags.add(arg.split("=", 1)[0])
        elif arg.startswith("-") and len(arg) > 1 and not arg[1].isdigit():
            for ch in arg[1:]:
                if ch == "=":
                    break
                flags.add(f"-{ch}")
        else:
            operands.append(arg)

    return flags, operands


def _expand_all(command: SimpleCommand, env: dict[str, str]) -> tuple[list[str], set[ParseProblem]]:
    problems: set[ParseProblem] = set()
    argv: list[str] = []
    for word in command.argv:
        text, word_problems = word.expand(env)
        problems |= word_problems
        argv.append(text)
    return argv, problems


def _apply_assignments(
    command: SimpleCommand, env: dict[str, str]
) -> tuple[dict[str, str], set[ParseProblem]]:
    """Return the env additions this command's ``VAR=x`` prefixes make."""
    added: dict[str, str] = {}
    problems: set[ParseProblem] = set()
    for word in command.assignments:
        text, word_problems = word.expand(env)
        problems |= word_problems
        name, _, value = text.partition("=")
        added[name] = value
    return added, problems


def _resolve_one(
    command: SimpleCommand,
    env: dict[str, str],
    pipeline_index: int,
    stage_index: int,
    depth: int,
) -> list[ResolvedCommand]:
    argv, problems = _expand_all(command, env)
    local_env = dict(env)
    added, assignment_problems = _apply_assignments(command, env)
    local_env.update(added)
    problems |= assignment_problems

    if not argv:
        return []

    wrappers: list[str] = []
    privileged = False
    index = 0

    while index < len(argv):
        head = argv[index]
        # A command name that came from a variable or substitution is not knowable.
        if "<unresolved:" in head or "<substitution>" in head:
            problems.add(ParseProblem.DYNAMIC_COMMAND_NAME)
            break
        name = head.rsplit("/", 1)[-1]

        if name in _RESERVED_WORDS:
            index += 1
            continue

        if name in _TRANSPARENT_WRAPPERS:
            wrappers.append(name)
            index += 1
            continue

        if name in _FLAG_TAKING_WRAPPERS or name in _WRAPPERS_WITH_ARG:
            wrappers.append(name)
            if name in {"sudo", "doas"}:
                privileged = True
            value_flags = _WRAPPER_VALUE_FLAGS.get(name, frozenset())
            index += 1
            while index < len(argv):
                arg = argv[index]
                # A flag that takes a *separate* value must consume that value too.
                # Getting this wrong means `nice -n 10 rm -rf /` resolves its program
                # name to "10", the `rm` is never seen, and the denylist is bypassed.
                if arg.startswith("-") and len(arg) > 1:
                    index += 2 if arg in value_flags else 1
                    continue
                if name == "env" and "=" in arg:
                    key, _, value = arg.partition("=")
                    local_env[key] = value
                    index += 1
                    continue
                break
            index += _WRAPPERS_WITH_ARG.get(name, 0)
            continue

        break

    if index >= len(argv):
        return []

    program_raw = argv[index]
    program = program_raw.rsplit("/", 1)[-1]
    tail = argv[index + 1 :]
    flags, operands = _normalise_flags(tail)

    redirects: list[str] = []
    for word in command.redirects:
        text, word_problems = word.expand(local_env)
        problems |= word_problems
        redirects.append(text)

    resolved = ResolvedCommand(
        program=program,
        argv=argv[index:],
        flags=flags,
        operands=operands,
        problems=set(problems),
        privileged=privileged,
        wrappers=wrappers,
        redirects=redirects,
        raw=command.raw,
        pipeline_index=pipeline_index,
        stage_index=stage_index,
    )

    results = [resolved]

    # `bash -c "<script>"` is not a wrapper — it is another script. Parse it, so the
    # command inside is classified on its own terms instead of hiding inside a string.
    if program in _SHELLS and "-c" in flags and operands and depth < 3:
        inner = resolve_script(parse(operands[0]), local_env, depth=depth + 1)
        for nested in inner:
            nested.privileged = nested.privileged or privileged
            nested.wrappers = [*wrappers, program, *nested.wrappers]
            nested.pipeline_index = pipeline_index
            nested.stage_index = stage_index
            nested.problems |= problems
        results.extend(inner)

    if program in _INDIRECTION:
        # Whatever this runs, its arguments come from somewhere we cannot see.
        resolved.problems.add(ParseProblem.DYNAMIC_COMMAND_NAME)
        if operands and depth < 3:
            nested_argv = operands
            nested_flags, nested_operands = _normalise_flags(nested_argv[1:])
            results.append(
                ResolvedCommand(
                    program=nested_argv[0].rsplit("/", 1)[-1],
                    argv=nested_argv,
                    flags=nested_flags,
                    operands=nested_operands,
                    problems={*problems, ParseProblem.DYNAMIC_COMMAND_NAME},
                    privileged=privileged,
                    wrappers=[*wrappers, program],
                    raw=command.raw,
                    pipeline_index=pipeline_index,
                    stage_index=stage_index,
                )
            )

    return results


def resolve_script(
    script: ParsedScript, env: dict[str, str] | None = None, depth: int = 0
) -> list[ResolvedCommand]:
    """Resolve every command in ``script``, threading variable assignments forward.

    Assignments made by a bare ``VAR=value`` command are visible to everything after
    it, which is what makes ``T=/; rm -rf $T`` resolvable rather than merely suspicious.
    """
    running_env = dict(env or {})
    out: list[ResolvedCommand] = []

    for pipeline_index, pipeline in enumerate(script.pipelines):
        for stage_index, command in enumerate(pipeline.commands):
            if command.assignments and not command.argv:
                added, _ = _apply_assignments(command, running_env)
                running_env.update(added)
                continue
            out.extend(
                _resolve_one(command, running_env, pipeline_index, stage_index, depth)
            )

    for resolved in out:
        resolved.problems |= script.problems
    return out
