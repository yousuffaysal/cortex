"""A deliberately conservative shell parser.

In:   a command string as the model proposed it.
Out:  a :class:`ParsedScript` — pipelines of simple commands, with every construct we
      could not resolve recorded as a :class:`ParseProblem`.
Fail: it does not. It never raises on malformed input; it records a problem and lets
      the engine fail closed. An exception here would be a way to skip classification.

Why not a regex, and why not ``shlex``
--------------------------------------
``shlex.split`` knows about quoting and nothing else. It returns one flat argv, so
``ls && rm -rf /`` becomes a single "ls" command with three harmless-looking arguments,
and ``rm -rf $TARGET`` keeps the variable unexpanded. Both read as safe. A regex for
``rm -rf /`` is worse: it is defeated by ``rm -fr /``, ``rm -r -f /``, an extra space,
a quote, or a variable.

Why not ``bashlex`` or another real bash parser
-----------------------------------------------
Considered and rejected for now. A full parser is more faithful, but it is third-party
code sitting inside the security boundary, and its failure mode on input it dislikes is
an exception rather than a "don't know". This parser is small enough to audit in one
sitting, and every gap in it routes to "don't know" — which the engine treats as unsafe.
Revisit if the problem rate on real commands gets annoying; correctness beats convenience
here, but so does auditability.

What "conservative" means concretely
------------------------------------
The parser's job is not to be right about what a command does. It is to be right about
whether it *knows* what a command does. ``$(...)``, backticks, ``eval``, unresolved
variables, and globs in argument position are all recorded rather than guessed at.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

__all__ = [
    "ParseProblem",
    "ParsedScript",
    "Pipeline",
    "SimpleCommand",
    "Word",
    "parse",
]


class ParseProblem(StrEnum):
    """Something in the command we could not resolve to a definite meaning.

    Every one of these means "I cannot tell what this does". The engine's response to
    any of them is to refuse automatic execution — never to assume the benign reading.
    """

    COMMAND_SUBSTITUTION = "command_substitution"
    PROCESS_SUBSTITUTION = "process_substitution"
    UNRESOLVED_VARIABLE = "unresolved_variable"
    DYNAMIC_COMMAND_NAME = "dynamic_command_name"
    GLOB_IN_ARGUMENT = "glob_in_argument"
    UNBALANCED_QUOTE = "unbalanced_quote"


# --- word model -------------------------------------------------------------------

#: A word is a sequence of parts: ("lit", text) | ("var", name) | ("sub", raw source).
Part = tuple[str, str]


@dataclass
class Word:
    parts: list[Part] = field(default_factory=list)
    raw: str = ""
    #: True when the word *begins* inside quotes, e.g. ``"A=b"``. Such a word is an
    #: argument, never a variable assignment — bash agrees.
    starts_quoted: bool = False

    def expand(self, env: dict[str, str]) -> tuple[str, set[ParseProblem]]:
        """Best-effort literal value, plus everything that made it uncertain."""
        problems: set[ParseProblem] = set()
        out: list[str] = []
        for kind, value in self.parts:
            if kind == "lit":
                out.append(value)
                if any(ch in value for ch in "*?["):
                    problems.add(ParseProblem.GLOB_IN_ARGUMENT)
            elif kind == "var":
                if value in env:
                    out.append(env[value])
                else:
                    problems.add(ParseProblem.UNRESOLVED_VARIABLE)
                    out.append(f"<unresolved:{value}>")
            elif kind == "sub":
                problems.add(ParseProblem.COMMAND_SUBSTITUTION)
                out.append("<substitution>")
            elif kind == "psub":
                problems.add(ParseProblem.PROCESS_SUBSTITUTION)
                out.append("<process-substitution>")
        return "".join(out), problems

    def is_assignment_prefix(self) -> bool:
        """``FOO=bar`` in command position. Quoted words never qualify."""
        if self.starts_quoted or not self.parts:
            return False
        kind, value = self.parts[0]
        if kind != "lit" or "=" not in value:
            return False
        name = value.split("=", 1)[0]
        return (
            bool(name)
            and (name[0].isalpha() or name[0] == "_")
            and all(ch.isalnum() or ch == "_" for ch in name)
        )


@dataclass
class SimpleCommand:
    """One command: optional ``VAR=x`` prefixes, an argv, and redirect targets."""

    argv: list[Word] = field(default_factory=list)
    assignments: list[Word] = field(default_factory=list)
    redirects: list[Word] = field(default_factory=list)
    raw: str = ""


@dataclass
class Pipeline:
    """Commands joined by ``|``. Kept grouped so ``curl … | sh`` stays detectable."""

    commands: list[SimpleCommand] = field(default_factory=list)


@dataclass
class ParsedScript:
    pipelines: list[Pipeline] = field(default_factory=list)
    problems: set[ParseProblem] = field(default_factory=set)

    def all_commands(self) -> list[SimpleCommand]:
        return [c for p in self.pipelines for c in p.commands]


# --- scanner ----------------------------------------------------------------------

# Longest match first: ">>" must be tried before ">", "&&" before "&>" before "&".
_OPERATORS = (
    "&&",
    "||",
    ">>",
    "<<",
    "&>",
    ">&",
    ">|",
    ";;",
    ";",
    "|",
    "&",
    ">",
    "<",
    "\n",
    "(",
    ")",
)
_REDIRECT_OPS = (">>", "<<", "&>", ">&", ">|", ">", "<")
_SEPARATORS = ("&&", "||", ";;", ";", "&", "\n", "(", ")")


def _read_balanced(src: str, start: int, opener: str, closer: str) -> int:
    """Index just past the balanced closer, or len(src) if it never closes."""
    depth = 0
    i = start
    while i < len(src):
        ch = src[i]
        if ch == "\\":
            i += 2
            continue
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(src)


class _Scanner:
    """Turns a command string into WORD / OP tokens. No expansion happens here."""

    def __init__(self, src: str) -> None:
        self.src = src
        self.i = 0
        self.tokens: list[tuple[str, object]] = []
        self.problems: set[ParseProblem] = set()
        self._word: Word | None = None

    # -- word building --
    def _ensure_word(self, quoted: bool = False) -> Word:
        if self._word is None:
            self._word = Word(starts_quoted=quoted)
        return self._word

    def _lit(self, text: str, raw: str | None = None, quoted: bool = False) -> None:
        w = self._ensure_word(quoted)
        if w.parts and w.parts[-1][0] == "lit":
            w.parts[-1] = ("lit", w.parts[-1][1] + text)
        else:
            w.parts.append(("lit", text))
        w.raw += raw if raw is not None else text

    def _part(self, kind: str, value: str, raw: str) -> None:
        w = self._ensure_word()
        w.parts.append((kind, value))
        w.raw += raw

    def _flush(self) -> None:
        if self._word is not None:
            self.tokens.append(("word", self._word))
            self._word = None

    # -- main loop --
    def scan(self) -> None:
        src = self.src
        while self.i < len(src):
            ch = src[self.i]

            if ch in " \t\r":
                self._flush()
                self.i += 1
            elif ch == "#" and self._word is None:
                while self.i < len(src) and src[self.i] != "\n":
                    self.i += 1
            elif ch == "\\":
                if self.i + 1 < len(src):
                    nxt = src[self.i + 1]
                    if nxt == "\n":  # line continuation
                        self.i += 2
                    else:
                        self._lit(nxt, raw=src[self.i : self.i + 2])
                        self.i += 2
                else:
                    self._lit("\\")
                    self.i += 1
            elif ch == "'":
                self._single_quote()
            elif ch == '"':
                self._double_quote()
            elif ch == "`":
                end = self._backtick_end()
                self._part("sub", src[self.i : end], src[self.i : end])
                self.i = end
            elif ch == "$":
                self._dollar()
            elif ch == "<" and src.startswith("<(", self.i):
                end = _read_balanced(src, self.i + 1, "(", ")")
                self._part("psub", src[self.i : end], src[self.i : end])
                self.i = end
            else:
                op = self._match_operator()
                if op is not None:
                    self._flush()
                    self.tokens.append(("op", op))
                    self.i += len(op)
                else:
                    self._lit(ch)
                    self.i += 1
        self._flush()

    def _match_operator(self) -> str | None:
        for op in _OPERATORS:
            if self.src.startswith(op, self.i):
                # A bare digit before > is an fd, e.g. `2>` — fold it into the operator
                # so it does not survive as an argv word.
                return op
        return None

    def _single_quote(self) -> None:
        src = self.src
        end = src.find("'", self.i + 1)
        quoted_start = self._word is None
        if end == -1:
            self.problems.add(ParseProblem.UNBALANCED_QUOTE)
            self._lit(src[self.i + 1 :], raw=src[self.i :], quoted=quoted_start)
            self.i = len(src)
            return
        self._lit(src[self.i + 1 : end], raw=src[self.i : end + 1], quoted=quoted_start)
        self.i = end + 1

    def _double_quote(self) -> None:
        src = self.src
        quoted_start = self._word is None
        self._ensure_word(quoted_start)
        start_raw = self.i
        self.i += 1
        buf: list[str] = []
        closed = False
        while self.i < len(src):
            ch = src[self.i]
            if ch == "\\" and self.i + 1 < len(src) and src[self.i + 1] in '"\\$`\n':
                buf.append(src[self.i + 1])
                self.i += 2
            elif ch == '"':
                closed = True
                self.i += 1
                break
            elif ch == "$":
                if buf:
                    self._lit("".join(buf), raw="")
                    buf = []
                self._dollar()
            elif ch == "`":
                if buf:
                    self._lit("".join(buf), raw="")
                    buf = []
                end = self._backtick_end()
                self._part("sub", src[self.i : end], "")
                self.i = end
            else:
                buf.append(ch)
                self.i += 1
        if buf:
            self._lit("".join(buf), raw="")
        if not closed:
            self.problems.add(ParseProblem.UNBALANCED_QUOTE)
        w = self._ensure_word()
        w.raw += src[start_raw : self.i]

    def _backtick_end(self) -> int:
        end = self.src.find("`", self.i + 1)
        return len(self.src) if end == -1 else end + 1

    def _dollar(self) -> None:
        src = self.src
        start = self.i
        if src.startswith("$((", self.i):
            end = _read_balanced(src, self.i + 2, "(", ")")
            end = _read_balanced(src, end - 1, "(", ")") if end < len(src) else end
            self._lit("<arith>", raw=src[start:end])
            self.i = end
            return
        if src.startswith("$(", self.i):
            end = _read_balanced(src, self.i + 1, "(", ")")
            self._part("sub", src[start:end], src[start:end])
            self.i = end
            return
        if src.startswith("${", self.i):
            end = _read_balanced(src, self.i + 1, "{", "}")
            inner = src[start + 2 : end - 1]
            # ${VAR}. Anything with an operator (:- := :? # % /) is not a plain lookup;
            # treat the whole thing as unresolvable rather than guessing a default.
            name = inner if inner.isidentifier() else ""
            if name:
                self._part("var", name, src[start:end])
            else:
                self._part("var", inner or "?", src[start:end])
            self.i = end
            return
        j = self.i + 1
        if j < len(src) and (src[j].isalpha() or src[j] == "_"):
            k = j
            while k < len(src) and (src[k].isalnum() or src[k] == "_"):
                k += 1
            self._part("var", src[j:k], src[start:k])
            self.i = k
            return
        # $1, $@, $*, $?, $$ — never resolvable from static text.
        if j < len(src) and src[j] in "0123456789@*?$#!":
            self._part("var", src[j], src[start : j + 1])
            self.i = j + 1
            return
        self._lit("$")
        self.i += 1


# --- assembly ---------------------------------------------------------------------


def parse(command: str) -> ParsedScript:
    """Parse ``command`` into pipelines of simple commands.

    Never raises. Constructs it cannot resolve appear in ``ParsedScript.problems`` and,
    after expansion, in the per-word problem sets the engine collects.
    """
    scanner = _Scanner(command)
    scanner.scan()

    script = ParsedScript(problems=set(scanner.problems))
    pipeline = Pipeline()
    current = SimpleCommand()
    expect_redirect_target = False

    def finish_command() -> None:
        nonlocal current
        if current.argv or current.assignments or current.redirects:
            pipeline.commands.append(current)
        current = SimpleCommand()

    def finish_pipeline() -> None:
        nonlocal pipeline
        finish_command()
        if pipeline.commands:
            script.pipelines.append(pipeline)
        pipeline = Pipeline()

    for position, (kind, value) in enumerate(scanner.tokens):
        if kind == "word":
            assert isinstance(value, Word)
            word = value
            # `2>file` — the bare fd number belongs to the redirection, not to argv.
            following = scanner.tokens[position + 1] if position + 1 < len(scanner.tokens) else None
            if (
                following is not None
                and following[0] == "op"
                and str(following[1]) in _REDIRECT_OPS
                and word.raw.isdigit()
            ):
                continue
            if expect_redirect_target:
                current.redirects.append(word)
                expect_redirect_target = False
            elif not current.argv and word.is_assignment_prefix():
                current.assignments.append(word)
            else:
                current.argv.append(word)
                current.raw = (current.raw + " " + word.raw).strip()
        else:
            op = str(value)
            if op in _REDIRECT_OPS:
                expect_redirect_target = True
            elif op == "|":
                finish_command()
            elif op in _SEPARATORS:
                finish_pipeline()

    finish_pipeline()
    return script
