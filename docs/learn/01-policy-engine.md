# 01 — The Policy Engine

*First in a series written in build order. Each doc explains the idea in general terms
before it explains what we built, so reading them start to finish is a course rather
than a set of notes about finished code.*

Prerequisite: none. This is the first thing in the system, deliberately.

---

## Part 1 — What a policy engine is

### The situation that creates the need

An agent that can only produce text is safe by construction. The moment it can *act* —
run a command, write a file, send a request — someone has to decide whether each
proposed action actually happens. That decision has to be made somewhere, by something.

The naive place to put it is wherever the action happens:

```python
def run_shell(command):
    if "rm -rf" in command:
        if not ask_user(command):
            return
    subprocess.run(command, shell=True)
```

This is the version almost everyone writes first, and it has four problems that get
worse over time, not better.

**It is scattered.** The next capability — a filesystem writer, an HTTP client, an
email sender — gets its own copy of this logic, with its own subtly different idea of
what counts as dangerous. There is no single place to read to find out what the system
will and won't do.

**It is bypassable.** Nothing stops a new code path from calling `subprocess.run`
directly. Six months in, nobody knows whether every execution site is covered, and the
only way to find out is to grep and hope.

**It is untestable.** The check is welded to the thing it guards, so testing the check
means executing, or heavily mocking, the dangerous operation.

**It has no vocabulary.** `"rm -rf" in command` is a fact about one string. It doesn't
compose, doesn't generalise, and can't answer "what class of thing is this?" — which is
the question the rest of the system actually needs answered.

### The move: separate deciding from doing

A policy engine is the decision, extracted into its own component:

> **A policy engine is a pure function from (proposed action, context) to a decision.**

Pure means: no I/O, no network, no filesystem, no model calls, no clock, no randomness.
Given the same action and the same context, it returns the same decision, always.

Everything good about the pattern follows from that purity:

- **One choke point.** If every execution site must call `decide()` first, then
  "is this system safe?" becomes a question about one module rather than about the
  whole codebase. You can enforce it by review, by type, or by architecture.
- **Testable to exhaustion.** A pure function over strings can be run a hundred
  thousand times a second. You can fuzz it. You *should* fuzz it — see Part 3.
- **Auditable.** The decision, and the reason for it, is a value you can log, render in
  a UI, and replay later. A decision buried in an `if` statement is not a value; it's a
  control-flow side effect that vanishes the moment it's made.
- **Reviewable by a human who isn't a programmer.** The rules live in one file, in one
  vocabulary.

### The output is not a boolean

The first instinct is `allow: bool`. This is wrong, and the wrongness is instructive.

There are three genuinely different answers:

| Verdict | Meaning | Who decides |
|---|---|---|
| `ALLOW` | Run it. Don't interrupt the human. | The engine |
| `APPROVE` | Run it only if a human says yes, having seen it | The human |
| `DENY` | There is no yes. No prompt is shown. | The rule, permanently |

Collapsing `APPROVE` and `DENY` into "not allowed" loses the most important
distinction in the system. `APPROVE` means *the engine is deferring to a better-informed
judge*. `DENY` means *no judge exists* — there is no context in which `rm -rf /` from an
agent is what someone wanted, so offering a button would only create the opportunity to
click it at 2am.

A denylist that can be overridden is a speed bump with extra steps. If a rule is worth
having, it's worth being unconditional; if it isn't, it shouldn't be a rule.

### Classification is what keeps the rules small

The second instinct is a big table of commands and what to do about each. This doesn't
scale — there are more commands than you can enumerate, and new ones ship weekly.

The move is to classify *kinds of damage* rather than enumerate programs:

| Class | What it can cost you |
|---|---|
| `read` | Nothing, if the path is allowed |
| `compute` | Nothing; sandboxed |
| `write_scoped` | A file inside a known directory — recoverable from a snapshot |
| `write_broad` | A file anywhere — recoverable, but the blast radius is unbounded |
| `exec_host` | Anything the shell can do |
| `network` | Data leaves the machine, or code arrives |
| `irreversible` | Something you cannot get back |

Now the rules are about seven classes, not ten thousand programs. New programs get
mapped into an existing class. The interesting question moves from "what do I do about
`shred`?" to "which class is `shred`?" — a much easier question with a much more stable
answer.

### Risk class and autonomy are two different axes

The last piece: how much to interrupt depends on how much the user currently trusts the
agent. That's a separate dimension from how dangerous the action is.

```
                L0        L1        L2        L3
read          approve   approve    ALLOW     ALLOW
compute       approve   approve    ALLOW     ALLOW
write_scoped  approve   approve    ALLOW     ALLOW
network       approve   approve   approve    ALLOW
exec_host     approve   approve   approve    ALLOW
write_broad   approve   approve   approve   approve
irreversible  approve   approve   approve   approve   ← no column ever says ALLOW
```

The decision is a lookup in this grid, and the grid makes one property visually
obvious: **the bottom two rows have no `ALLOW` in any column.** There is no autonomy
setting that auto-runs an irreversible operation. That isn't a rule enforced by careful
coding in five places — it's a property of a table, checkable at a glance and assertable
in one test.

---

## Part 2 — Why you cannot do this with a regex

Everyone's first classifier is a regex. Watch it die.

You want to stop `rm -rf /`, so:

```python
re.search(r"rm -rf /", command)
```

**`rm -fr /`** — flags are a set, not a sequence. Add alternation.

**`rm -r -f /`** — flags can be separate words. Add more alternation.

**`rm --recursive --force /`** — long forms. And `-R` is also recursive. And you only
actually need `-r`; `-f` just suppresses prompts.

**`rm  -rf  /`** — two spaces. Switch to `\s+`.

**`rm -rf "/"`** — quotes. Now you need to know that quoting is removed before the
program sees the argument.

**`rm -rf /usr/..`** — path arithmetic. `/usr/..` *is* `/`. So is `//`, `/.`, and
`/tmp/../..`. You now need path normalisation, which is not a regex operation.

**`T=/; rm -rf $T`** — the dangerous string never appears in the command at all. You
now need variable tracking, which means you need to know which parts of the line are
assignments, which means you need to parse.

**`ls && rm -rf /`** — you need to find the second command. So you split on `&&`. Now
`echo "use a && b"` breaks, because you split inside a quoted string. To split
correctly you must know where the quotes are, which is — again — parsing.

**`bash -c 'rm -rf /'`** — the payload is inside a string argument. To see it you must
parse the outer command, extract the argument, and parse *that* as a new script.

**`nice -n 10 rm -rf /`** — the real program isn't the first word. And you can't just
skip words starting with `-`, because `-n` consumes `10` as its value. Get this wrong
and the program name resolves to `10`.

**`if true; then rm -rf /; fi`** — `then` isn't a program, it's a keyword. The real
command is behind it.

**`rm -rf $(cat /tmp/target)`** — and here the whole approach ends, for reasons in
Part 3.

### What that list is really telling you

Each fix makes the pattern longer, and after ten of them you have not written a robust
regex. You have written a bad shell parser, in regex syntax, with no tests, one CVE at
a time.

The underlying reason is a category error:

> **A regex matches text. The shell executes a grammar. The gap between the two is
> where every bypass lives.**

The attacker's alphabet isn't "ways to spell `rm -rf /`". It's the entire shell
grammar — quoting, expansion, substitution, control flow, redirection, wrappers.
Anything you don't model is available to hide in.

And it fails in the other direction too. A regex loose enough to catch the variants
also fires on `echo "never run rm -rf /"` and on a file legitimately named `rm -rf`.
False positives aren't harmless: an approval prompt that's usually wrong trains the
user to click through without reading, which converts your security boundary into
decoration. **Over-blocking and under-blocking are both failures, and over-blocking is
the one that fails quietly.**

### So: parse to the structure the shell will actually use

The fix is to stop working with text and start working with the same structure the
shell does — commands, arguments, flags, operators, expansions — and then ask questions
of *that*. `rm -rf /`, `rm -fr /`, `T=/; rm -rf $T`, and `nice -n 10 rm -rf /` all
reduce to the same shape:

```
program: rm    flags: {-r, -f}    operands: ["/"]
```

One rule now covers all four, and every future spelling of the same idea.

---

## Part 3 — "I can't tell what this does" is an answer, and it means stop

### Some commands are not statically knowable

```sh
rm -rf $(cat /tmp/target)
```

What does this delete? The only way to find out is to read `/tmp/target` — and its
contents may change between when you check and when the command runs. Worse:

```sh
eval "$PAYLOAD"
echo "$B64" | base64 -d | sh
find . -name '*.tmp' | xargs rm -rf
```

For each of these, determining the effect requires *executing* something. This isn't a
matter of writing a better parser. Even a perfect bash parser — one that agrees with
bash on every character — cannot tell you what `$(cat /tmp/target)` expands to, because
that isn't a fact about the text. It's a fact about the world at the moment the command
runs.

So a classifier has three possible outputs, not two:

1. This is safe.
2. This is dangerous.
3. **I cannot determine which.**

Systems that admit only two answers don't eliminate case 3. They just force it to be
silently miscategorised as 1 or 2.

### Which way to guess is not a matter of taste

Compare the costs:

|  | Engine says "unsafe", actually safe | Engine says "safe", actually unsafe |
|---|---|---|
| Cost | One approval click | Your home directory |
| Reversible | Yes | No |
| Detectable | Immediately | After the fact, if ever |

These differ by many orders of magnitude, and they differ *asymmetrically*. When the
costs of the two error types are that lopsided, the default isn't a preference — it's
forced. Uncertainty resolves toward the cheap error.

This is the **fail-closed** (or fail-safe) principle, and its most common violation is
the innocent-looking exception handler:

```python
try:
    risk = classify(command)
except Exception:
    return ALLOW          # ← the whole security boundary, gone, silently
```

That's why our parser is specified never to raise. A component that can throw is a
component whose error path is a bypass, and error paths get less review than any other
code in the system.

### The inversion worth remembering

Here's the sentence that reorganises how you think about the parser:

> **The parser's job is not to be right about what a command does. Its job is to be
> right about whether it knows what a command does.**

Being wrong about the first is recoverable — that's what the approval prompt is for.
Being wrong about the second is not, because it means the system was confident and
mistaken at the same time, which is the only combination that actually hurts you.

So every construct we can't resolve — `$(…)`, backticks, unset variables, globs,
runtime-chosen program names — gets *recorded* rather than guessed at. The classifier
then treats their presence as a fact about the command, as significant as the program
name.

### "Block" has two meanings, and the difference matters

"When you can't tell, block it" is right, but it hides a distinction worth being
explicit about:

- **Never automatic** — the engine won't run it unattended, but a human may look and
  decide. This is right for `rm -rf $TARGET`. *You* might know what `$TARGET` is. The
  engine can't, but it also shouldn't pretend the answer is unknowable to everyone. Its
  job is to stop being the decider and hand over to someone better informed, with the
  uncertainty spelled out in the prompt.
- **No approval exists** — nothing runs, no prompt is offered. This is right for
  `rm -rf /`, where there is no human answer that makes it correct.

Uncertainty gets the first treatment. The fixed denylist gets the second. Collapsing
them means either offering a button that should never exist, or refusing work the user
had a legitimate reason to do.

### Conservatism has a budget

One caveat, because it's the failure mode of everything in this document. If "I can't
tell" fires on a third of real commands, users stop reading prompts, and the boundary
becomes theatre. **A security control that is too annoying to obey has a real-world
strength of zero.**

So conservatism needs a pressure valve — a way for the common, verified-safe cases to
become quiet over time without weakening the rules that matter. Ours is a per-workspace
allowlist that grows as the user approves things, and which is deliberately
narrow: it can only make a cleanly-parsed host command automatic. It can't touch the
denylist, can't rescue an irreversible operation, and doesn't apply when the parse was
uncertain. The valve releases pressure from the boring cases only.

---

## Part 4 — What we actually built

`packages/policy` is a pure Python package with no I/O. One public entry point:

```python
decide(operation, context) -> Decision
```

| Module | Job |
|---|---|
| `risk.py` | The class table, the autonomy grid, the operation and decision models. No logic. |
| `shellparse.py` | Tokenizer. Produces pipelines of commands, and records what it couldn't resolve. |
| `resolve.py` | Parsed syntax → program name, normalised flags, operands. Peels wrappers. |
| `paths.py` | Workspace containment, and the credential paths that are never readable. |
| `denylist.py` | The unconditional rules. |
| `engine.py` | `decide()`. Applies the denylist, escalates uncertainty, then consults the grid. |

### The order of operations is itself the design

1. **Denylist first**, and it cannot be reached past.
2. **Uncertainty escalates** — anything unresolved is treated as the worst thing it
   could be.
3. **Most severe wins** — `ls && rm -rf ~/work` is classified by the `rm`, never the `ls`.
4. **Only then** does the autonomy level apply, and it can't rescue an irreversible.

### Three decisions with reasons

**We wrote our own parser instead of using `bashlex`.** A real bash parser is more
faithful. But it's third-party code inside the security boundary, and its failure mode
on input it dislikes is an exception — which, per Part 3, is a bypass. Ours is small
enough to audit in one sitting and every gap in it routes to "don't know". If the
"don't know" rate on real commands gets annoying, this gets revisited.

**`denylist.check()` takes no context argument.** Not "ignores it" — cannot see it.
There is no autonomy level, no allowlist, no flag it can be passed that changes its
answer. That's invariant 4 expressed as a type signature rather than a comment, and
there's a test asserting the signature stays that way.

**Every host shell command starts at `exec_host`.** Even `ls`. The risk table says
`exec_host` is "shell command on host", and `read` is what you get from the filesystem
server — a different, narrower interface that can't also delete things. The allowlist is
what keeps this from being unbearable.

### The fuzz suite, and what it caught

The suite generates cases rather than listing them: every ordering of `rm`'s flags,
every spelling of `/`, every separator that can hide a second command, every wrapper
that can hide a program name. Each case asserts `DENY` at *all four* autonomy levels
with the allowlist stacked in its favour — a case that only passes at L1 is a hole.

It found three real denylist bypasses during development, none of which were in the
hand-written list:

1. `if true; then rm -rf /; fi` — `then` was parsed as the program name, so the `rm`
   became a mere argument.
2. `echo x > /dev/disk0` — only `>>` was registered as an operator, never single `>`,
   so the redirect target was swallowed into a word and never checked.
3. `nice -n 10 rm -rf /` — the wrapper peeler skipped `-n` but not its value, so the
   program name resolved to `10` and `rm` was invisible.

That is the argument for generating cases instead of listing them, in three lines. A
hand-written list contains exactly the attacks its author already thought of, which is
the same set they already defended against.

The suite also asserts the *other* direction: `rm -rf ./build` must be **approvable**,
and `ls -la` must not be refused. A classifier that denies everything passes every
destructive test in the file and is useless. Negative controls are what make a security
test suite mean anything.

---

## What this doesn't cover yet

The engine decides. It doesn't record, and it doesn't enforce — something still has to
call it, and something still has to write down what happened.

That's next: `packages/audit`, the hash-chained log, and the rule that the log entry is
written *before* the action runs, not after.

→ **02 — The Audit Log**
