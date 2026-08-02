# packages/policy

The security boundary. Every tool call in Cortex passes through this package before it
executes (CLAUDE.md invariant 1). Nothing here talks to the network, the filesystem, or
a model — it is a pure function from *a proposed operation* to *a risk classification
and a decision*.

See `docs/learn/01-policy-engine.md` for the plain-English explanation.
