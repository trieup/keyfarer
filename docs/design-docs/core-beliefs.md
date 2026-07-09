# Core beliefs

Agent-first operating principles for this repository. These define how we work, so
agents and humans make consistent decisions.

## Principles

1. Humans steer, agents execute. Human effort goes into environments, intent, and
   feedback loops, not hand-written code.
2. The repository is the system of record. If knowledge is not in versioned,
   repo-local artifacts, it does not exist for the agent.
3. Give a map, not a manual. Entry points stay small and stable; depth lives in
   linked docs (progressive disclosure).
4. Enforce invariants, not implementations. Boundaries, correctness, and
   reproducibility are enforced mechanically; expression within boundaries is free.
5. Optimize for agent legibility. Prefer boring, composable, stable technologies the
   agent can fully internalize. Keyfarer is a single Go module with a small
   dependency tree on purpose.
6. Promote rules into code. When documentation is not enough, encode the rule as a
   lint or test with a remediation message (see `core/arch_test.go`).
7. Pay down debt continuously. Small, frequent cleanups beat painful bursts.
8. Corrections are cheap, waiting is expensive. Favor short-lived PRs and follow-up
   fixes over indefinite blocking.

## Keyfarer-specific beliefs

- Never invent cryptography; wrap `filippo.io/age` and nothing else.
- Secret values are radioactive: they may exist in memory and in explicitly
  requested outputs, nowhere else.
- The MCP server is the primary interface for agents; the CLI is the primary
  interface for humans. Both are thin shells over the same service layer.

## How to apply

- Before a non-trivial change, read the relevant docs from [index.md](index.md) and
  write an execution plan.
- When a task is hard, ask what capability is missing (tooling, guardrails, docs)
  and feed the fix back into the repo, rather than just retrying.
- Capture human taste once (review comments, refactors, bugs) as docs or tooling so
  it is enforced everywhere thereafter.
