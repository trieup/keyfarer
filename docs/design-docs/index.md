# Design docs index

Catalog of design documentation. This is the system of record for design decisions.
Keep it current; a recurring doc-gardening pass should flag drift.

## How to use this index

- Each entry links to a design doc and records its verification status.
- "Verified" means the doc reflects real code behavior and has been checked.
- Add a row when you add a design doc. Update status when code changes.

## Operating principles

- [core-beliefs.md](core-beliefs.md) - agent-first operating principles
- [golden-principles.md](golden-principles.md) - opinionated mechanical rules

## Design docs

| Doc | Summary | Status | Last verified |
|-----|---------|--------|---------------|
| [vault-format.md](vault-format.md) | On-disk format of keyfarer.vault | Verified | 2026-07-03 |
| [ai-access-model.md](ai-access-model.md) | MCP-first secret access for agents | Verified | 2026-07-03 |

## Related sources of truth

- Architecture: [../../ARCHITECTURE.md](../../ARCHITECTURE.md)
- Security and threat model: [../../SECURITY.md](../../SECURITY.md)
- Plans: [../exec-plans/active/](../exec-plans/active/)
