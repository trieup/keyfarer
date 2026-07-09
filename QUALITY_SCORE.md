# Quality score

Grades each domain and layer, tracking gaps over time. A recurring cleanup process
updates these grades and opens targeted refactor PRs.

## Grading scale

- A: Meets all golden principles and reliability/security bars. Well tested.
- B: Minor gaps. Safe to build on.
- C: Notable gaps or inconsistent patterns. Refactor soon.
- D: Significant debt or risk. Prioritize.
- F: Broken, untested, or unsafe. Fix before extending.

## Domain grades

| Domain | Grade | Gaps | Tracked debt |
|--------|-------|------|--------------|
| Vault | B | Needs fuzz tests on header parsing | TD-001 |
| Secrets | B | Materialize TTL cleanup not implemented | TD-002 |
| Guard | B | Substring scan only covers staged text blobs | TD-003 |
| Instrumentation | B | Idempotency covered; more editor targets possible | - |
| Access (CLI/MCP) | B | MCP tested in-process, not against every client | - |

## Layer grades

| Layer | Grade | Gaps |
|-------|-------|------|
| Types | A | - |
| Persistence | B | Fuzzing gap (TD-001) |
| Service | B | See domain rows |
| Runtime | B | - |

## History

| Date | Domain/Layer | Change | Note |
|------|--------------|--------|------|
| 2026-07-03 | all | initial | First implementation |
