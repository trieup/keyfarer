# Technical debt tracker

Versioned, co-located record of known shortcuts. Treat debt like a high-interest
loan: pay it down continuously in small increments.

## How to use

- Add an entry whenever you knowingly take a shortcut.
- Link the entry from the relevant QUALITY_SCORE.md row.
- The recurring cleanup process picks from here and opens small refactor PRs.

## Open debt

| ID | Area | Description | Impact | Suggested fix | Added |
|----|------|-------------|--------|---------------|-------|
| TD-001 | Vault | No fuzz tests on vault/manifest parsing | med | Add go fuzz targets for Unpack and manifest decode | 2026-07-03 |
| TD-002 | Secrets | Materialized files have no TTL cleanup daemon. Partially addressed 2026-07-10: run-scoped file secrets are tracked with an owner PID and swept when the owner dies (`core/secrets.sweepEphemeral`). Still open for files materialized via `restore --files`/`materialize`. | low | Track expiry in state file; sweep on any command run | 2026-07-03 |
| TD-003 | Guard | Staged scan checks text blobs only; no binary heuristics | med | Scan binary blobs for exact secret byte sequences | 2026-07-03 |
| TD-004 | Access | `keyfarer merge` (vault conflict resolution) not implemented | med | Manifest-based newest-per-file merge command | 2026-07-03 |

## Resolved debt

| ID | Area | Resolution | Resolved |
|----|------|------------|----------|
| - | - | - | - |
