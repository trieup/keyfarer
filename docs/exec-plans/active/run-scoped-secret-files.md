# Execution plan: Run-scoped secret files for keyfarer run

Status: Active
Owner: agent
Created: 2026-07-10
Last updated: 2026-07-10

## Goal

Make `keyfarer run` and the MCP `run_with_secrets` tool materialize every sealed
secret file (`.env`, service account JSON, `.p8`, anything) at its recorded repo
path for exactly the lifetime of the child process, then remove it. Applications
that open secrets by path work unchanged, while plaintext exists on disk only
while the app is actually running, shrinking the window in which AI tooling can
index it.

Acceptance criteria:

- `keyfarer run -- <cmd>` writes each sealed file to its repo path before exec and
  deletes the ones it created after the child exits.
- Files already on disk (kept via `add --keep`, or explicitly materialized) are
  left untouched and never deleted.
- A file modified during the run is preserved (never destroyed); `keyfarer status`
  surfaces the drift.
- A crashed run leaves recoverable state: the next keyfarer command sweeps files
  whose owning process is dead, when they still match sealed content.
- `run_with_secrets` output redacts file contents as well as env values.
- `keyfarer run --no-files` restores the old env-only behavior.

## Context

- Design: [ai-access-model.md](../../design-docs/ai-access-model.md) (structural layer).
- Threat model: [SECURITY.md](../../../SECURITY.md).
- Architecture and layering: [ARCHITECTURE.md](../../../ARCHITECTURE.md).
- Related debt: TD-002 in [tech-debt-tracker.md](../tech-debt-tracker.md).

## Approach

All logic lives in the Service layer (`core/secrets`), which already composes
config, vault, gitx, keys. `unlock()` returns decrypted file bytes in memory; a
new `materializeForRun` writes them with the existing `writeSecretFile`, records
ownership (path + pid) in `.keyfarer/state.json`, and returns a cleanup func.
`Run` and `RunCapture` call a shared `prepareRun` helper. The Runtime layer
(`internal/cli/run.go`) adds the `--no-files` flag and keeps the parent alive
through Ctrl+C so cleanup always runs. Service packages never print; drift is
surfaced through the existing `status` path, not a print.

## Steps

- [ ] Add ephemeral records (path, pid, at) and an orphan sweep to `core/secrets/state.go`; add a portable `processAlive` (build-tagged unix/windows).
- [ ] Add `materializeForRun` + `prepareRun` to `core/secrets/run.go`, wired into `Run` (new `withFiles` param) and `RunCapture` (always on); re-ensure gitignore before writing; redact file contents in capture.
- [ ] Add `--no-files` flag and signal handling to `internal/cli/run.go`.
- [ ] Update MCP `run_with_secrets` and `materialize` descriptions in `internal/mcp/server.go`.
- [ ] Tests: unit (`core/secrets`), CLI integration, MCP; `make lint` and `make test`.
- [ ] Docs: `ai-access-model.md`, `SECURITY.md`, `README.md`, tech-debt tracker; `make docs-check`.

## Progress log

| Date | Update |
|------|--------|
| 2026-07-10 | Plan created; implementation started. |

## Decision log

| Date | Decision | Rationale | Alternatives considered |
|------|----------|-----------|-------------------------|
| 2026-07-10 | Materialize at real repo paths, not a temp dir | Toolchains expect canonical paths (`./.env`, `GOOGLE_APPLICATION_CREDENTIALS=./sa.json`); `cmd.Dir` is already the repo root | Out-of-workspace temp dir + symlink (weaker: some indexers follow symlinks) |
| 2026-07-10 | Drift surfaced via `status`, not a print from the service | Golden principle 3: service packages return data and errors, never print | Print a hint to stderr from `Run` |
| 2026-07-10 | Track owner pid in state; sweep dead-owner files on next run | Crash safety without a daemon; partially addresses TD-002 | TTL timestamp sweep (needs a clock policy) |

## Risks and debt

- Concurrent runs of the same repo: cleanup skips deletion while another live pid
  claims the same path; last live owner deletes. Mitigation implemented.
- A long-lived `keyfarer run -- npm run dev` keeps files on disk for the whole
  session (window = process lifetime, not zero). Accepted; noted in SECURITY.md.
- TD-002 remains open for files materialized via `restore --files`/`materialize`;
  the sweep here covers only run-owned files.

## Validation

`make lint` and `make test` (race) green; new unit, CLI, and MCP tests cover
materialize/cleanup, drift preservation, orphan sweep, concurrency, and file
content redaction.
