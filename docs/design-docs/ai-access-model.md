# AI access model

How AI coding agents use secrets without secret values entering the model context.
This is the core product design decision: Keyfarer is AI first.

## The problem

Agents need secrets to do real work (run a server against an API, sign an iOS
build with a `.p8`), but any value an agent reads becomes part of the conversation
transcript sent to an LLM provider, and may be pasted into code or logs.

## The three-layer guarantee stack

No hard guarantee is possible; agents are probabilistic and prompt-injectable.
Keyfarer stacks three layers so ignoring the rules is hard, detectable, and mostly
pointless:

1. **Instruction layer.** `keyfarer init` writes committed instrumentation into the
   user's repo: a managed section in `AGENTS.md` (and `CLAUDE.md`), a
   `.cursor/rules/keyfarer.mdc` rule, and MCP registration in `.cursor/mcp.json`
   and `.mcp.json`. Because these are committed, they survive `git clone`.
   Implementation: `core/instrument`.
2. **Structural layer.** By default there is no plaintext on disk,
   so MCP is the only path. Tools are designed to keep values out of context:
   - `list_secrets`: names, types, metadata. Never values.
   - `run_with_secrets`: spawn a command with secrets available; key/value
     secrets are injected as env vars and sealed secret files are materialized at
     their repo paths only for the duration of the command, then removed (see
     "Run-scoped file secrets" below). The agent sees only command output, which
     is scanned so any known secret value or file content is redacted to
     `[REDACTED]` before returning (backstop against a command that echoes an
     injected env var or cats a materialized file).
   - `materialize`: decrypt one file to its recorded path and leave it there, for
     a long-lived need outside a single command; returns only the path. Tracked
     in local state so `status` and guard know plaintext exists.
   - `get_secret`: last-resort raw value, with a warning in the tool description.
3. **Detection layer.** The guard pre-commit scan matches staged content against
   managed secret values and their hashes, catching values that leaked anyway.
   Implementation: `core/guard`.

## Run-scoped file secrets

Not every application reads secrets from the environment; many open a file by
path (a service account JSON, an Apple `.p8`, a `.env` a framework auto-loads).
`keyfarer run` and `run_with_secrets` bridge this without leaving plaintext at
rest: before spawning the child, every sealed file secret not already on disk is
written to its recorded repo path (mode 0600), and when the child exits the files
keyfarer created are removed. Because the child runs with the repo root as its
working directory, relative paths like `./.env` and env vars like
`GOOGLE_APPLICATION_CREDENTIALS=./sa.json` resolve normally.

Safety properties, implemented in `core/secrets` (`materializeForRun`,
`sweepEphemeral`):

- Files already on disk (kept via `add --keep`, or explicitly materialized) are
  never touched or deleted; keyfarer only removes what it created for the run.
- A file modified during the run is preserved (its content no longer matches the
  sealed hash), so edits are never destroyed; `keyfarer status` surfaces the drift.
- Ownership is recorded in `.keyfarer/state.json` with the owning process PID. A
  crashed run leaves the file behind; the next keyfarer command sweeps files whose
  owner is no longer alive, when they still match sealed content.
- Concurrent runs of the same repo do not delete each other's files: cleanup
  skips deletion while another live process still claims the path.

The trade-off is that a long-lived command (a dev server) keeps its file secrets
on disk for the whole session; the plaintext window equals the process lifetime,
not zero. `keyfarer run --no-files` opts out and injects env secrets only.

## Tool description as instruction surface

MCP tool descriptions are the strongest steering mechanism (agents read them on
every session). Descriptions in `internal/mcp` state explicitly: prefer
`run_with_secrets`; never read `.keyfarer/secrets/` directly; never echo secret
values.
