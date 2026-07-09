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
   - `run_with_secrets`: spawn a command with secrets injected as env vars; the
     agent sees only command output, which is scanned so any known secret value
     is redacted to `[REDACTED]` before returning (backstop against a command
     that echoes an injected env var).
   - `materialize`: decrypt one file to its recorded path on demand; returns only
     the path. Tracked in local state so `status` and guard know plaintext exists.
   - `get_secret`: last-resort raw value, with a warning in the tool description.
3. **Detection layer.** The guard pre-commit scan matches staged content against
   managed secret values and their hashes, catching values that leaked anyway.
   Implementation: `core/guard`.

## Tool description as instruction surface

MCP tool descriptions are the strongest steering mechanism (agents read them on
every session). Descriptions in `internal/mcp` state explicitly: prefer
`run_with_secrets`; never read `.keyfarer/secrets/` directly; never echo secret
values.
