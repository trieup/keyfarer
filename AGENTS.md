# AGENTS.md

This file is a map, not a manual. It points to deeper sources of truth; it does not
contain them. If a rule matters, it is enforced in code and linked here.

## What this project is

Keyfarer is a repo secret vault for solo developers: it encrypts local secret files
(API keys, `.p8` keys, `.env` files) into a single `keyfarer.vault` file that is safe
to commit to git, restores them on a new machine with your vault key, and serves
secrets to AI coding agents through an MCP server so values never enter the model
context.

## Start here

- Architecture and layering: [ARCHITECTURE.md](ARCHITECTURE.md)
- Knowledge base index: [docs/design-docs/index.md](docs/design-docs/index.md)
- Operating principles: [docs/design-docs/core-beliefs.md](docs/design-docs/core-beliefs.md)
- Golden principles (mechanical rules): [docs/design-docs/golden-principles.md](docs/design-docs/golden-principles.md)
- Quality grades: [QUALITY_SCORE.md](QUALITY_SCORE.md)
- Reliability bar: [RELIABILITY.md](RELIABILITY.md)
- Security requirements and threat model: [SECURITY.md](SECURITY.md)
- Active plans: [docs/exec-plans/active/](docs/exec-plans/active/)
- Known technical debt: [docs/exec-plans/tech-debt-tracker.md](docs/exec-plans/tech-debt-tracker.md)

## Environment

- Language / runtime: Go (version pinned in [go.mod](go.mod))
- Package manager: Go modules, single module `github.com/trieup/keyfarer`
- Key dependencies: `filippo.io/age` (crypto), `spf13/cobra` (CLI),
  `modelcontextprotocol/go-sdk` (MCP), `zalando/go-keyring` (OS keychain)

## Commands

```bash
go build ./...            # build everything
make build                # build the CLI to bin/keyfarer
make test                 # go test -race ./...
make lint                 # go vet + golangci-lint
make docs-check           # knowledge base freshness (also runs in CI)
bin/keyfarer --help       # run the CLI locally
```

## How to do a change end to end

1. Read the relevant docs from the map above before editing.
2. For non-trivial work, write or update an execution plan in
   `docs/exec-plans/active/` (template: `docs/exec-plans/exec-plan.md`).
3. Implement the change. Respect layer boundaries (see ARCHITECTURE.md).
4. Run `make lint` and `make test`. Fix failures; messages include remediation.
5. Review your own changes locally, then request agent review.
6. Open a PR. Iterate on feedback until reviewers are satisfied. Escalate to a
   human only when judgment is required.

## Inspecting the running app

- Manual end to end: create a temp git repo, run `bin/keyfarer init` inside it,
  then exercise `add`, `seal`, `restore`, `status`, `run`, `guard`.
- MCP: `bin/keyfarer mcp` speaks MCP over stdio; integration tests under
  `internal/mcp` drive it in-process.
- Integration tests create real temp git repos; see `internal/cli/*_test.go`.

## Boundaries (do not cross)

- Dependencies flow one direction through layers:
  `manifest/config -> vault -> secrets (service) -> cli/mcp (runtime)`.
  See [ARCHITECTURE.md](ARCHITECTURE.md).
- Never invent cryptography. All encryption goes through `core/vault`, which
  wraps `filippo.io/age`. No other package may import crypto primitives.
- Secret values must never be logged, printed to stderr, or embedded in error
  messages. See [SECURITY.md](SECURITY.md).
- Parse and validate data at boundaries (config files, vault headers, MCP tool
  input). Do not build on guessed shapes.

When in doubt, follow the linked source of truth rather than pattern-matching local
code.
