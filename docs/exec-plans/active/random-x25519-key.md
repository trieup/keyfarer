# Execution plan: Switch vault to random X25519 key

Status: Completed
Owner: agent
Created: 2026-07-07
Last updated: 2026-07-07

## Goal

Replace scrypt passphrase encryption with a random age X25519 identity so committed
vaults are immune to offline brute force. Add cross platform key storage (OS credential
store plus key file fallback). Rewrite README around what/who/risks/precedent.

Acceptance: `make lint`, `make test`, manual init/add/restore flow in a temp repo.

## Context

- [vault-format.md](../../design-docs/vault-format.md)
- [SECURITY.md](../../../SECURITY.md)
- Plan: random key model aligned with Rails credentials and SOPS

## Approach

Respect layer boundaries: crypto in `core/vault`, key acquisition in `core/keys`,
business logic in `core/secrets`, display in `internal/cli`.

## Steps

- [x] Replace scrypt with X25519 in `core/vault`
- [x] Rename `core/passphrase` to `core/keys` with key file fallback
- [x] Wire `core/secrets` and CLI (`key show`, `key forget`)
- [x] Update tests and docs
- [ ] Run `make lint` and `make test`

## Progress log

| Date | Update |
|------|--------|
| 2026-07-07 | Started implementation |

## Decision log

| Date | Decision | Rationale | Alternatives considered |
|------|----------|-----------|-------------------------|
| 2026-07-07 | Replace passphrase entirely | User chose full switch; no users yet | Opt in modes, migration command |
| 2026-07-07 | Key file at UserConfigDir/keyfarer/keys.txt | Headless Linux/CI have no Secret Service | Env var only |

## Risks and debt

- Key file is plaintext on disk with mode 0600; documented in SECURITY.md
- X25519 is not post quantum; documented for public repos

## Validation

`make lint`, `make test`, manual e2e in temp git repo.
