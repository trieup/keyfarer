# Security

Security requirements and the threat model for Keyfarer. This document is honest
about what Keyfarer protects against and what it cannot.

## Threat model

Keyfarer protects secrets **in transit between your machines through git**. It does
not, and cannot, protect secrets on a machine that is already compromised.

### What Keyfarer defends against

| Threat | Defense |
|--------|---------|
| Vault file read by anyone with repo access | age encryption (X25519 identity, ChaCha20-Poly1305 AEAD). Without the vault key the file is ciphertext. |
| Offline brute force of a committed vault | Random 256 bit X25519 key; brute force is computationally infeasible. The key is never stored in the repo. |
| Accidentally committing plaintext secrets | Layered guard: gitignore verification, pre-commit hook, staged content scan matching managed secret values and hashes. |
| AI agent pasting secret values into code, chat, or logs | AI-first access model: MCP tools inject secrets into subprocesses or materialize files on demand; values never enter the model context by default. The guard scan is the detection backstop. |
| Stale or torn vault | Authenticated encryption (tamper detection) plus a manifest with per-file hashes for drift detection. |

### What Keyfarer does NOT defend against

- **A compromised local machine.** Malware with your user privileges can read
  materialized plaintext, the OS credential store entry, the key file at
  `UserConfigDir/keyfarer/keys.txt`, or process environments.
- **A lost vault key.** There is no recovery. Save the key in a password manager
  when `keyfarer add` prints it the first time.
- **A leaked vault key in a public repo.** Anyone who ever cloned the repo can
  decrypt every vault version ever pushed. Rotating the vault does not un-leak
  history; rotate the underlying secrets themselves after any suspected compromise.
- **A guard bypass in a public repo.** Scanners monitor public GitHub continuously;
  a plaintext leak is compromised within minutes.
- **Harvest now, decrypt later.** Publicly committed ciphertext could in principle
  be decrypted decades from now if X25519 is broken. Same risk accepted by SOPS
  and Sealed Secrets users.
- **A determined or prompt-injected agent with local shell access.** Instructions
  (AGENTS.md, tool descriptions) steer agents; the absence of plaintext structurally
  forces MCP usage; the guard detects mistakes. None of this is a hard guarantee.
- **`git add -f` plus `git commit --no-verify` by a determined human.** Hooks are
  advisory in git by design.

## Rules the code must uphold

- **No custom cryptography.** All encryption goes through `core/vault`, which wraps
  `filippo.io/age`. No other package imports crypto primitives (enforced by
  `core/arch_test.go`).
- **Secret values never appear in logs, stdout (except explicit `get`), error
  messages, or MCP tool results other than `get_secret`.**
- **Vault keys** come only from `core/keys.Resolver` in this order: env var
  `KEYFARER_KEY`, OS credential store (macOS Keychain, Windows Credential Manager,
  Linux Secret Service), key file at `UserConfigDir/keyfarer/keys.txt` (mode 0600,
  overridable via `KEYFARER_KEYS_FILE`), or interactive paste prompt. The key is
  never committed to the repo.
- **Parse at the boundary.** Vault headers, config files, and MCP tool inputs are
  validated before use.
- **Dependencies.** Crypto: `filippo.io/age` only. Keychain: `zalando/go-keyring`.
  Keep the dependency tree small and vetted; prefer stdlib.

## Reporting a vulnerability

Open a private security advisory on GitHub or email the maintainer. Do not open a
public issue for exploitable vulnerabilities.
