# Keyfarer

**Your project's secrets, encrypted inside the repo, and served to AI agents
without ever entering the model context.**

## What it is

Keyfarer is a secret vault for solo developers. It encrypts your local secrets
(API keys, Apple `.p8` signing keys, `.env` values, service account JSON,
anything) into a single `keyfarer.vault` file that is **safe to commit to git**.
The vault is encrypted with a random [age](https://age-encryption.org) X25519 key
(256 bit entropy), the same model as Rails encrypted credentials and SOPS.

On a new machine you `git clone`, paste your vault key once, and everything is
back: secrets, git hooks, and AI agent configuration. The key is cached locally
(macOS Keychain, Windows Credential Manager, Linux Secret Service, or a key file
on headless Linux and CI).

Keyfarer also ships an **MCP server** (`keyfarer mcp`) so AI coding agents can
use secrets without values entering the model context:

| Tool | What the agent gets |
|------|---------------------|
| `list_secrets` | Names and metadata. Never values. |
| `run_with_secrets` | Runs a command with secrets injected as env vars; agent sees only the output. |
| `materialize` | Writes one secret file (e.g. a `.p8`) to its path; agent gets only the path. |
| `get_secret` | The raw value. Last resort, and the tool description says so. |

A **guard** pre commit hook scans staged content and blocks commits containing
managed secret paths, byte identical copies, or pasted secret values.

```
$ keyfarer init
$ keyfarer add AuthKey_ABC123.p8          # sealed into keyfarer.vault, plaintext removed
$ keyfarer add --env OPENAI_API_KEY       # prompted, hidden input
$ git add -A && git commit -m "vault"     # ciphertext travels with the repo

# ... on your new laptop ...
$ git clone you/your-app && cd your-app
$ keyfarer restore                        # paste vault key once, everything is back
```

## Who this is for

Keyfarer is built for **one person shipping from a laptop**: you work across
machines, you use AI coding agents, and your secrets are more than a single
`.env` file. The vault travels inside the repo because for a solo developer the
repo IS the project.

It is **not** built for teams that need shared access control, audit logs, or
server side secret management. Use Vault, 1Password, or your cloud provider for
that.

Public and private repos both work. See the risks section below for the honest
caveats on public repos.

## Is committing secrets to git standard?

Yes. Many mainstream tools commit encrypted secrets to git by design:

- **Rails** ships `config/credentials.yml.enc` in the repo; only `master.key` stays out of band.
- **SOPS** (CNCF) encrypts YAML and JSON files committed to gitOps repos.
- **Bitnami Sealed Secrets** states sealed secrets are "safe to store, even to a public repository."
- **git-crypt**, **Ansible Vault**, and **dotenvx** follow the same pattern.

Keyfarer uses the same random key model: the committed file is ciphertext only.
Without your vault key (never stored in the repo) the vault cannot be decrypted.
Offline brute force against a 256 bit key is computationally infeasible.

## Risks

The full threat model lives in [SECURITY.md](SECURITY.md). The short version:

- **Lost vault key means no recovery.** Save it in a password manager when
  `keyfarer add` prints it the first time. Use `keyfarer key show` to retrieve
  the cached key when setting up another machine.
- **A leaked key decrypts all published history forever.** Git history is
  permanent. Re encrypting the vault does not help; rotate the underlying
  secrets themselves after any suspected compromise.
- **Public repos are supported** with caveats: a guard bypass (`git commit
  --no-verify`) or accidental plaintext commit is compromised within minutes on
  public GitHub; long lived public ciphertext carries a harvest now decrypt later
  risk since X25519 is not post quantum.
- **A compromised local machine** can read cached keys, materialized plaintext,
  or process environments. No tool can prevent that.
- **Git hooks are advisory.** A determined human can bypass them.
- **AI agents are probabilistic.** Instructions steer, structure constrains, the
  guard detects. None of this is a hard guarantee.

## Install

Pick the option that fits you. You only need one.

**Option 1: Download a binary (easiest)**

1. Open the [releases page](https://github.com/trieup/keyfarer/releases) and download the file for your computer:
   - macOS on Apple Silicon: `keyfarer_*_darwin_arm64.tar.gz`
   - macOS on Intel: `keyfarer_*_darwin_amd64.tar.gz`
   - Windows: `keyfarer_*_windows_amd64.zip`
   - Linux: `keyfarer_*_linux_amd64.tar.gz` (or `arm64` on a Raspberry Pi or similar)
2. Unzip or untar the archive. You get a single `keyfarer` (or `keyfarer.exe` on Windows) program.
3. Move it somewhere on your [PATH](https://en.wikipedia.org/wiki/PATH_(variable)) so your terminal can find it, or run it from the folder you extracted to.

**Option 2: Install with a package manager**

Package managers keep `keyfarer` updated for you. Neither Homebrew nor Scoop ships with your operating system; install the manager first if you do not already have it.

*macOS or Linux with [Homebrew](https://brew.sh)*

If you do not have Homebrew yet, run this in Terminal:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Then install keyfarer:

```bash
brew install trieup/tap/keyfarer
```

*Windows with [Scoop](https://scoop.sh)*

If you do not have Scoop yet, open PowerShell and run:

```powershell
irm get.scoop.sh | iex
```

Then install keyfarer:

```powershell
scoop install keyfarer
```

**Option 3: Go developers only**

Skip this if you are not a Go programmer. You need the [Go toolchain](https://go.dev/dl/) installed first:

```bash
go install github.com/trieup/keyfarer/cmd/keyfarer@latest
```

The binary lands in your Go bin directory (usually `~/go/bin`). Make sure that folder is on your PATH.

**Verify**

Open a terminal and run:

```bash
keyfarer --help
```

If you see the command list, you are ready. Next step: `keyfarer init` inside your project folder.

## Commands

| Command | Purpose |
|---------|---------|
| `keyfarer init` | Set up the repo: config, gitignore, guard hook, agent instrumentation |
| `keyfarer add <file>` | Encrypt a secret file into the vault |
| `keyfarer add --env KEY[=VALUE]` | Encrypt a key/value secret |
| `keyfarer seal` | Re encrypt after editing plaintext sources |
| `keyfarer restore [--files]` | Restore on a new machine (hooks, state, optionally files) |
| `keyfarer status` | Drift report: what changed, what is unsealed |
| `keyfarer run -- <cmd>` | Run anything with secrets injected: env vars, plus file secrets materialized just for the command |
| `keyfarer key show` | Print the cached vault key (for another machine) |
| `keyfarer key forget` | Remove the cached vault key from local storage |
| `keyfarer guard [--staged]` | Verify nothing can leak into git (the hook entry point) |
| `keyfarer mcp` | Serve secrets to AI agents over MCP |

## How secrets live on disk

Secrets exist only encrypted at rest. Agents and commands access them through
MCP or `keyfarer run`. Key/value secrets are injected as environment variables;
file secrets (`.env`, service account JSON, `.p8`) are written to their repo
paths only for the lifetime of a `keyfarer run` command and removed when it
exits, so a tool that reads `./.env` or `GOOGLE_APPLICATION_CREDENTIALS=./sa.json`
just works without plaintext lingering. Use `keyfarer run --no-files` to inject
env secrets only. For a long-lived need outside a single command, files can be
materialized persistently (via `keyfarer restore --files`, the MCP materialize
tool, or `keyfarer add --keep`); anything materialized stays gitignored, guarded,
and sealed into the vault for backup.

## Why not SOPS / fnox / dotenvx / git-crypt?

Those are good tools with different centers of gravity. SOPS is built for
infra teams and YAML pipelines. dotenvx is `.env` only. git-crypt is
GPG era. Keyfarer is built for one person shipping from a laptop: arbitrary
file types, a random vault key, agent ready out of the box, and a guard that
assumes mistakes will happen.

fnox is the closest of the bunch: age encrypted secrets committed to git,
`fnox exec` for injection, file secrets via `as_file`, and an MCP server. The
differences are the parts Keyfarer treats as core, not extras. fnox has no
guard, so no pre commit hook, gitignore verification, or staged content scan
to catch a mistake before it lands. Its key travels by hand (`FNOX_AGE_KEY` or
a key file you copy yourself), where Keyfarer restores with a single pasted
key cached in the OS keychain. fnox leaves agent wiring to you; Keyfarer writes
AGENTS.md, rules, and mcp.json at `init`. And `as_file` materializes to temp
paths, where Keyfarer restores files to the real paths your toolchain expects.

Machine central vaults (TinyVault, CloakEnv, envkeep) solve secret storage,
but the vault stays on the old machine. Keyfarer's vault travels inside the
repo, because for a solo developer the repo IS the project.

## Contributing

Start with [AGENTS.md](AGENTS.md), the map of the codebase (yes, the repo
practices what it preaches: it is instrumented for AI agents). Then:

```bash
make test        # go test -race ./...
make lint
make docs-check  # knowledge base freshness
```

## License

MIT
