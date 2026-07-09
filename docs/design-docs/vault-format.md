# Vault format

The on-disk format of `keyfarer.vault`, the single encrypted artifact committed to
the user's repository.

## Layers, outside in

```
keyfarer.vault
└── age encryption (X25519 identity recipient)
    └── gzip compression
        └── tar archive
            ├── keyfarer-manifest.json   (always the first entry)
            ├── files/<relative path>    (managed secret files, byte exact)
            └── env entries live only in the manifest
```

- **age**: encryption via `filippo.io/age` with an X25519 identity recipient.
  The vault key is a random 256 bit age identity (`AGE-SECRET-KEY-1...`) generated
  on first `keyfarer add` and stored outside the repo. age handles nonce and
  ChaCha20-Poly1305 AEAD; any tampering fails decryption.
- **gzip**: stdlib, applied inside the encryption so ciphertext has no structure.
- **tar**: stdlib, preserves file mode. Paths are stored relative to the repo root
  with forward slashes.

## Manifest

`keyfarer-manifest.json`, schema in `core/manifest`:

```json
{
  "version": 1,
  "created_at": "2026-07-03T09:00:00Z",
  "files": [
    {"path": ".keyfarer/secrets/AuthKey_ABC.p8", "sha256": "...", "mode": 384, "mtime": "...", "size": 227}
  ],
  "env": [
    {"key": "OPENAI_API_KEY", "sha256": "...", "value": "sk-..."}
  ]
}
```

- `files[].sha256` enables drift detection (`status`) and guard content matching
  without decrypting file bodies twice.
- `env` entries are key/value secrets that never need to exist as files; they are
  injected by `run` and `run_with_secrets`.
- `version` gates future format changes; readers must reject unknown versions.

## Invariants

- Round trip is byte exact, including file mode (see `core/vault` tests).
- The manifest is always the first tar entry so `status` can stream-read it
  without extracting bodies.
- The vault never contains absolute paths or paths escaping the repo root
  (validated on unpack, `ErrUnsafePath`).
