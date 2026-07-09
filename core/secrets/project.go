// Package secrets is the service layer: it composes config, vault, state, and
// keys into the operations the CLI and MCP server expose. It never prints;
// it returns data and errors (golden principle 3).
package secrets

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/trieup/keyfarer/core/config"
	"github.com/trieup/keyfarer/core/gitx"
	"github.com/trieup/keyfarer/core/keys"
	"github.com/trieup/keyfarer/core/manifest"
	"github.com/trieup/keyfarer/core/vault"
)

var (
	ErrNoVault      = errors.New("secrets: no vault file (run `keyfarer add` or `keyfarer seal` first)")
	ErrNotManaged   = errors.New("secrets: not a managed secret")
	ErrEmptySecret  = errors.New("secrets: refusing to store an empty secret")
	ErrVaultMissing = errors.New("secrets: entry registered in keyfarer.toml but absent from vault and disk")
)

// Project is one keyfarer-managed repository.
type Project struct {
	Root     string
	Config   *config.Config
	Resolver *keys.Resolver
}

// Open locates the enclosing git repo and loads its keyfarer config.
func Open(dir string, interactive bool) (*Project, error) {
	root, err := gitx.RepoRoot(dir)
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(root)
	if err != nil {
		return nil, err
	}
	return &Project{
		Root:     root,
		Config:   cfg,
		Resolver: &keys.Resolver{RepoRoot: root, Interactive: interactive},
	}, nil
}

func (p *Project) vaultPath() string { return filepath.Join(p.Root, config.VaultFileName) }

// VaultExists reports whether the encrypted artifact is present.
func (p *Project) VaultExists() bool {
	_, err := os.Stat(p.vaultPath())
	return err == nil
}

// unlock opens the existing vault, or returns a fresh manifest when none
// exists yet (first add). On first use it generates a random X25519 key and
// caches it locally. The returned newKey string is non empty only when a key
// was just generated.
func (p *Project) unlock() (*manifest.Manifest, map[string][]byte, string, error) {
	data, err := os.ReadFile(p.vaultPath())
	if errors.Is(err, os.ErrNotExist) {
		key, err := p.Resolver.Generate()
		if err != nil {
			return nil, nil, "", err
		}
		return manifest.New(), map[string][]byte{}, key, nil
	}
	if err != nil {
		return nil, nil, "", fmt.Errorf("secrets: read vault: %w", err)
	}
	key, err := p.Resolver.Get()
	if err != nil {
		return nil, nil, "", err
	}
	m, contents, err := vault.Open(bytes.NewReader(data), key)
	if err != nil {
		return nil, nil, "", err
	}
	_ = p.Resolver.Store(key)
	return m, contents, "", nil
}

// sealTo writes the vault atomically and refreshes local state.
func (p *Project) sealTo(m *manifest.Manifest, contents map[string][]byte) error {
	key, err := p.Resolver.Get()
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := vault.Seal(m, contents, key, &buf); err != nil {
		return err
	}
	tmp := p.vaultPath() + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("secrets: write vault: %w", err)
	}
	if err := os.Rename(tmp, p.vaultPath()); err != nil {
		return fmt.Errorf("secrets: replace vault: %w", err)
	}
	st, _ := LoadState(p.Root)
	fresh := StateFromManifest(m)
	if st != nil {
		fresh.Materialized = st.Materialized
	}
	return fresh.Save(p.Root)
}

// relPath converts any user-supplied path into a repo-relative slash path.
func (p *Project) relPath(path string) (string, error) {
	abs := path
	if !filepath.IsAbs(abs) {
		wd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		abs = filepath.Join(wd, path)
	}
	// Resolve symlinks (macOS /var -> /private/var) so Rel against the
	// already-resolved repo root cannot spuriously escape.
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	rel, err := filepath.Rel(p.Root, abs)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("secrets: %q is outside the repository", path)
	}
	rel = filepath.ToSlash(rel)
	if err := config.ValidateRelPath(rel); err != nil {
		return "", err
	}
	return rel, nil
}

// AddFile encrypts the file at path into the vault and registers it. When
// removePlaintext is set, the on-disk plaintext is deleted after sealing.
// When a vault key was just generated, createdKey is non empty.
func (p *Project) AddFile(path string, removePlaintext bool) (rel string, createdKey string, err error) {
	rel, err = p.relPath(path)
	if err != nil {
		return "", "", err
	}
	full := filepath.Join(p.Root, filepath.FromSlash(rel))
	info, err := os.Stat(full)
	if err != nil {
		return "", "", fmt.Errorf("secrets: %w", err)
	}
	body, err := os.ReadFile(full)
	if err != nil {
		return "", "", fmt.Errorf("secrets: %w", err)
	}
	if len(body) == 0 {
		return "", "", ErrEmptySecret
	}

	m, contents, createdKey, err := p.unlock()
	if err != nil {
		return "", "", err
	}
	m.SetFile(manifest.FileEntry{
		Path:   rel,
		SHA256: manifest.HashBytes(body),
		Mode:   uint32(info.Mode().Perm()),
		MTime:  info.ModTime().UTC(),
		Size:   info.Size(),
	})
	contents[rel] = body

	if _, err := p.Config.RegisterFile(rel); err != nil {
		return "", "", err
	}
	if err := p.Config.Save(p.Root); err != nil {
		return "", "", err
	}
	if _, err := gitx.EnsureIgnored(p.Root, []string{rel}); err != nil {
		return "", "", err
	}
	if err := p.sealTo(m, contents); err != nil {
		return "", "", err
	}
	if removePlaintext {
		if err := os.Remove(full); err != nil {
			return "", "", fmt.Errorf("secrets: sealed but could not remove plaintext: %w", err)
		}
	} else {
		st, _ := LoadState(p.Root)
		if st != nil {
			st.MarkMaterialized(rel)
			if err := st.Save(p.Root); err != nil {
				return "", "", err
			}
		}
	}
	return rel, createdKey, nil
}

// AddEnv stores a key/value secret in the vault and registers the key.
// When a vault key was just generated, createdKey is non empty.
func (p *Project) AddEnv(key, value string) (createdKey string, err error) {
	if key == "" || value == "" {
		return "", ErrEmptySecret
	}
	m, contents, createdKey, err := p.unlock()
	if err != nil {
		return "", err
	}
	m.SetEnv(manifest.EnvEntry{Key: key, Value: value, SHA256: manifest.HashBytes([]byte(value))})
	p.Config.RegisterEnv(key)
	if err := p.Config.Save(p.Root); err != nil {
		return "", err
	}
	if err := p.sealTo(m, contents); err != nil {
		return "", err
	}
	return createdKey, nil
}

// Seal re-reads plaintext sources from disk and rewrites the vault. Files that
// exist only inside the vault are carried over unchanged. Files registered in
// config but present nowhere fail loudly.
func (p *Project) Seal() error {
	m, contents, _, err := p.unlock()
	if err != nil {
		return err
	}
	var missing []string
	for _, ref := range p.Config.Files {
		full := filepath.Join(p.Root, filepath.FromSlash(ref.Path))
		info, statErr := os.Stat(full)
		if statErr == nil {
			body, err := os.ReadFile(full)
			if err != nil {
				return fmt.Errorf("secrets: %w", err)
			}
			m.SetFile(manifest.FileEntry{
				Path:   ref.Path,
				SHA256: manifest.HashBytes(body),
				Mode:   uint32(info.Mode().Perm()),
				MTime:  info.ModTime().UTC(),
				Size:   info.Size(),
			})
			contents[ref.Path] = body
			continue
		}
		if m.File(ref.Path) == nil {
			missing = append(missing, ref.Path)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: %s", ErrVaultMissing, strings.Join(missing, ", "))
	}
	return p.sealTo(m, contents)
}

// Restore refreshes local state from the vault and, when withFiles is true,
// writes every secret file back to disk.
func (p *Project) Restore(withFiles bool) ([]string, error) {
	m, contents, _, err := p.unlock()
	if err != nil {
		return nil, err
	}
	st := StateFromManifest(m)
	var written []string
	if withFiles {
		for _, fe := range m.Files {
			if err := p.writeSecretFile(fe, contents[fe.Path]); err != nil {
				return written, err
			}
			st.MarkMaterialized(fe.Path)
			written = append(written, fe.Path)
		}
	}
	if err := st.Save(p.Root); err != nil {
		return written, err
	}
	return written, nil
}

func (p *Project) writeSecretFile(fe manifest.FileEntry, body []byte) error {
	full := filepath.Join(p.Root, filepath.FromSlash(fe.Path))
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		return fmt.Errorf("secrets: %w", err)
	}
	mode := os.FileMode(fe.Mode)
	if mode == 0 {
		mode = 0o600
	}
	if err := os.WriteFile(full, body, mode); err != nil {
		return fmt.Errorf("secrets: %w", err)
	}
	return os.Chmod(full, mode)
}

// Materialize decrypts a single file to its recorded path and returns the
// absolute path. This is the MCP-mode escape hatch for tools that need a real
// file (e.g. a .p8 signing key).
func (p *Project) Materialize(rel string) (string, error) {
	if err := config.ValidateRelPath(rel); err != nil {
		return "", err
	}
	m, contents, _, err := p.unlock()
	if err != nil {
		return "", err
	}
	fe := m.File(rel)
	if fe == nil {
		return "", fmt.Errorf("%w: %q", ErrNotManaged, rel)
	}
	if err := p.writeSecretFile(*fe, contents[rel]); err != nil {
		return "", err
	}
	st, _ := LoadState(p.Root)
	if st == nil {
		st = StateFromManifest(m)
	}
	st.MarkMaterialized(rel)
	if err := st.Save(p.Root); err != nil {
		return "", err
	}
	return filepath.Join(p.Root, filepath.FromSlash(rel)), nil
}

// ShowKey returns the cached vault key for this repo, if available.
func (p *Project) ShowKey() (string, error) {
	return p.Resolver.Get()
}

// ForgetKey removes the cached vault key from local storage.
func (p *Project) ForgetKey() error {
	return p.Resolver.Forget()
}
