// Package config defines keyfarer.toml, the committed per-repo configuration.
// It is the plaintext record of WHAT is managed (never values), so a fresh
// clone knows the secret set before the vault is ever decrypted.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

const (
	// FileName is the committed config file at the repo root.
	FileName = "keyfarer.toml"
	// VaultFileName is the committed encrypted artifact at the repo root.
	VaultFileName = "keyfarer.vault"
	// Dir is the local (gitignored) keyfarer directory.
	Dir = ".keyfarer"
	// SecretsDir holds plaintext secret files materialized on demand.
	SecretsDir = ".keyfarer/secrets"
	// StateFile is the local (gitignored) state: sealed hashes, materialized files.
	StateFile = ".keyfarer/state.json"
)

var (
	ErrNotInitialized = errors.New("config: keyfarer.toml not found (run `keyfarer init` first)")
	ErrInvalid        = errors.New("config: invalid keyfarer.toml")
)

// FileRef registers a managed secret file by repo-relative path.
type FileRef struct {
	Path string `toml:"path"`
}

// EnvRef registers a managed key/value secret by name.
type EnvRef struct {
	Key string `toml:"key"`
}

// Config is the typed form of keyfarer.toml.
type Config struct {
	Version int       `toml:"version"`
	Files   []FileRef `toml:"file"`
	Env     []EnvRef  `toml:"env"`
}

func Default() *Config {
	return &Config{Version: 1}
}

// Load reads and validates keyfarer.toml from the repo root.
func Load(root string) (*Config, error) {
	path := filepath.Join(root, FileName)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotInitialized
	}
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", FileName, err)
	}
	var c Config
	if err := toml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Save writes keyfarer.toml to the repo root.
func (c *Config) Save(root string) error {
	if err := c.validate(); err != nil {
		return err
	}
	var sb strings.Builder
	sb.WriteString("# Keyfarer configuration. Committed on purpose: it records WHAT is managed,\n")
	sb.WriteString("# never secret values. See https://github.com/trieup/keyfarer\n")
	enc := toml.NewEncoder(&sb)
	if err := enc.Encode(c); err != nil {
		return fmt.Errorf("config: encode: %w", err)
	}
	return os.WriteFile(filepath.Join(root, FileName), []byte(sb.String()), 0o644)
}

func (c *Config) validate() error {
	if c.Version != 1 {
		return fmt.Errorf("%w: unsupported version %d", ErrInvalid, c.Version)
	}
	for _, f := range c.Files {
		if err := ValidateRelPath(f.Path); err != nil {
			return err
		}
	}
	for _, e := range c.Env {
		if e.Key == "" {
			return fmt.Errorf("%w: env entry with empty key", ErrInvalid)
		}
	}
	return nil
}

// ValidateRelPath rejects paths that could escape the repo root when a vault is
// unpacked on another machine. Boundary validation per SECURITY.md.
func ValidateRelPath(p string) error {
	if p == "" {
		return fmt.Errorf("%w: empty file path", ErrInvalid)
	}
	if filepath.IsAbs(p) || strings.HasPrefix(p, "/") {
		return fmt.Errorf("%w: absolute path %q not allowed", ErrInvalid, p)
	}
	if strings.Contains(p, "\\") {
		return fmt.Errorf("%w: path %q must use forward slashes", ErrInvalid, p)
	}
	clean := filepath.ToSlash(filepath.Clean(p))
	if clean != p {
		return fmt.Errorf("%w: path %q is not clean (want %q)", ErrInvalid, p, clean)
	}
	if p == ".." || strings.HasPrefix(p, "../") {
		return fmt.Errorf("%w: path %q escapes the repository root", ErrInvalid, p)
	}
	return nil
}

// RegisterFile adds path to the managed set, reporting whether it was new.
func (c *Config) RegisterFile(path string) (bool, error) {
	if err := ValidateRelPath(path); err != nil {
		return false, err
	}
	for _, f := range c.Files {
		if f.Path == path {
			return false, nil
		}
	}
	c.Files = append(c.Files, FileRef{Path: path})
	return true, nil
}

// RegisterEnv adds key to the managed set, reporting whether it was new.
func (c *Config) RegisterEnv(key string) bool {
	for _, e := range c.Env {
		if e.Key == key {
			return false
		}
	}
	c.Env = append(c.Env, EnvRef{Key: key})
	return true
}

// HasFile reports whether path is registered.
func (c *Config) HasFile(path string) bool {
	for _, f := range c.Files {
		if f.Path == path {
			return true
		}
	}
	return false
}
