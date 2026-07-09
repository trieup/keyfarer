// Package keys is the single place vault keys are acquired and stored.
// Resolution order: KEYFARER_KEY env var, OS credential store, key file in
// the user config dir, interactive paste prompt. No other package may prompt
// or read the env var (golden principle; enforced by internal/archtest).
package keys

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zalando/go-keyring"
	"golang.org/x/term"

	"github.com/trieup/keyfarer/core/vault"
)

// EnvVar allows non-interactive use (CI, scripts, agents).
const EnvVar = "KEYFARER_KEY"

const keyringService = "keyfarer"

var (
	ErrNoKey     = errors.New("keys: not available non-interactively (set " + EnvVar + ", unlock via credential store, or run `keyfarer restore` in a terminal)")
	ErrInvalidKey = errors.New("keys: not a valid age X25519 identity")
)

// Resolver acquires the vault key for one repository. The repo root path is
// the credential store account and the key file lookup id.
type Resolver struct {
	RepoRoot string
	// Interactive permits prompting on a terminal. The MCP server and git
	// hooks must keep this false.
	Interactive bool
}

// Get returns the vault key, trying env var, credential store, key file, then prompt.
func (r *Resolver) Get() (string, error) {
	if k := os.Getenv(EnvVar); k != "" {
		if err := validateKey(k); err != nil {
			return "", err
		}
		return k, nil
	}
	if k, err := r.fromKeyring(); err == nil && k != "" {
		return k, nil
	}
	if k, err := r.fromKeyFile(); err == nil && k != "" {
		return k, nil
	}
	if !r.Interactive || !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", ErrNoKey
	}
	k, err := promptOnce("Vault key (paste AGE-SECRET-KEY-1...): ")
	if err != nil {
		return "", err
	}
	_ = r.Store(k)
	return k, nil
}

// Generate creates a new random X25519 identity for a brand new vault, stores
// it locally, and returns the key string for one time display. If KEYFARER_KEY
// is set it must be a valid age identity and is used instead (for automation).
func (r *Resolver) Generate() (string, error) {
	if k := os.Getenv(EnvVar); k != "" {
		if err := validateKey(k); err != nil {
			return "", err
		}
		_ = r.Store(k)
		return k, nil
	}
	k, err := vault.GenerateKey()
	if err != nil {
		return "", err
	}
	if err := r.Store(k); err != nil {
		return "", err
	}
	return k, nil
}

// Store caches the key in the OS credential store, falling back to the key
// file when no store is available (headless Linux, CI).
func (r *Resolver) Store(k string) error {
	if err := validateKey(k); err != nil {
		return err
	}
	if err := keyring.Set(keyringService, r.RepoRoot, k); err == nil {
		return nil
	}
	return r.writeKeyFile(k)
}

// Forget removes the cached key from both the credential store and key file.
func (r *Resolver) Forget() error {
	err := keyring.Delete(keyringService, r.RepoRoot)
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("keys: credential store delete: %w", err)
	}
	if err := r.deleteKeyFile(); err != nil {
		return err
	}
	return nil
}

// KeyFilePath returns the path to the fallback key file for this user.
// KEYFARER_KEYS_FILE overrides the default location (for tests and advanced setups).
func KeyFilePath() (string, error) {
	if p := os.Getenv("KEYFARER_KEYS_FILE"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("keys: config dir: %w", err)
	}
	return filepath.Join(dir, "keyfarer", "keys.txt"), nil
}

func (r *Resolver) fromKeyring() (string, error) {
	k, err := keyring.Get(keyringService, r.RepoRoot)
	if err != nil {
		return "", err
	}
	if err := validateKey(k); err != nil {
		return "", err
	}
	return k, nil
}

func (r *Resolver) fromKeyFile() (string, error) {
	path, err := KeyFilePath()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		id, k, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		if id != r.RepoRoot {
			continue
		}
		if err := validateKey(k); err != nil {
			return "", err
		}
		return k, nil
	}
	return "", os.ErrNotExist
}

func (r *Resolver) writeKeyFile(k string) error {
	path, err := KeyFilePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("keys: mkdir: %w", err)
	}

	lines := make([]string, 0)
	if data, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			id, _, ok := strings.Cut(line, ": ")
			if ok && id == r.RepoRoot {
				continue
			}
			lines = append(lines, line)
		}
	}
	lines = append(lines, r.RepoRoot+": "+k)

	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("keys: write key file: %w", err)
	}
	return nil
}

func (r *Resolver) deleteKeyFile() error {
	path, err := KeyFilePath()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("keys: read key file: %w", err)
	}
	var kept []string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		id, _, ok := strings.Cut(trimmed, ": ")
		if ok && id == r.RepoRoot {
			continue
		}
		kept = append(kept, line)
	}
	if len(kept) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("keys: remove key file: %w", err)
		}
		return nil
	}
	content := strings.Join(kept, "\n") + "\n"
	return os.WriteFile(path, []byte(content), 0o600)
}

func validateKey(k string) error {
	if err := vault.ValidateKey(k); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	return nil
}

func promptOnce(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("keys: read: %w", err)
	}
	k := strings.TrimSpace(string(b))
	if err := validateKey(k); err != nil {
		return "", err
	}
	return k, nil
}

// ParseKeyFile reads every repo id and key from the key file. Used by tests.
func ParseKeyFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	out := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		id, k, ok := strings.Cut(line, ": ")
		if ok {
			out[id] = k
		}
	}
	return out, sc.Err()
}
