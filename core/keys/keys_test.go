package keys

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/trieup/keyfarer/core/vault"
)

func TestMain(m *testing.M) {
	keyring.MockInit()
	os.Exit(m.Run())
}

func TestGenerateAndGetFromKeyring(t *testing.T) {
	dir := t.TempDir()
	r := &Resolver{RepoRoot: dir, Interactive: false}
	k, err := r.Generate()
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Get()
	if err != nil {
		t.Fatal(err)
	}
	if got != k {
		t.Errorf("Get = %q, want %q", got, k)
	}
}

func TestGetFromEnv(t *testing.T) {
	k, err := vault.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvVar, k)
	r := &Resolver{RepoRoot: t.TempDir(), Interactive: false}
	got, err := r.Get()
	if err != nil {
		t.Fatal(err)
	}
	if got != k {
		t.Errorf("Get = %q, want %q", got, k)
	}
}

func TestKeyFileFallback(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "keys.txt")
	t.Setenv("KEYFARER_KEYS_FILE", keyFile)

	dir := t.TempDir()
	r := &Resolver{RepoRoot: dir, Interactive: false}
	k, err := vault.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.writeKeyFile(k); err != nil {
		t.Fatal(err)
	}
	got, err := r.fromKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	if got != k {
		t.Errorf("fromKeyFile = %q, want %q", got, k)
	}

	path, err := KeyFilePath()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows does not model Unix permission bits: Go reports 0666 for any
	// writable file regardless of the mode passed to os.WriteFile, so 0600 is
	// unrepresentable there. The 0600 guarantee only applies on Unix.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %o, want 0600", info.Mode().Perm())
	}
	if !filepath.IsAbs(path) {
		t.Errorf("key file path not absolute: %q", path)
	}
}

func TestForgetClearsKeyFile(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "keys.txt")
	t.Setenv("KEYFARER_KEYS_FILE", keyFile)

	dir := t.TempDir()
	r := &Resolver{RepoRoot: dir, Interactive: false}
	k, err := vault.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.writeKeyFile(k); err != nil {
		t.Fatal(err)
	}
	if err := r.Forget(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.fromKeyFile(); err == nil {
		t.Fatal("key still in key file after Forget")
	}
}

func TestInvalidKeyRejected(t *testing.T) {
	t.Setenv(EnvVar, "not-a-valid-age-key")
	r := &Resolver{RepoRoot: t.TempDir(), Interactive: false}
	if _, err := r.Get(); err == nil {
		t.Fatal("invalid env key accepted")
	}
}
