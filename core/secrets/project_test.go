package secrets

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/trieup/keyfarer/core/config"
	"github.com/trieup/keyfarer/core/vault"
)

func testVaultKey(t *testing.T) string {
	t.Helper()
	k, err := vault.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestMain(m *testing.M) {
	keyring.MockInit()
	os.Exit(m.Run())
}

// newTestRepo creates a real git repo with keyfarer initialized.
func newTestRepo(t *testing.T) *Project {
	t.Helper()
	dir := t.TempDir()
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "test@example.com"},
		{"config", "user.name", "Test"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	cfg := config.Default()
	if err := cfg.Save(dir); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYFARER_KEY", testVaultKey(t))
	p, err := Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func writeFile(t *testing.T, root, rel, content string) string {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return full
}

func TestAddFileMCPModeRemovesPlaintext(t *testing.T) {
	p := newTestRepo(t)
	full := writeFile(t, p.Root, ".keyfarer/secrets/key.p8", "PRIVATE KEY BYTES")

	rel, _, err := p.AddFile(full, true)
	if err != nil {
		t.Fatalf("AddFile: %v", err)
	}
	if rel != ".keyfarer/secrets/key.p8" {
		t.Errorf("rel = %q", rel)
	}
	if _, err := os.Stat(full); !errors.Is(err, os.ErrNotExist) {
		t.Error("plaintext still on disk after MCP-mode add")
	}
	if !p.VaultExists() {
		t.Fatal("vault not written")
	}

	path, err := p.Materialize(rel)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "PRIVATE KEY BYTES" {
		t.Errorf("materialized content = %q", body)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o600 {
			t.Errorf("materialized mode = %v, want 0600", info.Mode().Perm())
		}
	}
}

func TestAddEnvAndRun(t *testing.T) {
	p := newTestRepo(t)
	if _, err := p.AddEnv("MY_API_KEY", "sk-secret-value"); err != nil {
		t.Fatalf("AddEnv: %v", err)
	}

	out, code, err := p.RunCapture(context.Background(), []string{"sh", "-c", "test \"$MY_API_KEY\" = sk-secret-value && echo OK"})
	if err != nil || code != 0 {
		t.Fatalf("RunCapture: %v code=%d", err, code)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("env not injected, output = %q", out)
	}

	leak, _, err := p.RunCapture(context.Background(), []string{"sh", "-c", "printf '%s' \"$MY_API_KEY\""})
	if err != nil {
		t.Fatalf("RunCapture: %v", err)
	}
	if strings.Contains(leak, "sk-secret-value") {
		t.Errorf("captured output leaked secret value: %q", leak)
	}
}

func TestStatusLifecycle(t *testing.T) {
	p := newTestRepo(t)
	full := writeFile(t, p.Root, "prod.pem", "CERTIFICATE")

	if _, err := p.Config.RegisterFile("prod.pem"); err != nil {
		t.Fatal(err)
	}
	if err := p.Config.Save(p.Root); err != nil {
		t.Fatal(err)
	}
	rep, err := p.Status()
	if err != nil {
		t.Fatal(err)
	}
	if got := entryStatus(rep, "prod.pem"); got != StatusUnsealed {
		t.Errorf("before seal: %v, want unsealed", got)
	}

	if err := p.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	rep, _ = p.Status()
	if got := entryStatus(rep, "prod.pem"); got != StatusClean {
		t.Errorf("after seal: %v, want clean", got)
	}

	if err := os.WriteFile(full, []byte("ROTATED CERTIFICATE"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, _ = p.Status()
	if got := entryStatus(rep, "prod.pem"); got != StatusDrifted {
		t.Errorf("after edit: %v, want drifted", got)
	}
	if !rep.Dirty() {
		t.Error("report should be dirty")
	}

	if err := p.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(full); err != nil {
		t.Fatal(err)
	}
	rep, _ = p.Status()
	if got := entryStatus(rep, "prod.pem"); got != StatusEncrypted {
		t.Errorf("after remove: %v, want encrypted", got)
	}
	if rep.Dirty() {
		t.Error("encrypted-only should not be dirty")
	}
}

func TestRestoreOnFreshClone(t *testing.T) {
	p := newTestRepo(t)
	writeFile(t, p.Root, ".keyfarer/secrets/db.env", "DB_URL=postgres://x")
	if _, _, err := p.AddFile(filepath.Join(p.Root, ".keyfarer/secrets/db.env"), true); err != nil {
		t.Fatal(err)
	}
	if _, err := p.AddEnv("TOKEN", "t-123"); err != nil {
		t.Fatal(err)
	}

	if err := os.RemoveAll(filepath.Join(p.Root, config.Dir)); err != nil {
		t.Fatal(err)
	}
	p2, err := Open(p.Root, false)
	if err != nil {
		t.Fatal(err)
	}
	written, err := p2.Restore(true)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if len(written) != 1 || written[0] != ".keyfarer/secrets/db.env" {
		t.Errorf("written = %v", written)
	}
	body, err := os.ReadFile(filepath.Join(p.Root, ".keyfarer/secrets/db.env"))
	if err != nil || string(body) != "DB_URL=postgres://x" {
		t.Errorf("restored content = %q err=%v", body, err)
	}

	val, err := p2.GetEnvValue("TOKEN")
	if err != nil || val != "t-123" {
		t.Errorf("GetEnvValue = %q, %v", val, err)
	}
}

func TestSealFailsWhenRegisteredFileVanished(t *testing.T) {
	p := newTestRepo(t)
	if _, err := p.Config.RegisterFile("ghost.pem"); err != nil {
		t.Fatal(err)
	}
	if err := p.Config.Save(p.Root); err != nil {
		t.Fatal(err)
	}
	err := p.Seal()
	if !errors.Is(err, ErrVaultMissing) {
		t.Fatalf("want ErrVaultMissing, got %v", err)
	}
	if err != nil && !strings.Contains(err.Error(), "ghost.pem") {
		t.Errorf("error should name the missing file: %v", err)
	}
}

func TestAddFileOutsideRepoRejected(t *testing.T) {
	p := newTestRepo(t)
	outside := filepath.Join(t.TempDir(), "outside.pem")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.AddFile(outside, false); err == nil {
		t.Fatal("file outside repo accepted")
	}
}

func entryStatus(rep *Report, name string) EntryStatus {
	for _, e := range rep.Entries {
		if e.Name == name {
			return e.Status
		}
	}
	return "absent"
}
