package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"

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

func newRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "t@example.com"},
		{"config", "user.name", "T"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	t.Chdir(dir)
	t.Setenv("KEYFARER_KEY", testVaultKey(t))
	return dir
}

func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	cmd := New()
	cmd.SetArgs(args)
	runErr := cmd.Execute()
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	return buf.String(), runErr
}

func git(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestEndToEndLifecycle(t *testing.T) {
	dir := newRepo(t)

	out, err := runCLI(t, "init")
	if err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	for _, want := range []string{"created keyfarer.toml", "pre-commit guard hook", "AGENTS.md"} {
		if !strings.Contains(out, want) {
			t.Errorf("init output missing %q:\n%s", want, out)
		}
	}
	if out, err = runCLI(t, "init"); err != nil {
		t.Fatalf("second init: %v\n%s", err, out)
	}

	// Add a secret file (plaintext removed by default).
	keyPath := filepath.Join(dir, "AuthKey_TEST.p8")
	if err := os.WriteFile(keyPath, []byte("APPLE PRIVATE KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err = runCLI(t, "add", "AuthKey_TEST.p8"); err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}
	if _, err := os.Stat(keyPath); err == nil {
		t.Error("plaintext still present after add")
	}

	if out, err = runCLI(t, "add", "--env", "API_TOKEN=tok-abcdef123456"); err != nil {
		t.Fatalf("add --env: %v\n%s", err, out)
	}

	out, err = runCLI(t, "status")
	if err != nil {
		t.Fatalf("status: %v\n%s", err, out)
	}
	if !strings.Contains(out, "encrypted") || !strings.Contains(out, "sealed") {
		t.Errorf("status output:\n%s", out)
	}

	out, err = runCLI(t, "run", "--", "sh", "-c", "printf found-%s \"$API_TOKEN\"")
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}

	if out, err = runCLI(t, "restore", "--files"); err != nil {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	body, err := os.ReadFile(keyPath)
	if err != nil || string(body) != "APPLE PRIVATE KEY" {
		t.Fatalf("restored file: %q, %v", body, err)
	}

	if out, err := git(t, dir, "add", "-A"); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}
	staged, _ := git(t, dir, "diff", "--cached", "--name-only")
	if strings.Contains(staged, "AuthKey_TEST.p8") {
		t.Errorf("secret file was staged despite gitignore:\n%s", staged)
	}
	for _, want := range []string{"keyfarer.vault", "keyfarer.toml", "AGENTS.md", ".cursor/mcp.json"} {
		if !strings.Contains(staged, want) {
			t.Errorf("expected %s to be staged:\n%s", want, staged)
		}
	}
}

func TestFreshCloneRestore(t *testing.T) {
	dir := newRepo(t)
	if _, err := runCLI(t, "init"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secret.pem"), []byte("PEM DATA"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := runCLI(t, "add", "secret.pem"); err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}
	if out, err := git(t, dir, "add", "-A"); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}
	if out, err := git(t, dir, "commit", "-q", "-m", "vault", "--no-verify"); err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}

	cloneParent := t.TempDir()
	clone := filepath.Join(cloneParent, "clone")
	if out, err := git(t, cloneParent, "clone", "-q", dir, clone); err != nil {
		t.Fatalf("git clone: %v\n%s", err, out)
	}
	clone, err := filepath.EvalSymlinks(clone)
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(clone)

	out, err := runCLI(t, "restore", "--files")
	if err != nil {
		t.Fatalf("restore on clone: %v\n%s", err, out)
	}
	body, err := os.ReadFile(filepath.Join(clone, "secret.pem"))
	if err != nil || string(body) != "PEM DATA" {
		t.Fatalf("restored clone file: %q, %v", body, err)
	}
	if _, err := os.Stat(filepath.Join(clone, ".git", "hooks", "pre-commit")); err != nil {
		t.Error("pre-commit hook not reinstalled on clone")
	}
}

func TestGuardBlocksStagedSecret(t *testing.T) {
	dir := newRepo(t)
	if _, err := runCLI(t, "init"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "leak.env"), []byte("TOKEN=super-secret-value-123"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := runCLI(t, "add", "leak.env", "--keep"); err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}

	if out, err := git(t, dir, "add", "-f", "leak.env"); err != nil {
		t.Fatalf("git add -f: %v\n%s", err, out)
	}
	if _, err := exec.LookPath("keyfarer"); err != nil {
		t.Skip("keyfarer binary not on PATH; hook execution covered in guard unit tests")
	}
	if out, err := git(t, dir, "commit", "-m", "leak"); err == nil {
		t.Fatalf("commit with staged secret succeeded:\n%s", out)
	}
}
