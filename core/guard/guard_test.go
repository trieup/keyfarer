package guard

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/trieup/keyfarer/core/config"
	"github.com/trieup/keyfarer/core/gitx"
	"github.com/trieup/keyfarer/core/manifest"
	"github.com/trieup/keyfarer/core/secrets"
)

func newRepo(t *testing.T) (string, *config.Config) {
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
	return dir, config.Default()
}

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

func write(t *testing.T, dir, rel, content string) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCheckSetupFlagsMissingIgnores(t *testing.T) {
	dir, cfg := newRepo(t)
	if _, err := cfg.RegisterFile("naked.pem"); err != nil {
		t.Fatal(err)
	}

	vs := CheckSetup(dir, cfg)
	if len(vs) != 2 {
		t.Fatalf("violations = %+v", vs)
	}

	// Fixing the ignores clears everything.
	if _, err := gitx.EnsureIgnored(dir, []string{config.Dir + "/", "naked.pem"}); err != nil {
		t.Fatal(err)
	}
	if vs := CheckSetup(dir, cfg); len(vs) != 0 {
		t.Fatalf("violations after fix = %+v", vs)
	}
}

func TestCheckStagedDetections(t *testing.T) {
	dir, cfg := newRepo(t)
	if _, err := cfg.RegisterFile("secret.pem"); err != nil {
		t.Fatal(err)
	}
	secretBody := "SUPER-SECRET-PEM-CONTENT-1234567890"
	apiKey := "sk-live-abcdef0123456789"
	st := &secrets.State{
		Files: []secrets.FileState{{Path: "secret.pem", SHA256: manifest.HashBytes([]byte(secretBody))}},
		Env:   []secrets.EnvState{{Key: "API_KEY", SHA256: manifest.HashBytes([]byte(apiKey))}},
	}

	// 1. Managed path staged directly.
	write(t, dir, "secret.pem", secretBody)
	gitRun(t, dir, "add", "-f", "secret.pem")
	// 2. Byte-identical copy under another name.
	write(t, dir, "backup/copy.txt", secretBody)
	gitRun(t, dir, "add", "backup/copy.txt")
	// 3. Pasted value inside source code.
	write(t, dir, "main.go", "package main\nconst key = \""+apiKey+"\"\n")
	gitRun(t, dir, "add", "main.go")
	// 4. Innocent file.
	write(t, dir, "README.md", "hello world, nothing to see")
	gitRun(t, dir, "add", "README.md")

	vs, err := CheckStaged(dir, cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, v := range vs {
		got[v.Path] = v.Code
	}
	if got["secret.pem"] != "GUARD_STAGED_SECRET_PATH" {
		t.Errorf("secret.pem: %+v", vs)
	}
	if got["backup/copy.txt"] != "GUARD_STAGED_SECRET_COPY" {
		t.Errorf("copy: %+v", vs)
	}
	if got["main.go"] != "GUARD_STAGED_SECRET_VALUE" {
		t.Errorf("pasted value: %+v", vs)
	}
	if _, ok := got["README.md"]; ok {
		t.Errorf("false positive on README.md: %+v", vs)
	}
	if !Blocking(vs) {
		t.Error("violations should block")
	}
}

func TestCheckStagedDegradesWithoutState(t *testing.T) {
	dir, cfg := newRepo(t)
	write(t, dir, "app.txt", "content")
	gitRun(t, dir, "add", "app.txt")

	vs, err := CheckStaged(dir, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 1 || vs[0].Code != "GUARD_NO_LOCAL_STATE" || vs[0].Blocking {
		t.Fatalf("want single advisory GUARD_NO_LOCAL_STATE, got %+v", vs)
	}
}

func TestCheckStagedCleanTree(t *testing.T) {
	dir, cfg := newRepo(t)
	vs, err := CheckStaged(dir, cfg, &secrets.State{})
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 0 {
		t.Fatalf("clean tree produced %+v", vs)
	}
}
