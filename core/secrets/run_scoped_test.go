package secrets

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trieup/keyfarer/core/gitx"
)

func devnull(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// deadPID returns a PID that is guaranteed to no longer be running.
func deadPID(t *testing.T) int {
	t.Helper()
	c := exec.Command("sh", "-c", "exit 0")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	_ = c.Wait()
	return c.Process.Pid
}

func addSealedFile(t *testing.T, p *Project, rel, content string) {
	t.Helper()
	writeFile(t, p.Root, rel, content)
	if _, _, err := p.AddFile(filepath.Join(p.Root, filepath.FromSlash(rel)), true); err != nil {
		t.Fatalf("AddFile(%s): %v", rel, err)
	}
	if _, err := os.Stat(filepath.Join(p.Root, filepath.FromSlash(rel))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("plaintext %s should be gone after add", rel)
	}
}

func TestRunMaterializesFilesEphemerally(t *testing.T) {
	p := newTestRepo(t)
	addSealedFile(t, p, ".env", "SECRET=hunter2")

	dn := devnull(t)
	code, err := p.Run(context.Background(), []string{"sh", "-c", `test "$(cat .env)" = "SECRET=hunter2"`}, dn, dn, dn, true)
	if err != nil || code != 0 {
		t.Fatalf("run: err=%v code=%d (file not materialized for child?)", err, code)
	}
	if _, err := os.Stat(filepath.Join(p.Root, ".env")); !errors.Is(err, os.ErrNotExist) {
		t.Error("ephemeral file not cleaned up after run")
	}
	st, _ := LoadState(p.Root)
	if st != nil && len(st.Ephemeral) != 0 {
		t.Errorf("ephemeral records left behind: %+v", st.Ephemeral)
	}
}

func TestRunNoFilesLeavesFileSealed(t *testing.T) {
	p := newTestRepo(t)
	addSealedFile(t, p, ".env", "SECRET=hunter2")

	dn := devnull(t)
	code, err := p.Run(context.Background(), []string{"sh", "-c", `test ! -e .env`}, dn, dn, dn, false)
	if err != nil || code != 0 {
		t.Fatalf("run --no-files should not materialize: err=%v code=%d", err, code)
	}
}

func TestRunReEnsuresGitignore(t *testing.T) {
	p := newTestRepo(t)
	addSealedFile(t, p, "sa.json", `{"key":"value-1234567"}`)

	// Simulate a user wiping the .gitignore entry after add.
	if err := os.WriteFile(filepath.Join(p.Root, ".gitignore"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if gitx.IsIgnored(p.Root, "sa.json") {
		t.Fatal("precondition: sa.json should not be ignored after wiping .gitignore")
	}

	dn := devnull(t)
	if _, err := p.Run(context.Background(), []string{"true"}, dn, dn, dn, true); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !gitx.IsIgnored(p.Root, "sa.json") {
		t.Error("gitignore entry not re-ensured before materialization")
	}
}

func TestRunLeavesKeptFileUntouched(t *testing.T) {
	p := newTestRepo(t)
	full := writeFile(t, p.Root, "keep.pem", "KEEP THIS")
	if _, _, err := p.AddFile(full, false); err != nil { // keep plaintext
		t.Fatal(err)
	}

	dn := devnull(t)
	if _, err := p.Run(context.Background(), []string{"true"}, dn, dn, dn, true); err != nil {
		t.Fatalf("run: %v", err)
	}
	body, err := os.ReadFile(full)
	if err != nil || string(body) != "KEEP THIS" {
		t.Errorf("kept file altered/removed: %q err=%v", body, err)
	}
	st, _ := LoadState(p.Root)
	if st != nil {
		for _, e := range st.Ephemeral {
			if e.Path == "keep.pem" {
				t.Error("a kept file must never be tracked as ephemeral")
			}
		}
	}
}

func TestRunPreservesFileModifiedDuringRun(t *testing.T) {
	p := newTestRepo(t)
	addSealedFile(t, p, ".env", "SECRET=orig")

	dn := devnull(t)
	if _, err := p.Run(context.Background(), []string{"sh", "-c", `printf 'SECRET=changed' > .env`}, dn, dn, dn, true); err != nil {
		t.Fatalf("run: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(p.Root, ".env"))
	if err != nil || string(body) != "SECRET=changed" {
		t.Errorf("file modified during run was not preserved: %q err=%v", body, err)
	}
	st, _ := LoadState(p.Root)
	if st != nil && len(st.Ephemeral) != 0 {
		t.Errorf("ephemeral record not cleared for preserved file: %+v", st.Ephemeral)
	}
}

func TestSweepEphemeralRemovesDeadOwnerFiles(t *testing.T) {
	p := newTestRepo(t)
	addSealedFile(t, p, ".env", "SECRET=sweep")

	// Simulate a crashed run: file on disk, recorded under a dead pid.
	m, contents, _, err := p.unlock()
	if err != nil {
		t.Fatal(err)
	}
	fe := m.File(".env")
	if err := p.writeSecretFile(*fe, contents[".env"]); err != nil {
		t.Fatal(err)
	}
	st, _ := LoadState(p.Root)
	if st == nil {
		st = StateFromManifest(m)
	}
	st.MarkEphemeral(".env", deadPID(t))
	if err := st.Save(p.Root); err != nil {
		t.Fatal(err)
	}

	p.sweepEphemeral()

	if _, err := os.Stat(filepath.Join(p.Root, ".env")); !errors.Is(err, os.ErrNotExist) {
		t.Error("orphaned ephemeral file not swept")
	}
	st, _ = LoadState(p.Root)
	if st != nil && len(st.Ephemeral) != 0 {
		t.Errorf("dead ephemeral record not cleared: %+v", st.Ephemeral)
	}
}

func TestSweepEphemeralKeepsDriftedFile(t *testing.T) {
	p := newTestRepo(t)
	addSealedFile(t, p, ".env", "SECRET=orig")

	// Dead owner, but the on-disk file no longer matches the sealed content.
	if err := os.WriteFile(filepath.Join(p.Root, ".env"), []byte("SECRET=drifted"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, _, _, err := p.unlock()
	if err != nil {
		t.Fatal(err)
	}
	st, _ := LoadState(p.Root)
	if st == nil {
		st = StateFromManifest(m)
	}
	st.MarkEphemeral(".env", deadPID(t))
	if err := st.Save(p.Root); err != nil {
		t.Fatal(err)
	}

	p.sweepEphemeral()

	body, err := os.ReadFile(filepath.Join(p.Root, ".env"))
	if err != nil || string(body) != "SECRET=drifted" {
		t.Errorf("drifted file wrongly swept: %q err=%v", body, err)
	}
}

func TestRunCleanupSkipsWhileOtherOwnerAlive(t *testing.T) {
	p := newTestRepo(t)
	addSealedFile(t, p, ".env", "SECRET=shared")

	live := exec.Command("sleep", "30")
	if err := live.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = live.Process.Kill(); _ = live.Wait() })

	// A concurrent run already claimed .env under a live pid.
	m, _, _, err := p.unlock()
	if err != nil {
		t.Fatal(err)
	}
	st, _ := LoadState(p.Root)
	if st == nil {
		st = StateFromManifest(m)
	}
	st.MarkEphemeral(".env", live.Process.Pid)
	if err := st.Save(p.Root); err != nil {
		t.Fatal(err)
	}

	dn := devnull(t)
	if _, err := p.Run(context.Background(), []string{"true"}, dn, dn, dn, true); err != nil {
		t.Fatalf("run: %v", err)
	}

	if _, err := os.Stat(filepath.Join(p.Root, ".env")); err != nil {
		t.Error("file deleted despite another live owner")
	}
	st, _ = LoadState(p.Root)
	foundLive := false
	for _, e := range st.Ephemeral {
		if e.PID == live.Process.Pid {
			foundLive = true
		}
		if e.PID == os.Getpid() {
			t.Error("our own ephemeral record was not cleared")
		}
	}
	if !foundLive {
		t.Error("live owner's ephemeral record was wrongly removed")
	}
}

func TestRunCaptureRedactsFileContents(t *testing.T) {
	p := newTestRepo(t)
	addSealedFile(t, p, "sa.json", "PRIVATE-CREDENTIAL-abcdef")

	out, code, err := p.RunCapture(context.Background(), []string{"cat", "sa.json"})
	if err != nil || code != 0 {
		t.Fatalf("RunCapture: err=%v code=%d out=%q", err, code, out)
	}
	if strings.Contains(out, "PRIVATE-CREDENTIAL-abcdef") {
		t.Errorf("file content leaked into captured output: %q", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("file content not redacted: %q", out)
	}
	if _, err := os.Stat(filepath.Join(p.Root, "sa.json")); !errors.Is(err, os.ErrNotExist) {
		t.Error("ephemeral file not cleaned up after RunCapture")
	}
}
