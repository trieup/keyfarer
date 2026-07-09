package secrets

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/trieup/keyfarer/core/gitx"
	"github.com/trieup/keyfarer/core/manifest"
)

// redactPlaceholder replaces any secret value found in agent-facing output.
const redactPlaceholder = "[REDACTED]"

// redactMinLen skips values shorter than this when redacting. Masking a very
// short value (say "1") would blank out unrelated output; we accept that such
// short values are not meaningfully secret. Mirrors the guard's token floor.
const redactMinLen = 5

// redactSecrets masks every occurrence of each value in out with a placeholder.
// Values are processed longest first so a value that contains a shorter one is
// masked in full. Empty or very short values are skipped (see redactMinLen).
func redactSecrets(out string, values []string) string {
	ordered := make([]string, 0, len(values))
	for _, v := range values {
		if len(v) >= redactMinLen {
			ordered = append(ordered, v)
		}
	}
	sort.Slice(ordered, func(i, j int) bool { return len(ordered[i]) > len(ordered[j]) })
	for _, v := range ordered {
		out = strings.ReplaceAll(out, v, redactPlaceholder)
	}
	return out
}

// SecretInfo is metadata about one secret, safe to show to agents: never the
// value.
type SecretInfo struct {
	Name         string `json:"name"`
	Kind         string `json:"kind"` // "file" or "env"
	Sealed       bool   `json:"sealed"`
	Materialized bool   `json:"materialized,omitempty"`
	Size         int64  `json:"size,omitempty"`
}

// List returns metadata for every managed secret without decrypting anything.
func (p *Project) List() ([]SecretInfo, error) {
	rep, err := p.Status()
	if err != nil {
		return nil, err
	}
	st, _ := LoadState(p.Root)
	materialized := map[string]bool{}
	if st != nil {
		for _, m := range st.Materialized {
			materialized[m.Path] = true
		}
	}
	var out []SecretInfo
	for _, e := range rep.Entries {
		info := SecretInfo{Name: e.Name, Kind: e.Kind}
		switch e.Status {
		case StatusClean, StatusEncrypted, StatusDrifted, StatusSealedEnv:
			info.Sealed = true
		}
		if e.Kind == "file" {
			info.Materialized = materialized[e.Name]
		}
		out = append(out, info)
	}
	return out, nil
}

// EnvMap decrypts the vault and returns all env entries as KEY=value pairs.
func (p *Project) EnvMap() (map[string]string, error) {
	m, _, _, err := p.unlock()
	if err != nil {
		return nil, err
	}
	env := make(map[string]string, len(m.Env))
	for _, e := range m.Env {
		env[e.Key] = e.Value
	}
	return env, nil
}

// prepareRun unlocks the vault once and assembles everything a run needs: the
// env map to inject, an optional list of secret values to redact from captured
// output, and a cleanup func to call after the child exits. When withFiles is
// true, every sealed file secret not already on disk is materialized at its repo
// path for the duration of the run.
func (p *Project) prepareRun(withFiles, wantValues bool) (env map[string]string, values []string, cleanup func(), err error) {
	m, contents, _, err := p.unlock()
	if err != nil {
		return nil, nil, nil, err
	}
	env = make(map[string]string, len(m.Env))
	for _, e := range m.Env {
		env[e.Key] = e.Value
		if wantValues {
			values = append(values, e.Value)
		}
	}
	cleanup = func() {}
	if withFiles {
		c, mErr := p.materializeForRun(m, contents)
		if mErr != nil {
			return nil, nil, nil, mErr
		}
		cleanup = c
		if wantValues {
			values = append(values, fileRedactValues(m, contents)...)
		}
	}
	return env, values, cleanup, nil
}

// fileRedactValues returns the full content and each substantial line of every
// sealed file so captured output cannot leak a file secret to an agent.
func fileRedactValues(m *manifest.Manifest, contents map[string][]byte) []string {
	var values []string
	for _, fe := range m.Files {
		body := contents[fe.Path]
		if len(body) == 0 {
			continue
		}
		values = append(values, string(body))
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimRight(line, "\r")
			if len(line) >= redactMinLen {
				values = append(values, line)
			}
		}
	}
	return values
}

// materializeForRun writes every sealed file secret that is not already on disk
// to its repo path, records ownership in state under the current pid, and returns
// a cleanup func that removes exactly those files (and directories it created)
// once the child exits, provided they still match the sealed content. Files
// already present on disk are left untouched and never deleted.
func (p *Project) materializeForRun(m *manifest.Manifest, contents map[string][]byte) (func(), error) {
	p.sweepEphemeral()

	st, _ := LoadState(p.Root)
	if st == nil {
		st = StateFromManifest(m)
	}
	pid := os.Getpid()
	var owned []manifest.FileEntry
	var createdDirs []string
	for _, fe := range m.Files {
		full := filepath.Join(p.Root, filepath.FromSlash(fe.Path))
		if _, statErr := os.Stat(full); statErr == nil {
			continue // already on disk; not ours to manage or delete
		}
		if _, err := gitx.EnsureIgnored(p.Root, []string{fe.Path}); err != nil {
			removeRunFiles(p.Root, owned)
			return nil, err
		}
		createdDirs = append(createdDirs, missingDirs(p.Root, filepath.Dir(full))...)
		if err := p.writeSecretFile(fe, contents[fe.Path]); err != nil {
			removeRunFiles(p.Root, owned)
			return nil, err
		}
		owned = append(owned, fe)
		st.MarkEphemeral(fe.Path, pid)
	}
	if err := st.Save(p.Root); err != nil {
		removeRunFiles(p.Root, owned)
		return nil, err
	}

	cleanup := func() {
		st, _ := LoadState(p.Root)
		if st == nil {
			return
		}
		for _, fe := range owned {
			full := filepath.Join(p.Root, filepath.FromSlash(fe.Path))
			if st.OtherLiveOwner(fe.Path, pid) {
				st.UnmarkEphemeral(fe.Path, pid)
				continue
			}
			// Delete only what we wrote, and only if it still matches the sealed
			// content. A file edited during the run is preserved; status surfaces
			// the drift.
			if body, rerr := os.ReadFile(full); rerr == nil && manifest.HashBytes(body) == fe.SHA256 {
				_ = os.Remove(full)
			}
			st.UnmarkEphemeral(fe.Path, pid)
		}
		removeEmptyDirs(createdDirs)
		_ = st.Save(p.Root)
	}
	return cleanup, nil
}

// sweepEphemeral removes files left behind by runs whose owning process is no
// longer alive, but only when the file still matches its sealed content. This is
// the crash-recovery path: a killed run leaves its records, the next command
// cleans them up.
func (p *Project) sweepEphemeral() {
	st, err := LoadState(p.Root)
	if err != nil || st == nil || len(st.Ephemeral) == 0 {
		return
	}
	kept := st.Ephemeral[:0]
	changed := false
	for _, e := range st.Ephemeral {
		if processAlive(e.PID) {
			kept = append(kept, e)
			continue
		}
		full := filepath.Join(p.Root, filepath.FromSlash(e.Path))
		if body, rerr := os.ReadFile(full); rerr == nil && manifest.HashBytes(body) == st.FileHash(e.Path) {
			_ = os.Remove(full)
		}
		changed = true
	}
	st.Ephemeral = kept
	if changed {
		_ = st.Save(p.Root)
	}
}

// removeRunFiles deletes files this run wrote, used to roll back a partial
// materialization when a later step fails.
func removeRunFiles(root string, files []manifest.FileEntry) {
	for _, fe := range files {
		_ = os.Remove(filepath.Join(root, filepath.FromSlash(fe.Path)))
	}
}

// missingDirs returns the ancestor directories of dir that do not yet exist,
// stopping at root. These are the directories a subsequent write will create.
func missingDirs(root, dir string) []string {
	var missing []string
	for d := dir; len(d) > len(root); d = filepath.Dir(d) {
		if _, err := os.Stat(d); err == nil {
			break
		}
		missing = append(missing, d)
	}
	return missing
}

// removeEmptyDirs removes the given directories deepest first. os.Remove only
// deletes empty directories, so this never discards unrelated files.
func removeEmptyDirs(dirs []string) {
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	for _, d := range dirs {
		_ = os.Remove(d)
	}
}

// GetEnvValue returns the raw value of one env secret. Last resort; callers
// own the responsibility of where it ends up (see docs/design-docs/ai-access-model.md).
func (p *Project) GetEnvValue(key string) (string, error) {
	m, _, _, err := p.unlock()
	if err != nil {
		return "", err
	}
	e := m.EnvVar(key)
	if e == nil {
		return "", fmt.Errorf("%w: env %q", ErrNotManaged, key)
	}
	return e.Value, nil
}

// Run executes argv with vault secrets available to the child process: env
// entries injected into its environment and, when withFiles is true, every
// sealed file secret materialized at its repo path for the lifetime of the
// child, then removed. The secrets never appear in Run's own output.
func (p *Project) Run(ctx context.Context, argv []string, stdout, stderr *os.File, stdin *os.File, withFiles bool) (int, error) {
	env, _, cleanup, err := p.prepareRun(withFiles, false)
	if err != nil {
		return -1, err
	}
	defer cleanup()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = p.Root
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Stdin = stdin
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	err = cmd.Run()
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), nil
	}
	if err != nil {
		return -1, fmt.Errorf("secrets: run: %w", err)
	}
	return 0, nil
}

// RunCapture executes argv with secrets injected and returns combined output.
// Used by the MCP run_with_secrets tool, where output goes back to the agent, so
// file secrets are materialized for the run and both env values and file
// contents are redacted from the output as a backstop against a command that
// echoes an injected env var or cats a materialized file.
func (p *Project) RunCapture(ctx context.Context, argv []string) (string, int, error) {
	env, values, cleanup, err := p.prepareRun(true, true)
	if err != nil {
		return "", -1, err
	}
	defer cleanup()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = p.Root
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	redacted := redactSecrets(string(out), values)
	if exitErr, ok := err.(*exec.ExitError); ok {
		return redacted, exitErr.ExitCode(), nil
	}
	if err != nil {
		return redacted, -1, fmt.Errorf("secrets: run: %w", err)
	}
	return redacted, 0, nil
}
