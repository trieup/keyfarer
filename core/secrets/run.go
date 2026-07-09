package secrets

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
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

// Run executes argv with vault env secrets injected into the child process
// environment. The secrets exist only in the child's env, never in output.
func (p *Project) Run(ctx context.Context, argv []string, stdout, stderr *os.File, stdin *os.File) (int, error) {
	env, err := p.EnvMap()
	if err != nil {
		return -1, err
	}
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
// Used by the MCP run_with_secrets tool, where output goes back to the agent.
// Known secret values are redacted from the output as a backstop so a command
// that echoes an injected env var cannot leak it into the model context.
func (p *Project) RunCapture(ctx context.Context, argv []string) (string, int, error) {
	env, err := p.EnvMap()
	if err != nil {
		return "", -1, err
	}
	values := make([]string, 0, len(env))
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = p.Root
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
		values = append(values, v)
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
