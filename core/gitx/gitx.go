// Package gitx wraps the git plumbing keyfarer needs: repo discovery,
// gitignore checks, staged content access, and hook installation. It shells
// out to the git binary, the same source of truth the user's tools use.
package gitx

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var ErrNotARepo = errors.New("gitx: not inside a git repository")

func run(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("gitx: git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out.String(), nil
}

// RepoRoot returns the absolute repository root containing dir, with symlinks
// resolved (macOS /var vs /private/var) so path comparisons are stable.
func RepoRoot(dir string) (string, error) {
	out, err := run(dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", ErrNotARepo
	}
	root := strings.TrimSpace(out)
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		return resolved, nil
	}
	return root, nil
}

// IsIgnored reports whether relPath is matched by gitignore rules. A trailing
// slash means "directory": git's dir-only patterns (like `.keyfarer/`) do not
// match a plain path probe unless the directory exists, so we probe a
// hypothetical file inside it instead.
func IsIgnored(root, relPath string) bool {
	probe := relPath
	if strings.HasSuffix(relPath, "/") {
		probe = relPath + "keyfarer-probe"
	}
	cmd := exec.Command("git", "check-ignore", "-q", "--", probe)
	cmd.Dir = root
	return cmd.Run() == nil
}

// EnsureIgnored appends the given patterns to the root .gitignore if git does
// not already ignore them. Returns the patterns that were added.
func EnsureIgnored(root string, patterns []string) ([]string, error) {
	var missing []string
	for _, p := range patterns {
		if !IsIgnored(root, p) {
			missing = append(missing, p)
		}
	}
	if len(missing) == 0 {
		return nil, nil
	}
	path := filepath.Join(root, ".gitignore")
	existing, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("gitx: read .gitignore: %w", err)
	}
	var sb strings.Builder
	sb.Write(existing)
	if len(existing) > 0 && !bytes.HasSuffix(existing, []byte("\n")) {
		sb.WriteString("\n")
	}
	sb.WriteString("\n# Keyfarer: local secrets must never be committed\n")
	for _, p := range missing {
		sb.WriteString(p + "\n")
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		return nil, fmt.Errorf("gitx: write .gitignore: %w", err)
	}
	return missing, nil
}

// StagedFiles lists repo-relative paths staged for commit (added, copied,
// modified, renamed).
func StagedFiles(root string) ([]string, error) {
	out, err := run(root, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
	if err != nil {
		return nil, err
	}
	var files []string
	for _, f := range strings.Split(out, "\x00") {
		if f != "" {
			files = append(files, f)
		}
	}
	return files, nil
}

// StagedContent returns the staged (index) content of relPath.
func StagedContent(root, relPath string) ([]byte, error) {
	out, err := run(root, "show", ":"+relPath)
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}

const hookMarker = "# keyfarer-guard"

// InstallPreCommitHook installs (or appends to) .git/hooks/pre-commit so
// `keyfarer guard --staged` runs before every commit. Idempotent.
func InstallPreCommitHook(root string) error {
	gitDir, err := run(root, "rev-parse", "--git-dir")
	if err != nil {
		return err
	}
	hooksDir := filepath.Join(root, strings.TrimSpace(gitDir), "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		return fmt.Errorf("gitx: hooks dir: %w", err)
	}
	hookPath := filepath.Join(hooksDir, "pre-commit")
	hookLine := hookMarker + "\nkeyfarer guard --staged || exit 1\n"

	existing, err := os.ReadFile(hookPath)
	if errors.Is(err, os.ErrNotExist) {
		script := "#!/bin/sh\n" + hookLine
		return os.WriteFile(hookPath, []byte(script), 0o755)
	}
	if err != nil {
		return fmt.Errorf("gitx: read pre-commit hook: %w", err)
	}
	if strings.Contains(string(existing), hookMarker) {
		return nil
	}
	out := string(existing)
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	out += hookLine
	return os.WriteFile(hookPath, []byte(out), 0o755)
}
