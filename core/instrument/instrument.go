// Package instrument writes the committed AI-agent harness into a user's
// repository: AGENTS.md / CLAUDE.md sections, a Cursor rule, and MCP server
// registration. All writes are idempotent; managed blocks are delimited by
// markers so re-running init updates in place without touching user content.
// Design: docs/design-docs/ai-access-model.md (instruction layer).
package instrument

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	beginMarker = "<!-- keyfarer:begin (managed by `keyfarer init`, do not edit inside) -->"
	endMarker   = "<!-- keyfarer:end -->"
)

const agentsSection = beginMarker + `
## Secrets: managed by Keyfarer

This repository stores its secrets in an encrypted vault (` + "`keyfarer.vault`" + `),
managed by [Keyfarer](https://github.com/trieup/keyfarer). Rules for agents:

- Use the ` + "`keyfarer`" + ` MCP tools to work with secrets. Prefer
  ` + "`run_with_secrets`" + ` (runs a command with secrets injected as env vars) and
  ` + "`materialize`" + ` (writes a secret file to its path and returns the path).
- Never read files under ` + "`.keyfarer/`" + ` directly.
- Never paste secret values into code, config, chat, commit messages, or logs.
- Never commit plaintext secrets. The pre-commit guard will block you; do not
  bypass it with ` + "`--no-verify`" + `.
- If the MCP server is unavailable, run ` + "`keyfarer mcp`" + ` or ask the user, do
  not work around it.
` + endMarker + "\n"

const cursorRule = `---
description: Keyfarer manages this repository's secrets
alwaysApply: true
---

- Secrets live in the encrypted ` + "`keyfarer.vault`" + `; use the ` + "`keyfarer`" + ` MCP tools.
- Prefer ` + "`run_with_secrets`" + ` to execute commands that need secrets, and
  ` + "`materialize`" + ` when a tool needs a real file (returns only the path).
- Never read ` + "`.keyfarer/`" + ` directly, never echo secret values into code,
  chat, or logs, and never bypass the pre-commit guard.
`

// WriteAll installs or refreshes every instrumentation file. It returns the
// repo-relative paths it created or updated.
func WriteAll(root string) ([]string, error) {
	var changed []string
	for _, f := range []struct {
		rel string
		fn  func(string) (bool, error)
	}{
		{"AGENTS.md", func(p string) (bool, error) { return upsertManagedSection(p) }},
		{"CLAUDE.md", func(p string) (bool, error) { return upsertManagedSection(p) }},
		{".cursor/rules/keyfarer.mdc", writeCursorRule},
		{".cursor/mcp.json", upsertMCPRegistration},
		{".mcp.json", upsertMCPRegistration},
	} {
		full := filepath.Join(root, filepath.FromSlash(f.rel))
		did, err := f.fn(full)
		if err != nil {
			return changed, fmt.Errorf("instrument: %s: %w", f.rel, err)
		}
		if did {
			changed = append(changed, f.rel)
		}
	}
	return changed, nil
}

// upsertManagedSection appends the managed block to a markdown file, or
// replaces an existing managed block in place.
func upsertManagedSection(path string) (bool, error) {
	existing, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	content := string(existing)
	var out string
	if i := strings.Index(content, beginMarker); i >= 0 {
		j := strings.Index(content, endMarker)
		if j < i {
			return false, fmt.Errorf("malformed keyfarer markers")
		}
		out = content[:i] + strings.TrimSuffix(agentsSection, "\n") + content[j+len(endMarker):]
	} else {
		out = content
		if out != "" && !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		if out != "" {
			out += "\n"
		}
		out += agentsSection
	}
	if out == content {
		return false, nil
	}
	return true, os.WriteFile(path, []byte(out), 0o644)
}

func writeCursorRule(path string) (bool, error) {
	existing, err := os.ReadFile(path)
	if err == nil && string(existing) == cursorRule {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	return true, os.WriteFile(path, []byte(cursorRule), 0o644)
}

// upsertMCPRegistration merges the keyfarer server into an mcp.json without
// disturbing other configured servers.
func upsertMCPRegistration(path string) (bool, error) {
	doc := map[string]json.RawMessage{}
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, &doc); err != nil {
			return false, fmt.Errorf("existing file is not valid JSON: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}

	servers := map[string]json.RawMessage{}
	if raw, ok := doc["mcpServers"]; ok {
		if err := json.Unmarshal(raw, &servers); err != nil {
			return false, fmt.Errorf("mcpServers is not an object: %w", err)
		}
	}
	entry, _ := json.Marshal(map[string]any{
		"command": "keyfarer",
		"args":    []string{"mcp"},
	})
	if existing, ok := servers["keyfarer"]; ok {
		var compact bytes.Buffer
		if json.Compact(&compact, existing) == nil && compact.String() == string(entry) {
			return false, nil
		}
	}
	servers["keyfarer"] = entry
	rawServers, _ := json.Marshal(servers)
	doc["mcpServers"] = rawServers

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	return true, os.WriteFile(path, append(out, '\n'), 0o644)
}
