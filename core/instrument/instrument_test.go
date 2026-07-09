package instrument

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteAllFreshRepo(t *testing.T) {
	dir := t.TempDir()
	changed, err := WriteAll(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 5 {
		t.Fatalf("changed = %v", changed)
	}
	agents, err := os.ReadFile(filepath.Join(dir, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"run_with_secrets", "materialize", "Never read files under `.keyfarer/`", beginMarker, endMarker} {
		if !strings.Contains(string(agents), want) {
			t.Errorf("AGENTS.md missing %q", want)
		}
	}

	var mcpDoc struct {
		Servers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	raw, err := os.ReadFile(filepath.Join(dir, ".cursor", "mcp.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &mcpDoc); err != nil {
		t.Fatal(err)
	}
	kf, ok := mcpDoc.Servers["keyfarer"]
	if !ok || kf.Command != "keyfarer" || len(kf.Args) != 1 || kf.Args[0] != "mcp" {
		t.Fatalf("mcp.json registration = %+v", mcpDoc)
	}
}

func TestWriteAllIdempotent(t *testing.T) {
	dir := t.TempDir()
	if _, err := WriteAll(dir); err != nil {
		t.Fatal(err)
	}
	changed, err := WriteAll(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 0 {
		t.Fatalf("second run changed %v, want nothing", changed)
	}
}

func TestPreservesUserContent(t *testing.T) {
	dir := t.TempDir()
	userAgents := "# My project\n\nCustom agent instructions here.\n"
	if err := os.WriteFile(filepath.Join(dir, "AGENTS.md"), []byte(userAgents), 0o644); err != nil {
		t.Fatal(err)
	}
	userMCP := `{"mcpServers":{"other":{"command":"other-server"}}}`
	if err := os.MkdirAll(filepath.Join(dir, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".cursor", "mcp.json"), []byte(userMCP), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := WriteAll(dir); err != nil {
		t.Fatal(err)
	}

	agents, _ := os.ReadFile(filepath.Join(dir, "AGENTS.md"))
	if !strings.Contains(string(agents), "Custom agent instructions here.") {
		t.Error("user AGENTS.md content lost")
	}
	if !strings.Contains(string(agents), beginMarker) {
		t.Error("managed section not appended")
	}

	raw, _ := os.ReadFile(filepath.Join(dir, ".cursor", "mcp.json"))
	var doc map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["mcpServers"]["other"]; !ok {
		t.Error("existing MCP server registration lost")
	}
	if _, ok := doc["mcpServers"]["keyfarer"]; !ok {
		t.Error("keyfarer MCP server not registered")
	}
}

func TestManagedSectionUpdatedInPlace(t *testing.T) {
	dir := t.TempDir()
	stale := "# Repo\n\n" + beginMarker + "\nOLD STALE CONTENT\n" + endMarker + "\n\n## After section\n"
	if err := os.WriteFile(filepath.Join(dir, "AGENTS.md"), []byte(stale), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteAll(dir); err != nil {
		t.Fatal(err)
	}
	agents, _ := os.ReadFile(filepath.Join(dir, "AGENTS.md"))
	s := string(agents)
	if strings.Contains(s, "OLD STALE CONTENT") {
		t.Error("stale managed content not replaced")
	}
	if !strings.Contains(s, "## After section") {
		t.Error("content after managed section lost")
	}
	if !strings.Contains(s, "run_with_secrets") {
		t.Error("fresh managed content missing")
	}
}
