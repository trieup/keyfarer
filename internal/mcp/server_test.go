package mcp

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/zalando/go-keyring"

	"github.com/trieup/keyfarer/core/config"
	"github.com/trieup/keyfarer/core/secrets"
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

func newVaultRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	if err := config.Default().Save(dir); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYFARER_KEY", testVaultKey(t))

	p, err := secrets.Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.AddEnv("SERVICE_TOKEN", "tok-value-42"); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, ".keyfarer", "secrets", "sign.p8")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("P8 KEY BODY"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.AddFile(keyPath, true); err != nil {
		t.Fatal(err)
	}
	return dir
}

func connect(t *testing.T, dir string) *sdk.ClientSession {
	t.Helper()
	ctx := context.Background()
	serverT, clientT := sdk.NewInMemoryTransports()
	server := NewServer(dir)
	if _, err := server.Connect(ctx, serverT, nil); err != nil {
		t.Fatal(err)
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "test-agent", Version: "0"}, nil)
	session, err := client.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func call(t *testing.T, s *sdk.ClientSession, tool string, args map[string]any) *sdk.CallToolResult {
	t.Helper()
	res, err := s.CallTool(context.Background(), &sdk.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s): %v", tool, err)
	}
	return res
}

func structured(t *testing.T, res *sdk.CallToolResult, into any) {
	t.Helper()
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatal(err)
	}
}

func TestListSecretsNeverLeaksValues(t *testing.T) {
	dir := newVaultRepo(t)
	s := connect(t, dir)
	res := call(t, s, "list_secrets", nil)
	if res.IsError {
		t.Fatalf("list_secrets errored: %+v", res.Content)
	}
	var out struct {
		Secrets []secrets.SecretInfo `json:"secrets"`
	}
	structured(t, res, &out)
	if len(out.Secrets) != 2 {
		t.Fatalf("secrets = %+v", out.Secrets)
	}
	raw, _ := json.Marshal(res)
	if strings.Contains(string(raw), "tok-value-42") || strings.Contains(string(raw), "P8 KEY BODY") {
		t.Fatal("list_secrets response leaked a secret value")
	}
}

func TestRunWithSecretsInjectsWithoutLeaking(t *testing.T) {
	dir := newVaultRepo(t)
	s := connect(t, dir)
	res := call(t, s, "run_with_secrets", map[string]any{
		"argv": []string{"sh", "-c", "test \"$SERVICE_TOKEN\" = tok-value-42 && echo TOKEN_OK"},
	})
	if res.IsError {
		t.Fatalf("run_with_secrets errored: %+v", res.Content[0])
	}
	var out struct {
		Output   string `json:"output"`
		ExitCode int    `json:"exit_code"`
	}
	structured(t, res, &out)
	if out.ExitCode != 0 || !strings.Contains(out.Output, "TOKEN_OK") {
		t.Fatalf("run output: %+v", out)
	}
}

func TestRunWithSecretsRedactsOutput(t *testing.T) {
	dir := newVaultRepo(t)
	s := connect(t, dir)
	res := call(t, s, "run_with_secrets", map[string]any{
		"argv": []string{"sh", "-c", "echo \"leaked: $SERVICE_TOKEN\""},
	})
	if res.IsError {
		t.Fatalf("run_with_secrets errored: %+v", res.Content[0])
	}
	var out struct {
		Output   string `json:"output"`
		ExitCode int    `json:"exit_code"`
	}
	structured(t, res, &out)
	if strings.Contains(out.Output, "tok-value-42") {
		t.Fatalf("output leaked the secret value: %q", out.Output)
	}
	if !strings.Contains(out.Output, "[REDACTED]") {
		t.Fatalf("output was not redacted: %q", out.Output)
	}
	raw, _ := json.Marshal(res)
	if strings.Contains(string(raw), "tok-value-42") {
		t.Fatal("run_with_secrets response leaked the secret value")
	}
}

func TestMaterializeReturnsPathOnly(t *testing.T) {
	dir := newVaultRepo(t)
	s := connect(t, dir)
	res := call(t, s, "materialize", map[string]any{"path": ".keyfarer/secrets/sign.p8"})
	if res.IsError {
		t.Fatalf("materialize errored: %+v", res.Content[0])
	}
	var out struct {
		AbsolutePath string `json:"absolute_path"`
	}
	structured(t, res, &out)
	body, err := os.ReadFile(out.AbsolutePath)
	if err != nil || string(body) != "P8 KEY BODY" {
		t.Fatalf("materialized file: %q, %v", body, err)
	}
	raw, _ := json.Marshal(res)
	if strings.Contains(string(raw), "P8 KEY BODY") {
		t.Fatal("materialize response leaked file content")
	}
}

func TestGetSecretReturnsValue(t *testing.T) {
	dir := newVaultRepo(t)
	s := connect(t, dir)
	res := call(t, s, "get_secret", map[string]any{"key": "SERVICE_TOKEN"})
	if res.IsError {
		t.Fatalf("get_secret errored: %+v", res.Content[0])
	}
	var out struct {
		Value string `json:"value"`
	}
	structured(t, res, &out)
	if out.Value != "tok-value-42" {
		t.Fatalf("value = %q", out.Value)
	}

	res = call(t, s, "get_secret", map[string]any{"key": "NOPE"})
	if !res.IsError {
		t.Fatal("get_secret for unknown key should be a tool error")
	}
}
