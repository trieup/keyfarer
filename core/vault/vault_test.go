package vault

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/trieup/keyfarer/core/manifest"
)

func testKey(t *testing.T) string {
	t.Helper()
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func buildManifest(t *testing.T, contents map[string][]byte) *manifest.Manifest {
	t.Helper()
	m := manifest.New()
	for path, body := range contents {
		m.SetFile(manifest.FileEntry{
			Path:   path,
			SHA256: manifest.HashBytes(body),
			Mode:   0o600,
			MTime:  time.Now().UTC(),
			Size:   int64(len(body)),
		})
	}
	m.SetEnv(manifest.EnvEntry{Key: "OPENAI_API_KEY", Value: "sk-test-123", SHA256: manifest.HashBytes([]byte("sk-test-123"))})
	return m
}

func TestRoundTrip(t *testing.T) {
	key := testKey(t)
	contents := map[string][]byte{
		".keyfarer/secrets/AuthKey_ABC.p8": []byte("-----BEGIN PRIVATE KEY-----\nMIGT...binary-ish \x00\x01\x02\n-----END PRIVATE KEY-----\n"),
		".keyfarer/secrets/service.json":   []byte(`{"type":"service_account"}`),
	}
	m := buildManifest(t, contents)

	var buf bytes.Buffer
	if err := Seal(m, contents, key, &buf); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	gotM, gotContents, err := Open(&buf, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(gotContents) != len(contents) {
		t.Fatalf("got %d files, want %d", len(gotContents), len(contents))
	}
	for path, body := range contents {
		if !bytes.Equal(gotContents[path], body) {
			t.Errorf("file %q not byte identical after round trip", path)
		}
	}
	if e := gotM.EnvVar("OPENAI_API_KEY"); e == nil || e.Value != "sk-test-123" {
		t.Errorf("env entry lost in round trip: %+v", e)
	}
	if fe := gotM.File(".keyfarer/secrets/AuthKey_ABC.p8"); fe == nil || fe.Mode != 0o600 {
		t.Errorf("file mode lost in round trip: %+v", fe)
	}
}

func TestWrongKey(t *testing.T) {
	wrong, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	key := testKey(t)
	contents := map[string][]byte{"a.txt": []byte("secret")}
	m := buildManifest(t, contents)
	var buf bytes.Buffer
	if err := Seal(m, contents, key, &buf); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	_, _, err = Open(&buf, wrong)
	if !errors.Is(err, ErrWrongKey) {
		t.Fatalf("want ErrWrongKey, got %v", err)
	}
}

func TestCorruptedVault(t *testing.T) {
	key := testKey(t)
	contents := map[string][]byte{"a.txt": bytes.Repeat([]byte("secret data "), 100)}
	m := buildManifest(t, contents)
	var buf bytes.Buffer
	if err := Seal(m, contents, key, &buf); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	raw := buf.Bytes()
	// Flip one byte in the ciphertext body (past the age header).
	raw[len(raw)-10] ^= 0xFF
	_, _, err := Open(bytes.NewReader(raw), key)
	if err == nil {
		t.Fatal("corrupted vault decrypted without error; tamper detection failed")
	}
}

func TestTruncatedVault(t *testing.T) {
	key := testKey(t)
	contents := map[string][]byte{"a.txt": bytes.Repeat([]byte("x"), 4096)}
	m := buildManifest(t, contents)
	var buf bytes.Buffer
	if err := Seal(m, contents, key, &buf); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	raw := buf.Bytes()[:buf.Len()/2]
	_, _, err := Open(bytes.NewReader(raw), key)
	if err == nil {
		t.Fatal("truncated vault opened without error")
	}
}

func TestMissingContent(t *testing.T) {
	key := testKey(t)
	m := buildManifest(t, map[string][]byte{"a.txt": []byte("x")})
	var buf bytes.Buffer
	err := Seal(m, map[string][]byte{}, key, &buf)
	if err == nil {
		t.Fatal("Seal accepted manifest entry without content")
	}
}
