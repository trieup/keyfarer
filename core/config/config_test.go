package config

import (
	"errors"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	c := Default()
	if _, err := c.RegisterFile(".keyfarer/secrets/key.p8"); err != nil {
		t.Fatal(err)
	}
	c.RegisterEnv("OPENAI_API_KEY")
	if err := c.Save(dir); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !got.HasFile(".keyfarer/secrets/key.p8") || len(got.Env) != 1 {
		t.Errorf("round trip mismatch: %+v", got)
	}
}

func TestLoadMissing(t *testing.T) {
	if _, err := Load(t.TempDir()); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("want ErrNotInitialized, got %v", err)
	}
}

func TestValidateRelPath(t *testing.T) {
	bad := []string{"", "/etc/passwd", "../outside", "a/../../b", "a\\b", "./a"}
	for _, p := range bad {
		if err := ValidateRelPath(p); err == nil {
			t.Errorf("ValidateRelPath(%q) accepted an unsafe path", p)
		}
	}
	good := []string{".keyfarer/secrets/a.p8", ".env", "config/prod.pem"}
	for _, p := range good {
		if err := ValidateRelPath(p); err != nil {
			t.Errorf("ValidateRelPath(%q) = %v, want nil", p, err)
		}
	}
}

func TestRegisterFileDuplicate(t *testing.T) {
	c := Default()
	added, err := c.RegisterFile("a.pem")
	if err != nil || !added {
		t.Fatalf("first register: %v %v", added, err)
	}
	added, err = c.RegisterFile("a.pem")
	if err != nil || added {
		t.Fatalf("duplicate register should be a no-op: %v %v", added, err)
	}
}
