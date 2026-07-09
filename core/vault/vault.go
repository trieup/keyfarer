// Package vault implements the on-disk format of keyfarer.vault:
// tar -> gzip -> age (X25519 identity). This is the ONLY package in the
// module allowed to touch cryptography (enforced by internal/archtest).
// Format spec: docs/design-docs/vault-format.md.
package vault

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"

	"github.com/trieup/keyfarer/core/config"
	"github.com/trieup/keyfarer/core/manifest"
)

// manifestName is always the first tar entry so readers can stream the index
// without extracting file bodies.
const manifestName = "keyfarer-manifest.json"

// filePrefix namespaces managed file bodies inside the tar archive.
const filePrefix = "files/"

var (
	ErrWrongKey   = errors.New("vault: wrong key or corrupted vault")
	ErrMalformed  = errors.New("vault: malformed archive")
	ErrUnsafePath = errors.New("vault: entry path is unsafe")
	ErrInvalidKey = errors.New("vault: not a valid age X25519 identity")
)

// GenerateKey creates a random X25519 age identity string (AGE-SECRET-KEY-1...).
func GenerateKey() (string, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return "", fmt.Errorf("vault: generate key: %w", err)
	}
	return identity.String(), nil
}

// ValidateKey checks that s is a valid age X25519 identity string.
func ValidateKey(s string) error {
	if _, err := age.ParseX25519Identity(strings.TrimSpace(s)); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	return nil
}

// Seal writes an encrypted vault containing m and the file bodies in contents
// (keyed by repo-relative path, matching m.Files). key is an age identity
// string (AGE-SECRET-KEY-1...).
func Seal(m *manifest.Manifest, contents map[string][]byte, key string, w io.Writer) error {
	identity, err := age.ParseX25519Identity(key)
	if err != nil {
		return fmt.Errorf("vault: identity: %w", err)
	}
	recipient := identity.Recipient()

	encw, err := age.Encrypt(w, recipient)
	if err != nil {
		return fmt.Errorf("vault: encrypt: %w", err)
	}
	gz := gzip.NewWriter(encw)
	tw := tar.NewWriter(gz)

	var mbuf bytes.Buffer
	if err := m.Encode(&mbuf); err != nil {
		return err
	}
	if err := writeEntry(tw, manifestName, 0o600, mbuf.Bytes()); err != nil {
		return err
	}
	for _, fe := range m.Files {
		body, ok := contents[fe.Path]
		if !ok {
			return fmt.Errorf("vault: no content provided for manifest entry %q", fe.Path)
		}
		if err := writeEntry(tw, filePrefix+fe.Path, int64(fe.Mode), body); err != nil {
			return err
		}
	}

	for _, c := range []io.Closer{tw, gz, encw} {
		if err := c.Close(); err != nil {
			return fmt.Errorf("vault: finalize: %w", err)
		}
	}
	return nil
}

func writeEntry(tw *tar.Writer, name string, mode int64, body []byte) error {
	hdr := &tar.Header{Name: name, Mode: mode, Size: int64(len(body)), Format: tar.FormatPAX}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("vault: write header %q: %w", name, err)
	}
	if _, err := tw.Write(body); err != nil {
		return fmt.Errorf("vault: write body %q: %w", name, err)
	}
	return nil
}

// Open decrypts a vault and returns its manifest and file bodies keyed by
// repo-relative path. key is an age identity string (AGE-SECRET-KEY-1...).
// Entry paths are validated against traversal before use.
func Open(r io.Reader, key string) (*manifest.Manifest, map[string][]byte, error) {
	identity, err := age.ParseX25519Identity(key)
	if err != nil {
		return nil, nil, fmt.Errorf("vault: identity: %w", err)
	}
	decr, err := age.Decrypt(r, identity)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return nil, nil, ErrWrongKey
		}
		return nil, nil, fmt.Errorf("vault: decrypt: %w", err)
	}
	gz, err := gzip.NewReader(decr)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrWrongKey, err)
	}
	tr := tar.NewReader(gz)

	hdr, err := tr.Next()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: empty archive", ErrMalformed)
	}
	if hdr.Name != manifestName {
		return nil, nil, fmt.Errorf("%w: first entry is %q, want %q", ErrMalformed, hdr.Name, manifestName)
	}
	m, err := manifest.Decode(tr)
	if err != nil {
		return nil, nil, err
	}

	contents := make(map[string][]byte, len(m.Files))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// A decryption error surfacing mid-stream means tampering: age
			// authenticates chunks as they are read.
			return nil, nil, fmt.Errorf("%w: %v", ErrWrongKey, err)
		}
		rel, ok := strings.CutPrefix(hdr.Name, filePrefix)
		if !ok {
			return nil, nil, fmt.Errorf("%w: unexpected entry %q", ErrMalformed, hdr.Name)
		}
		if err := config.ValidateRelPath(rel); err != nil {
			return nil, nil, fmt.Errorf("%w: %q", ErrUnsafePath, hdr.Name)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrWrongKey, err)
		}
		contents[rel] = body
	}

	for _, fe := range m.Files {
		if _, ok := contents[fe.Path]; !ok {
			return nil, nil, fmt.Errorf("%w: manifest lists %q but archive has no body", ErrMalformed, fe.Path)
		}
	}
	return m, contents, nil
}
