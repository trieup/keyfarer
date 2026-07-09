// Package manifest defines the vault manifest: the typed index of every secret
// stored in a keyfarer vault. It sits in the Types layer and imports only stdlib.
package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Version is the current manifest schema version. Readers must reject unknown
// versions rather than guessing.
const Version = 1

var ErrUnsupportedVersion = errors.New("manifest: unsupported version")

// FileEntry describes one managed secret file, byte exact.
type FileEntry struct {
	Path   string    `json:"path"`
	SHA256 string    `json:"sha256"`
	Mode   uint32    `json:"mode"`
	MTime  time.Time `json:"mtime"`
	Size   int64     `json:"size"`
}

// EnvEntry describes one key/value secret that never needs to exist as a file.
// The value lives only inside the encrypted vault.
type EnvEntry struct {
	Key    string `json:"key"`
	SHA256 string `json:"sha256"`
	Value  string `json:"value"`
}

// Manifest indexes everything inside a vault.
type Manifest struct {
	Version   int         `json:"version"`
	CreatedAt time.Time   `json:"created_at"`
	Files     []FileEntry `json:"files"`
	Env       []EnvEntry  `json:"env"`
}

func New() *Manifest {
	return &Manifest{Version: Version, CreatedAt: time.Now().UTC()}
}

// Decode parses and validates a manifest from r.
func Decode(r io.Reader) (*Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(r)
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest: decode: %w", err)
	}
	if m.Version != Version {
		return nil, fmt.Errorf("%w: %d (this build understands %d)", ErrUnsupportedVersion, m.Version, Version)
	}
	return &m, nil
}

func (m *Manifest) Encode(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(m)
}

// HashBytes returns the hex SHA256 of b, the hash format used everywhere in
// keyfarer (manifest entries, guard matching, drift detection).
func HashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// File returns the entry for path, or nil.
func (m *Manifest) File(path string) *FileEntry {
	for i := range m.Files {
		if m.Files[i].Path == path {
			return &m.Files[i]
		}
	}
	return nil
}

// EnvVar returns the entry for key, or nil.
func (m *Manifest) EnvVar(key string) *EnvEntry {
	for i := range m.Env {
		if m.Env[i].Key == key {
			return &m.Env[i]
		}
	}
	return nil
}

// SetFile inserts or replaces the entry for e.Path.
func (m *Manifest) SetFile(e FileEntry) {
	if existing := m.File(e.Path); existing != nil {
		*existing = e
		return
	}
	m.Files = append(m.Files, e)
}

// SetEnv inserts or replaces the entry for e.Key.
func (m *Manifest) SetEnv(e EnvEntry) {
	if existing := m.EnvVar(e.Key); existing != nil {
		*existing = e
		return
	}
	m.Env = append(m.Env, e)
}

// RemoveFile deletes the entry for path, reporting whether it existed.
func (m *Manifest) RemoveFile(path string) bool {
	for i := range m.Files {
		if m.Files[i].Path == path {
			m.Files = append(m.Files[:i], m.Files[i+1:]...)
			return true
		}
	}
	return false
}

// RemoveEnv deletes the entry for key, reporting whether it existed.
func (m *Manifest) RemoveEnv(key string) bool {
	for i := range m.Env {
		if m.Env[i].Key == key {
			m.Env = append(m.Env[:i], m.Env[i+1:]...)
			return true
		}
	}
	return false
}
