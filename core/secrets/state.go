package secrets

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/trieup/keyfarer/core/config"
	"github.com/trieup/keyfarer/core/manifest"
)

// State is the local, gitignored record of what the sealed vault contains
// (hashes only, never values) plus which files are currently materialized.
// It lets status and guard work without decrypting the vault, and without
// leaking hashes into git history.
type State struct {
	Files        []FileState        `json:"files"`
	Env          []EnvState         `json:"env"`
	Materialized []MaterializedFile `json:"materialized,omitempty"`
	Ephemeral    []EphemeralFile    `json:"ephemeral,omitempty"`
	SealedAt     time.Time          `json:"sealed_at"`
}

type FileState struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type EnvState struct {
	Key    string `json:"key"`
	SHA256 string `json:"sha256"`
}

type MaterializedFile struct {
	Path string    `json:"path"`
	At   time.Time `json:"at"`
}

// EphemeralFile records a secret file materialized for the lifetime of one
// `keyfarer run`, owned by the process PID that created it. The owner deletes it
// when the child exits; if the owner dies first, a later run sweeps it (see
// Project.sweepEphemeral). Keeping this separate from Materialized preserves the
// meaning of Materialized for status and list_secrets.
type EphemeralFile struct {
	Path string    `json:"path"`
	PID  int       `json:"pid"`
	At   time.Time `json:"at"`
}

// StateFromManifest projects a manifest down to hashes.
func StateFromManifest(m *manifest.Manifest) *State {
	s := &State{SealedAt: time.Now().UTC()}
	for _, f := range m.Files {
		s.Files = append(s.Files, FileState{Path: f.Path, SHA256: f.SHA256})
	}
	for _, e := range m.Env {
		s.Env = append(s.Env, EnvState{Key: e.Key, SHA256: e.SHA256})
	}
	return s
}

// LoadState reads the local state file; a missing file yields (nil, nil).
func LoadState(root string) (*State, error) {
	data, err := os.ReadFile(filepath.Join(root, config.StateFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("secrets: read state: %w", err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("secrets: parse state: %w", err)
	}
	return &s, nil
}

// Save writes the state file with owner-only permissions.
func (s *State) Save(root string) error {
	path := filepath.Join(root, config.StateFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("secrets: state dir: %w", err)
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("secrets: encode state: %w", err)
	}
	return os.WriteFile(path, data, 0o600)
}

// FileHash returns the sealed hash for path, or "".
func (s *State) FileHash(path string) string {
	for _, f := range s.Files {
		if f.Path == path {
			return f.SHA256
		}
	}
	return ""
}

// MarkMaterialized records that path exists as plaintext on disk.
func (s *State) MarkMaterialized(path string) {
	for i := range s.Materialized {
		if s.Materialized[i].Path == path {
			s.Materialized[i].At = time.Now().UTC()
			return
		}
	}
	s.Materialized = append(s.Materialized, MaterializedFile{Path: path, At: time.Now().UTC()})
}

// UnmarkMaterialized removes the record for path.
func (s *State) UnmarkMaterialized(path string) {
	for i := range s.Materialized {
		if s.Materialized[i].Path == path {
			s.Materialized = append(s.Materialized[:i], s.Materialized[i+1:]...)
			return
		}
	}
}

// MarkEphemeral records that pid materialized path for the duration of a run.
func (s *State) MarkEphemeral(path string, pid int) {
	for i := range s.Ephemeral {
		if s.Ephemeral[i].Path == path && s.Ephemeral[i].PID == pid {
			s.Ephemeral[i].At = time.Now().UTC()
			return
		}
	}
	s.Ephemeral = append(s.Ephemeral, EphemeralFile{Path: path, PID: pid, At: time.Now().UTC()})
}

// UnmarkEphemeral drops the record for (path, pid).
func (s *State) UnmarkEphemeral(path string, pid int) {
	out := s.Ephemeral[:0]
	for _, e := range s.Ephemeral {
		if e.Path == path && e.PID == pid {
			continue
		}
		out = append(out, e)
	}
	s.Ephemeral = out
}

// OtherLiveOwner reports whether a live process other than pid still claims path.
// Cleanup uses this so concurrent runs do not delete each other's files.
func (s *State) OtherLiveOwner(path string, pid int) bool {
	for _, e := range s.Ephemeral {
		if e.Path == path && e.PID != pid && processAlive(e.PID) {
			return true
		}
	}
	return false
}
