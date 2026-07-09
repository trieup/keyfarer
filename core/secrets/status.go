package secrets

import (
	"os"
	"path/filepath"

	"github.com/trieup/keyfarer/core/manifest"
)

// EntryStatus classifies one managed entry for drift reporting.
type EntryStatus string

const (
	StatusClean       EntryStatus = "clean"        // sealed, plaintext on disk matches
	StatusEncrypted   EntryStatus = "encrypted"    // sealed, no plaintext on disk
	StatusDrifted     EntryStatus = "drifted"      // plaintext on disk differs from sealed copy
	StatusUnsealed    EntryStatus = "unsealed"     // registered + on disk, but never sealed
	StatusMissing     EntryStatus = "missing"      // registered, but in neither vault nor disk
	StatusSealedEnv   EntryStatus = "sealed"       // env entry present in vault
	StatusUnsealedEnv EntryStatus = "unsealed-env" // env key registered but not in vault
)

// EntryReport is the status of one managed entry.
type EntryReport struct {
	Name   string      `json:"name"` // path for files, key for env
	Kind   string      `json:"kind"` // "file" or "env"
	Status EntryStatus `json:"status"`
}

// Report is the full drift report for a project.
type Report struct {
	Entries    []EntryReport `json:"entries"`
	VaultFound bool          `json:"vault_found"`
	// StateFound is false on a fresh clone before restore: statuses are then
	// computed without sealed hashes and drift cannot be detected.
	StateFound bool `json:"state_found"`
}

// Dirty reports whether anything needs sealing or attention.
func (r *Report) Dirty() bool {
	for _, e := range r.Entries {
		switch e.Status {
		case StatusDrifted, StatusUnsealed, StatusMissing, StatusUnsealedEnv:
			return true
		}
	}
	return false
}

// Status computes the drift report from local state, without decrypting the
// vault (so it works in hooks and on locked machines).
func (p *Project) Status() (*Report, error) {
	st, err := LoadState(p.Root)
	if err != nil {
		return nil, err
	}
	rep := &Report{VaultFound: p.VaultExists(), StateFound: st != nil}

	for _, ref := range p.Config.Files {
		full := filepath.Join(p.Root, filepath.FromSlash(ref.Path))
		onDisk := false
		var diskHash string
		if body, err := os.ReadFile(full); err == nil {
			onDisk = true
			diskHash = manifest.HashBytes(body)
		}
		sealedHash := ""
		if st != nil {
			sealedHash = st.FileHash(ref.Path)
		}
		var status EntryStatus
		switch {
		case sealedHash == "" && onDisk:
			status = StatusUnsealed
		case sealedHash == "" && !onDisk:
			status = StatusMissing
		case !onDisk:
			status = StatusEncrypted
		case diskHash == sealedHash:
			status = StatusClean
		default:
			status = StatusDrifted
		}
		rep.Entries = append(rep.Entries, EntryReport{Name: ref.Path, Kind: "file", Status: status})
	}

	for _, ref := range p.Config.Env {
		status := StatusUnsealedEnv
		if st != nil {
			for _, e := range st.Env {
				if e.Key == ref.Key {
					status = StatusSealedEnv
					break
				}
			}
		}
		rep.Entries = append(rep.Entries, EntryReport{Name: ref.Key, Kind: "env", Status: status})
	}
	return rep, nil
}
