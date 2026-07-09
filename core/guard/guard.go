// Package guard is the detection layer: it verifies gitignore coverage and
// scans staged content so plaintext secrets cannot slip into a commit
// unnoticed. It is a safety net, not a guarantee (SECURITY.md threat model).
package guard

import (
	"strings"

	"github.com/trieup/keyfarer/core/config"
	"github.com/trieup/keyfarer/core/gitx"
	"github.com/trieup/keyfarer/core/manifest"
	"github.com/trieup/keyfarer/core/secrets"
)

// Violation is one reason a commit must be blocked or a setup issue surfaced.
type Violation struct {
	// Code identifies the rule, e.g. GUARD_STAGED_SECRET_PATH.
	Code string `json:"code"`
	// Path is the offending repo-relative path, when applicable.
	Path string `json:"path,omitempty"`
	// Message explains what is wrong and how to fix it. It never contains
	// secret values.
	Message string `json:"message"`
	// Blocking violations fail the pre-commit hook; advisory ones only warn.
	Blocking bool `json:"blocking"`
}

// CheckSetup verifies the repository's protective configuration: gitignore
// coverage for the keyfarer dir and every registered plaintext path.
func CheckSetup(root string, cfg *config.Config) []Violation {
	var vs []Violation
	if !gitx.IsIgnored(root, config.Dir+"/") {
		vs = append(vs, Violation{
			Code:     "GUARD_KEYFARER_DIR_NOT_IGNORED",
			Path:     config.Dir,
			Message:  ".keyfarer/ is not gitignored. Fix: run `keyfarer init` again or add `.keyfarer/` to .gitignore.",
			Blocking: true,
		})
	}
	for _, f := range cfg.Files {
		if strings.HasPrefix(f.Path, config.Dir+"/") {
			continue // covered by the directory rule above
		}
		if !gitx.IsIgnored(root, f.Path) {
			vs = append(vs, Violation{
				Code:     "GUARD_SECRET_NOT_IGNORED",
				Path:     f.Path,
				Message:  "managed secret file " + f.Path + " is not gitignored. Fix: add it to .gitignore (keyfarer add does this automatically).",
				Blocking: true,
			})
		}
	}
	return vs
}

// CheckStaged scans the git index for managed secrets:
//  1. a staged path that IS a managed secret file,
//  2. a staged blob whose whole content hash equals a managed file's hash,
//  3. a staged blob containing a token whose hash equals a managed value's
//     hash (catches an agent pasting an API key into code).
//
// Hash comparison means the check needs no vault key and no secret values.
func CheckStaged(root string, cfg *config.Config, st *secrets.State) ([]Violation, error) {
	staged, err := gitx.StagedFiles(root)
	if err != nil {
		return nil, err
	}
	if len(staged) == 0 {
		return nil, nil
	}

	managedPaths := map[string]bool{}
	for _, f := range cfg.Files {
		managedPaths[f.Path] = true
	}
	valueHashes := map[string]string{} // sha256 -> descriptive name
	if st != nil {
		for _, f := range st.Files {
			valueHashes[f.SHA256] = "content of managed file " + f.Path
		}
		for _, e := range st.Env {
			valueHashes[e.SHA256] = "value of managed secret " + e.Key
		}
	}

	var vs []Violation
	for _, path := range staged {
		if managedPaths[path] || strings.HasPrefix(path, config.Dir+"/") {
			vs = append(vs, Violation{
				Code:     "GUARD_STAGED_SECRET_PATH",
				Path:     path,
				Message:  path + " is a managed secret and must never be committed. Fix: `git restore --staged " + path + "`.",
				Blocking: true,
			})
			continue
		}
		if len(valueHashes) == 0 {
			continue
		}
		content, err := gitx.StagedContent(root, path)
		if err != nil {
			continue // e.g. submodule entries; path check above already ran
		}
		if name, ok := valueHashes[manifest.HashBytes(content)]; ok {
			vs = append(vs, Violation{
				Code:     "GUARD_STAGED_SECRET_COPY",
				Path:     path,
				Message:  path + " is byte-identical to the " + name + ". Fix: `git restore --staged " + path + "` and delete the copy.",
				Blocking: true,
			})
			continue
		}
		if name, ok := containsSecretToken(content, valueHashes); ok {
			vs = append(vs, Violation{
				Code:     "GUARD_STAGED_SECRET_VALUE",
				Path:     path,
				Message:  path + " contains the " + name + ". Fix: `git restore --staged " + path + "`, remove the value, and rotate the secret if it was ever pushed.",
				Blocking: true,
			})
		}
	}

	if st == nil {
		vs = append(vs, Violation{
			Code:     "GUARD_NO_LOCAL_STATE",
			Message:  "no local keyfarer state; content scanning is degraded to path checks. Fix: run `keyfarer restore`.",
			Blocking: false,
		})
	}
	return vs, nil
}

// containsSecretToken tokenizes text the way secrets appear in code (split on
// quotes, whitespace, separators) and hash-compares each candidate token, so
// exact pasted values are caught without the guard ever holding plaintext.
func containsSecretToken(content []byte, valueHashes map[string]string) (string, bool) {
	if len(content) > 4<<20 { // skip huge blobs; hash check above still ran
		return "", false
	}
	tokens := strings.FieldsFunc(string(content), func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', '"', '\'', '`', '=', ',', ';', '(', ')', '[', ']', '{', '}', '<', '>':
			return true
		}
		return false
	})
	for _, tok := range tokens {
		if len(tok) < 8 {
			continue // too short to be a credential; avoids hashing noise
		}
		if name, ok := valueHashes[manifest.HashBytes([]byte(tok))]; ok {
			return name, true
		}
	}
	return "", false
}

// Blocking reports whether any violation must fail the commit.
func Blocking(vs []Violation) bool {
	for _, v := range vs {
		if v.Blocking {
			return true
		}
	}
	return false
}
