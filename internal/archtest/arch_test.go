// Package archtest mechanically enforces the architecture rules documented in
// ARCHITECTURE.md and docs/design-docs/golden-principles.md. Failure messages
// include remediation instructions on purpose: a failing check must tell the
// agent how to fix it.
package archtest

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

type goFile struct {
	path    string // repo-relative
	pkgDir  string // repo-relative dir, e.g. core/vault
	imports []string
	lines   int
	source  string
	isTest  bool
}

func parseAll(t *testing.T) []goFile {
	t.Helper()
	root := repoRoot(t)
	var files []goFile
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "bin" || name == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, src, parser.ImportsOnly)
		if err != nil {
			return fmt.Errorf("parse %s: %w", rel, err)
		}
		gf := goFile{
			path:   rel,
			pkgDir: filepath.ToSlash(filepath.Dir(rel)),
			lines:  strings.Count(string(src), "\n") + 1,
			source: string(src),
			isTest: strings.HasSuffix(rel, "_test.go"),
		}
		for _, imp := range f.Imports {
			gf.imports = append(gf.imports, strings.Trim(imp.Path.Value, `"`))
		}
		files = append(files, gf)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// TestCryptoIsolation: only core/vault may import cryptography.
func TestCryptoIsolation(t *testing.T) {
	cryptoPrefixes := []string{"filippo.io/", "crypto/", "golang.org/x/crypto"}
	allowed := map[string]bool{"core/vault": true, "core/manifest": true} // manifest uses crypto/sha256 for hashing
	for _, f := range parseAll(t) {
		if allowed[f.pkgDir] {
			continue
		}
		for _, imp := range f.imports {
			for _, p := range cryptoPrefixes {
				if strings.HasPrefix(imp, p) {
					t.Errorf("[CRYPTO_ISOLATION] %s imports %q.\n"+
						"Why: all cryptography must go through core/vault so the format stays auditable (SECURITY.md).\n"+
						"Fix: call a core/vault function instead of importing crypto primitives directly.\n"+
						"See: docs/design-docs/golden-principles.md rule 1.", f.path, imp)
				}
			}
		}
	}
}

// TestLayerDirection: core packages must not import runtime packages, and the
// dependency direction inside core is types -> persistence -> service.
func TestLayerDirection(t *testing.T) {
	const module = "github.com/trieup/keyfarer/"
	layer := map[string]int{
		"core/manifest":   1,
		"core/config":     1,
		"core/vault":      2,
		"core/gitx":       2,
		"core/keys":         3,
		"core/secrets":    3,
		"core/guard":      3,
		"core/instrument": 3,
		"internal/cli":    4,
		"internal/mcp":    4,
		"cmd/keyfarer":    5,
	}
	for _, f := range parseAll(t) {
		from, ok := layer[f.pkgDir]
		if !ok {
			continue
		}
		for _, imp := range f.imports {
			rel, ok := strings.CutPrefix(imp, module)
			if !ok {
				continue
			}
			to, ok := layer[rel]
			if !ok {
				continue
			}
			if to > from {
				t.Errorf("[LAYER_DIRECTION] %s (layer %d) imports %s (layer %d).\n"+
					"Why: dependencies flow one direction: types -> persistence -> service -> runtime (ARCHITECTURE.md).\n"+
					"Fix: move the shared code down a layer, or invert the dependency.\n"+
					"See: ARCHITECTURE.md layer model.", f.path, from, rel, to)
			}
		}
	}
}

// TestNoPrinting: service and lower layers never print; the runtime layer owns
// all user-visible output.
func TestNoPrinting(t *testing.T) {
	banned := []string{"fmt.Print", "println("}
	for _, f := range parseAll(t) {
		if !strings.HasPrefix(f.pkgDir, "core/") || f.isTest {
			continue
		}
		if f.pkgDir == "core/keys" {
			continue // interactive prompting is this package's documented job
		}
		for _, b := range banned {
			if strings.Contains(f.source, b) {
				t.Errorf("[NO_PRINTING] %s calls %s.\n"+
					"Why: service packages return data and errors; the runtime layer owns output (golden principle 3).\n"+
					"Fix: return the value or error and print it from internal/cli or internal/mcp.\n"+
					"See: docs/design-docs/golden-principles.md rule 3.", f.path, b)
			}
		}
	}
}

// TestFileSize keeps modules legible for agents.
func TestFileSize(t *testing.T) {
	const limit = 400
	for _, f := range parseAll(t) {
		if f.isTest {
			continue
		}
		if f.lines > limit {
			t.Errorf("[FILE_SIZE] %s is %d lines (limit %d).\n"+
				"Why: small files keep the codebase legible for future agent runs.\n"+
				"Fix: split the file by responsibility.\n"+
				"See: docs/design-docs/golden-principles.md rule 6.", f.path, f.lines, limit)
		}
	}
}
