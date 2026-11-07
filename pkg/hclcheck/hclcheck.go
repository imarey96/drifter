// Package hclcheck parses Terraform/OpenTofu configuration natively so syntax
// errors are reported with file and line before any plan runs, and so root
// modules can be discovered without invoking a binary.
package hclcheck

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
)

// Module is the result of parsing one directory of configuration.
type Module struct {
	Dir   string
	Files []string
	// HasBackend is true when a terraform block declares a backend or cloud block.
	HasBackend bool
	Diags      hcl.Diagnostics
}

func (m *Module) HasErrors() bool { return m.Diags.HasErrors() }

// FormatDiags renders error diagnostics as "file:line: summary: detail" lines.
func (m *Module) FormatDiags() string {
	var b strings.Builder
	for _, d := range m.Diags {
		if d.Severity != hcl.DiagError {
			continue
		}
		loc := ""
		if d.Subject != nil {
			rel, err := filepath.Rel(m.Dir, d.Subject.Filename)
			if err != nil {
				rel = d.Subject.Filename
			}
			loc = fmt.Sprintf("%s:%d: ", rel, d.Subject.Start.Line)
		}
		fmt.Fprintf(&b, "%s%s", loc, d.Summary)
		if d.Detail != "" {
			fmt.Fprintf(&b, ": %s", d.Detail)
		}
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

var terraformSchema = &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "terraform"}}}

var backendSchema = &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{
	{Type: "backend", LabelNames: []string{"type"}},
	{Type: "cloud"},
}}

// ParseDir parses every *.tf and *.tf.json file directly inside dir.
func ParseDir(dir string) (*Module, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	m := &Module{Dir: dir}
	p := hclparse.NewParser()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		path := filepath.Join(dir, name)
		var f *hcl.File
		var diags hcl.Diagnostics
		switch {
		case strings.HasSuffix(name, ".tf"):
			f, diags = p.ParseHCLFile(path)
		case strings.HasSuffix(name, ".tf.json"):
			f, diags = p.ParseJSONFile(path)
		default:
			continue
		}
		m.Files = append(m.Files, name)
		m.Diags = append(m.Diags, diags...)
		if f != nil && !diags.HasErrors() && hasBackend(f.Body) {
			m.HasBackend = true
		}
	}
	return m, nil
}

func hasBackend(body hcl.Body) bool {
	content, _, _ := body.PartialContent(terraformSchema)
	for _, tf := range content.Blocks {
		inner, _, _ := tf.Body.PartialContent(backendSchema)
		if len(inner.Blocks) > 0 {
			return true
		}
	}
	return false
}

var skipDirs = map[string]bool{".terraform": true, ".git": true, ".drifter": true, "node_modules": true}

// DiscoverRoots walks root and returns directories that look like root
// modules: they declare a backend, have a dependency lock file, or have been
// initialised. If none are found and root itself contains configuration,
// root is returned.
func DiscoverRoots(root string) ([]string, error) {
	var roots []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		if path != root && (skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
			return filepath.SkipDir
		}
		if isRoot(path) {
			roots = append(roots, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(roots) == 0 {
		if m, err := ParseDir(root); err == nil && len(m.Files) > 0 {
			roots = []string{root}
		}
	}
	return roots, nil
}

func isRoot(dir string) bool {
	for _, marker := range []string{".terraform.lock.hcl", ".terraform"} {
		if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
			return true
		}
	}
	m, err := ParseDir(dir)
	return err == nil && m.HasBackend
}
