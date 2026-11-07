package cli

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/imarey96/drifter/pkg/drifterr"
	"github.com/imarey96/drifter/pkg/engine"
	"github.com/imarey96/drifter/pkg/ignore"
)

const defaultCacheFile = ".drifter/last-scan.json"

// saveReport writes an already-redacted report with owner-only permissions.
func saveReport(path string, r *engine.Report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// loadReport reads cached scan results and re-applies the current ignore
// rules, so edits to .drifterignore take effect without a rescan.
func loadReport(g *globalOpts) (*engine.Report, error) {
	b, err := os.ReadFile(g.cacheFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, drifterr.New(drifterr.CodeNoScan, "no scan results found at "+g.cacheFile,
			"run `drifter scan` first, or point --cache-file at a saved scan")
	}
	if err != nil {
		return nil, err
	}
	var r engine.Report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, drifterr.Wrap(drifterr.CodeNoScan, err, "cached scan results are unreadable", "re-run `drifter scan`")
	}
	if r.SchemaVersion != engine.SchemaVersion {
		return nil, drifterr.New(drifterr.CodeNoScan, "cached scan results were written by an incompatible drifter version",
			"re-run `drifter scan`")
	}
	rules, err := ignore.Load(g.ignoreFile)
	if err != nil {
		return nil, drifterr.Wrap(drifterr.CodeInvalidInput, err, "invalid ignore file", "fix or remove "+g.ignoreFile)
	}
	engine.ApplyIgnores(&r, rules)
	return &r, nil
}
