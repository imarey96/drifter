// Package render formats drift reports for terminals, pull requests, and
// machines.
package render

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/imarey96/drifter/pkg/engine"
	"github.com/imarey96/drifter/pkg/redact"
)

// JSON writes v as indented JSON.
func JSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func formatValue(v any, unknown bool, limit int) string {
	if unknown {
		return "(known after apply)"
	}
	var s string
	switch t := v.(type) {
	case nil:
		s = "null"
	case string:
		if t == redact.Sensitive || t == redact.Redacted {
			s = t
		} else {
			s = fmt.Sprintf("%q", t)
		}
	default:
		b, err := json.Marshal(t)
		if err != nil {
			s = fmt.Sprint(t)
		} else {
			s = string(b)
		}
	}
	if limit > 0 && len([]rune(s)) > limit {
		r := []rune(s)
		s = string(r[:limit-1]) + "…"
	}
	return s
}

func changeSymbol(k engine.ChangeKind) string {
	switch k {
	case engine.ChangeAdded:
		return "+"
	case engine.ChangeRemoved:
		return "-"
	default:
		return "~"
	}
}

func actionSymbol(a engine.Action) string {
	switch a {
	case engine.ActionAdded:
		return "+"
	case engine.ActionDestroyed:
		return "-"
	case engine.ActionReplaced:
		return "±"
	default:
		return "~"
	}
}

func originLabel(o engine.Origin) string {
	switch o {
	case engine.OriginOutOfBand:
		return "out-of-band"
	case engine.OriginUnapplied:
		return "unapplied"
	}
	return string(o)
}

// changedPaths lists the non-ignored attribute paths, out-of-band first.
func changedPaths(rd engine.ResourceDrift, limit int) string {
	seen := map[string]bool{}
	var paths []string
	for _, set := range [][]engine.AttributeChange{rd.OutOfBand, rd.Planned} {
		for _, c := range set {
			if c.Ignored || seen[c.Path] {
				continue
			}
			seen[c.Path] = true
			paths = append(paths, c.Path)
		}
	}
	if rd.Action != engine.ActionModified {
		return ""
	}
	if len(paths) > limit {
		return strings.Join(paths[:limit], ", ") + fmt.Sprintf(" +%d more", len(paths)-limit)
	}
	return strings.Join(paths, ", ")
}

func summaryLine(s engine.Summary) string {
	if s.Drifted == 0 {
		scanned := s.Workspaces - s.Errors
		if scanned == 0 {
			return "No workspaces scanned successfully"
		}
		msg := fmt.Sprintf("No drift across %d workspace%s", scanned, plural(scanned))
		if s.Ignored > 0 {
			msg += fmt.Sprintf(" (%d ignored)", s.Ignored)
		}
		return msg
	}
	parts := []string{fmt.Sprintf("%d drifted (%d out-of-band, %d unapplied)", s.Drifted, s.OutOfBand, s.Unapplied)}
	for _, p := range []struct {
		n     int
		label string
	}{{s.Added, "added"}, {s.Modified, "modified"}, {s.Destroyed, "destroyed"}, {s.Replaced, "replaced"}, {s.Ignored, "ignored"}} {
		if p.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", p.n, p.label))
		}
	}
	return strings.Join(parts, " · ")
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
