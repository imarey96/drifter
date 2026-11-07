package render

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"

	"github.com/imarey96/drifter/pkg/engine"
)

var (
	styleBold   = lipgloss.NewStyle().Bold(true)
	styleDim    = lipgloss.NewStyle().Faint(true)
	styleRed    = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#B42318", Dark: "#F97066"})
	styleGreen  = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#067647", Dark: "#47CD89"})
	styleYellow = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#B54708", Dark: "#FDB022"})
	styleBlue   = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#175CD3", Dark: "#53B1FD"})
	styleHeader = lipgloss.NewStyle().Bold(true).Faint(true).PaddingRight(2)
	styleCell   = lipgloss.NewStyle().PaddingRight(2)
)

func actionStyle(a engine.Action) lipgloss.Style {
	switch a {
	case engine.ActionAdded:
		return styleGreen
	case engine.ActionDestroyed, engine.ActionReplaced:
		return styleRed
	default:
		return styleYellow
	}
}

// Terminal renders human-readable output. Colours degrade automatically when
// the output is not a TTY or NO_COLOR is set.
type Terminal struct {
	W           io.Writer
	ShowIgnored bool
}

func (t Terminal) Scan(r *engine.Report) {
	for i, ws := range r.Workspaces {
		if i > 0 {
			fmt.Fprintln(t.W)
		}
		t.workspace(ws)
	}
	fmt.Fprintln(t.W)
	line := summaryLine(r.Summary)
	switch {
	case r.Summary.Drifted > 0:
		line = styleYellow.Bold(true).Render(line)
	default:
		line = styleGreen.Bold(true).Render(line)
	}
	fmt.Fprintln(t.W, line)
	if r.Summary.Errors > 0 {
		fmt.Fprintln(t.W, styleRed.Bold(true).Render(fmt.Sprintf("%d workspace%s failed to scan", r.Summary.Errors, plural(r.Summary.Errors))))
	}
}

func (t Terminal) workspace(ws engine.WorkspaceReport) {
	meta := []string{}
	if ws.Engine != "" {
		meta = append(meta, strings.TrimSpace(ws.Engine+" "+ws.EngineVersion))
	}
	meta = append(meta, (time.Duration(ws.DurationMS) * time.Millisecond).Round(100*time.Millisecond).String())
	fmt.Fprintf(t.W, "%s  %s\n", styleBold.Render(ws.Path), styleDim.Render(strings.Join(meta, " · ")))

	if ws.Error != nil {
		t.scanError(ws.Error)
		return
	}

	var rows [][]string
	var actions []engine.Action
	ignored := 0
	for _, rd := range ws.Resources {
		if rd.Ignored {
			ignored++
			if !t.ShowIgnored {
				continue
			}
		}
		status := originLabel(rd.Origin)
		if rd.Ignored {
			status = "ignored"
		}
		rows = append(rows, []string{actionSymbol(rd.Action) + " " + string(rd.Action), status, rd.Address, changedPaths(rd, 3)})
		actions = append(actions, rd.Action)
	}

	if len(rows) == 0 {
		msg := "  no drift"
		if ignored > 0 {
			msg += fmt.Sprintf(" (%d ignored)", ignored)
		}
		fmt.Fprintln(t.W, styleGreen.Render(msg))
		return
	}

	tbl := table.New().
		Border(lipgloss.NormalBorder()).
		BorderTop(false).BorderBottom(false).BorderLeft(false).BorderRight(false).
		BorderColumn(false).BorderHeader(true).
		BorderStyle(styleDim).
		Headers("ACTION", "ORIGIN", "RESOURCE", "ATTRIBUTES").
		Rows(rows...).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == table.HeaderRow {
				return styleHeader
			}
			s := styleCell
			if rows[row][1] == "ignored" {
				return s.Faint(true)
			}
			switch col {
			case 0:
				return s.Inherit(actionStyle(actions[row]))
			case 1:
				if rows[row][1] == "out-of-band" {
					return s.Inherit(styleRed)
				}
				return s.Inherit(styleBlue)
			case 3:
				return s.Faint(true)
			}
			return s
		})
	for _, l := range strings.Split(tbl.Render(), "\n") {
		fmt.Fprintln(t.W, "  "+l)
	}
	if ignored > 0 && !t.ShowIgnored {
		fmt.Fprintln(t.W, styleDim.Render(fmt.Sprintf("  %d ignored by .drifterignore", ignored)))
	}
}

func (t Terminal) scanError(e *engine.ScanError) {
	fmt.Fprintf(t.W, "  %s %s\n", styleRed.Bold(true).Render("error:"), e.Message)
	if e.Detail != "" {
		for _, l := range strings.Split(e.Detail, "\n") {
			fmt.Fprintln(t.W, styleDim.Render("    "+l))
		}
	}
	if e.Hint != "" {
		fmt.Fprintf(t.W, "  %s %s\n", styleBlue.Render("hint:"), e.Hint)
	}
}

// Diff renders attribute-level detail for each resource.
func (t Terminal) Diff(items []engine.Located) {
	for i, it := range items {
		if i > 0 {
			fmt.Fprintln(t.W)
		}
		rd := it.Resource
		head := actionStyle(rd.Action).Bold(true).Render(actionSymbol(rd.Action) + " " + rd.Address)
		fmt.Fprintf(t.W, "%s  %s\n", head, styleDim.Render(it.Workspace))
		desc := fmt.Sprintf("%s · %s", rd.Action, originDescription(rd.Origin))
		if rd.Ignored {
			desc += " · ignored (" + rd.IgnoreRule + ")"
		}
		fmt.Fprintln(t.W, styleDim.Render("  "+desc))

		if len(rd.OutOfBand) > 0 {
			fmt.Fprintln(t.W)
			fmt.Fprintln(t.W, "  "+styleBold.Render("Changed outside IaC")+styleDim.Render("  last applied state → live"))
			t.changes(rd.OutOfBand)
		}
		if len(rd.Planned) > 0 {
			fmt.Fprintln(t.W)
			fmt.Fprintln(t.W, "  "+styleBold.Render("Live vs code")+styleDim.Render("  live → .tf config (what apply would do)"))
			t.changes(rd.Planned)
		}
	}
}

func (t Terminal) changes(cs []engine.AttributeChange) {
	for _, c := range cs {
		sym := changeSymbol(c.Kind)
		var line string
		switch c.Kind {
		case engine.ChangeAdded:
			line = fmt.Sprintf("%s %s: %s", sym, c.Path, formatValue(c.After, c.Unknown, 120))
		case engine.ChangeRemoved:
			line = fmt.Sprintf("%s %s: %s", sym, c.Path, formatValue(c.Before, false, 120))
		default:
			line = fmt.Sprintf("%s %s: %s → %s", sym, c.Path, formatValue(c.Before, false, 60), formatValue(c.After, c.Unknown, 60))
		}
		style := styleYellow
		switch c.Kind {
		case engine.ChangeAdded:
			style = styleGreen
		case engine.ChangeRemoved:
			style = styleRed
		}
		if c.Ignored {
			fmt.Fprintln(t.W, styleDim.Render("    "+line+"  (ignored)"))
			continue
		}
		fmt.Fprintln(t.W, "    "+style.Render(line))
	}
}

func originDescription(o engine.Origin) string {
	switch o {
	case engine.OriginOutOfBand:
		return "changed outside Terraform/OpenTofu"
	case engine.OriginUnapplied:
		return "code differs from live, not yet applied"
	}
	return string(o)
}
