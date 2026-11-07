// Package cli wires the drifter commands to the engine.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/spf13/cobra"

	"github.com/imarey96/drifter/pkg/drifterr"
	"github.com/imarey96/drifter/pkg/ignore"
)

// Exit codes mirror `terraform plan -detailed-exitcode`.
const (
	ExitOK    = 0
	ExitError = 1
	ExitDrift = 2
)

var version = "dev"

// exitError ends the process with a code without printing anything further;
// the command has already written its output.
type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit %d", e.code) }

type globalOpts struct {
	format     string
	json       bool
	markdown   bool
	noColor    bool
	ignoreFile string
	cacheFile  string
}

func newRoot() *cobra.Command {
	g := &globalOpts{}
	root := &cobra.Command{
		Use:   "drifter",
		Short: "Detect, classify, and report infrastructure drift in Terraform and OpenTofu projects",
		Long: `drifter runs read-only plans against live infrastructure and reports
resources that changed outside IaC (out-of-band) or whose code was never
applied (unapplied).

Exit codes: 0 no drift, 1 error, 2 drift detected.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			if g.noColor {
				lipgloss.SetColorProfile(termenv.Ascii)
			}
		},
	}
	pf := root.PersistentFlags()
	pf.StringVar(&g.format, "format", "", "output format: table, json, markdown")
	pf.BoolVar(&g.json, "json", false, "shorthand for --format json")
	pf.BoolVar(&g.markdown, "markdown", false, "shorthand for --format markdown")
	pf.BoolVar(&g.noColor, "no-color", false, "disable coloured output (NO_COLOR is also honoured)")
	pf.StringVar(&g.ignoreFile, "ignore-file", ignore.DefaultFile, "path to the ignore rules file")
	pf.StringVar(&g.cacheFile, "cache-file", defaultCacheFile, "where scan results are stored for diff and report")

	root.AddCommand(newScanCmd(g), newDiffCmd(g), newIgnoreCmd(g), newReportCmd(g))
	return root
}

func (g *globalOpts) resolveFormat(def string) (string, error) {
	f := g.format
	switch {
	case g.json && g.markdown:
		return "", drifterr.New(drifterr.CodeInvalidInput, "--json and --markdown are mutually exclusive", "")
	case g.json:
		f = "json"
	case g.markdown:
		f = "markdown"
	case f == "":
		f = def
	}
	switch f {
	case "table", "json", "markdown":
		return f, nil
	case "md":
		return "markdown", nil
	}
	return "", drifterr.New(drifterr.CodeInvalidInput, fmt.Sprintf("unknown format %q", f), "use table, json, or markdown")
}

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	err := newRoot().Execute()
	if err == nil {
		return ExitOK
	}
	var ee exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	printError(os.Stderr, err)
	return ExitError
}

func printError(w io.Writer, err error) {
	r := lipgloss.NewRenderer(w)
	red := r.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#B42318", Dark: "#F97066"}).Bold(true)
	blue := r.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#175CD3", Dark: "#53B1FD"})
	dim := r.NewStyle().Faint(true)

	de, ok := drifterr.As(err)
	if !ok {
		fmt.Fprintf(w, "%s %v\n", red.Render("error:"), err)
		return
	}
	fmt.Fprintf(w, "%s %s\n", red.Render("error:"), de.Error())
	if de.Detail != "" {
		for _, l := range strings.Split(de.Detail, "\n") {
			fmt.Fprintln(w, dim.Render("  "+l))
		}
	}
	if de.Hint != "" {
		fmt.Fprintf(w, "%s %s\n", blue.Render("hint:"), de.Hint)
	}
}
