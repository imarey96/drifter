package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"github.com/imarey96/drifter/pkg/drifterr"
	"github.com/imarey96/drifter/pkg/engine"
	"github.com/imarey96/drifter/pkg/hclcheck"
	"github.com/imarey96/drifter/pkg/ignore"
	"github.com/imarey96/drifter/pkg/provider"
	"github.com/imarey96/drifter/pkg/provider/tfcli"
	"github.com/imarey96/drifter/pkg/redact"
	"github.com/imarey96/drifter/pkg/render"
)

type scanOpts struct {
	recursive   bool
	engineName  string
	parallel    int
	noInit      bool
	timeout     time.Duration
	varFiles    []string
	workspace   string
	planFile    string
	showIgnored bool
	noCache     bool
	exitZero    bool
}

func newScanCmd(g *globalOpts) *cobra.Command {
	o := &scanOpts{}
	cmd := &cobra.Command{
		Use:   "scan [path...]",
		Short: "Run read-only plans and detect drift",
		Long: `Runs plan with -lock=false -detailed-exitcode against each root module and
classifies every changed resource. Plans are written to a private temp
directory and deleted afterwards; uninitialised modules are initialised into
a temporary data dir so ./.terraform is left untouched.

Results are cached for 'drifter diff' and 'drifter report'.`,
		Example: `  drifter scan
  drifter scan ./envs --recursive --parallel 8
  drifter scan --json > drift.json
  terraform show -json plan.out > plan.json && drifter scan --plan-file plan.json`,
		RunE: func(cmd *cobra.Command, args []string) error { return runScan(cmd, g, o, args) },
	}
	f := cmd.Flags()
	f.BoolVarP(&o.recursive, "recursive", "r", false, "discover root modules below each path")
	f.StringVar(&o.engineName, "engine", "auto", "IaC binary: auto, terraform, tofu")
	f.IntVarP(&o.parallel, "parallel", "p", 4, "maximum concurrent plans")
	f.BoolVar(&o.noInit, "no-init", false, "fail instead of initialising uninitialised modules")
	f.DurationVar(&o.timeout, "timeout", 30*time.Minute, "overall scan timeout")
	f.StringArrayVar(&o.varFiles, "var-file", nil, "pass -var-file to plan (repeatable)")
	f.StringVar(&o.workspace, "workspace", "", "terraform workspace to plan (sets TF_WORKSPACE)")
	f.StringVar(&o.planFile, "plan-file", "", "analyse an existing `show -json` plan instead of running a plan")
	f.BoolVar(&o.showIgnored, "show-ignored", false, "include ignored resources in output")
	f.BoolVar(&o.noCache, "no-cache", false, "do not save results for diff/report")
	f.BoolVar(&o.exitZero, "exit-zero", false, "exit 0 even when drift is found")
	return cmd
}

func runScan(cmd *cobra.Command, g *globalOpts, o *scanOpts, args []string) error {
	format, err := g.resolveFormat("table")
	if err != nil {
		return err
	}
	if len(args) == 0 {
		args = []string{"."}
	}

	rules, err := ignore.Load(g.ignoreFile)
	if err != nil {
		return drifterr.Wrap(drifterr.CodeInvalidInput, err, "invalid ignore file", "fix or remove "+g.ignoreFile)
	}

	scrubber := redact.FromEnv(os.Environ())
	var prov provider.StateProvider
	var targets []provider.Target
	if o.planFile != "" {
		prov = provider.FileProvider{Path: o.planFile}
		targets = []provider.Target{{Dir: ".", Label: o.planFile}}
	} else {
		tp, err := tfcli.Detect(o.engineName)
		if err != nil {
			return err
		}
		tp.AutoInit = !o.noInit
		tp.Scrubber = scrubber
		prov = tp
		if targets, err = resolveTargets(args, o); err != nil {
			return err
		}
	}

	ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, o.timeout)
	defer cancelTimeout()

	eng := &engine.Engine{Provider: prov, Rules: rules, Scrubber: scrubber, Parallelism: o.parallel}
	if format == "table" && isatty.IsTerminal(os.Stderr.Fd()) {
		eng.OnDone = progressPrinter(len(targets), prov.Name())
	}

	report, err := eng.Scan(ctx, targets)
	if err != nil {
		return drifterr.Wrap(drifterr.CodePlanFailed, err, "scan aborted", "")
	}

	if !o.noCache {
		if err := saveReport(g.cacheFile, report); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not save scan results: %v\n", err)
		}
	}

	out := cmd.OutOrStdout()
	switch format {
	case "json":
		err = render.JSON(out, report)
	case "markdown":
		err = render.Markdown(out, report, render.MarkdownOptions{ShowIgnored: o.showIgnored})
	default:
		render.Terminal{W: out, ShowIgnored: o.showIgnored}.Scan(report)
	}
	if err != nil {
		return err
	}
	return scanExit(report, o.exitZero)
}

func scanExit(r *engine.Report, exitZero bool) error {
	switch {
	case r.HasErrors():
		return exitError{ExitError}
	case r.HasDrift() && !exitZero:
		return exitError{ExitDrift}
	}
	return nil
}

func resolveTargets(args []string, o *scanOpts) ([]provider.Target, error) {
	cwd, _ := os.Getwd()
	var dirs []string
	for _, a := range args {
		info, err := os.Stat(a)
		if err != nil || !info.IsDir() {
			return nil, drifterr.New(drifterr.CodeInvalidInput, a+" is not a directory", "pass the path to a root module")
		}
		if !o.recursive {
			dirs = append(dirs, a)
			continue
		}
		found, err := hclcheck.DiscoverRoots(a)
		if err != nil {
			return nil, err
		}
		dirs = append(dirs, found...)
	}
	if len(dirs) == 0 {
		return nil, drifterr.New(drifterr.CodeInvalidInput, "no root modules found",
			"root modules are detected by a backend block, .terraform.lock.hcl, or .terraform directory")
	}

	seen := map[string]bool{}
	var targets []provider.Target
	for _, d := range dirs {
		abs, err := filepath.Abs(d)
		if err != nil || seen[abs] {
			continue
		}
		seen[abs] = true
		label, err := filepath.Rel(cwd, abs)
		if err != nil {
			label = abs
		}
		targets = append(targets, provider.Target{Dir: abs, Label: label, VarFiles: o.varFiles, Workspace: o.workspace})
	}
	return targets, nil
}

func progressPrinter(total int, engineName string) func(engine.WorkspaceReport) {
	r := lipgloss.NewRenderer(os.Stderr)
	dim := r.NewStyle().Faint(true)
	ok := r.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#067647", Dark: "#47CD89"})
	bad := r.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#B42318", Dark: "#F97066"})

	fmt.Fprintln(os.Stderr, dim.Render(fmt.Sprintf("Scanning %d workspace%s with %s…", total, map[bool]string{true: "", false: "s"}[total == 1], engineName)))
	var mu sync.Mutex
	done := 0
	return func(ws engine.WorkspaceReport) {
		mu.Lock()
		defer mu.Unlock()
		done++
		mark := ok.Render("✓")
		if ws.Error != nil {
			mark = bad.Render("✗")
		}
		fmt.Fprintf(os.Stderr, "%s %s %s\n", mark, ws.Path, dim.Render(fmt.Sprintf("[%d/%d]", done, total)))
		if done == total {
			fmt.Fprintln(os.Stderr)
		}
	}
}
