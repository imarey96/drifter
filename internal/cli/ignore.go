package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/imarey96/drifter/pkg/drifterr"
	"github.com/imarey96/drifter/pkg/ignore"
	"github.com/imarey96/drifter/pkg/render"
)

func newIgnoreCmd(g *globalOpts) *cobra.Command {
	var attr, reason string
	var list, remove bool
	cmd := &cobra.Command{
		Use:   "ignore [resource]",
		Short: "Suppress expected drift via .drifterignore",
		Long: `Adds a rule to .drifterignore. Without --attr the whole resource is ignored;
with --attr only that attribute (and anything nested under it) is ignored.
Both accept '*' wildcards.`,
		Example: `  drifter ignore aws_autoscaling_group.web --attr desired_capacity
  drifter ignore '*' --attr tags_all --reason "provider default_tags"
  drifter ignore 'module.monitoring.*'
  drifter ignore --list
  drifter ignore aws_instance.app --remove`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if list {
				rules, err := ignore.Load(g.ignoreFile)
				if err != nil {
					return err
				}
				if g.json {
					return render.JSON(out, rules.List())
				}
				if len(rules.List()) == 0 {
					fmt.Fprintf(out, "no rules in %s\n", g.ignoreFile)
				}
				for _, r := range rules.List() {
					fmt.Fprintln(out, r.String())
				}
				return nil
			}

			if len(args) == 0 {
				return drifterr.New(drifterr.CodeInvalidInput, "missing resource address", "usage: drifter ignore <resource> [--attr path]")
			}
			line := args[0]
			if attr != "" {
				line += ":" + attr
			}
			rule, err := ignore.ParseRule(line)
			if err != nil {
				return drifterr.Wrap(drifterr.CodeInvalidInput, err, "invalid rule", "")
			}

			if remove {
				n, err := ignore.Remove(g.ignoreFile, rule)
				if err != nil {
					return err
				}
				if n == 0 {
					fmt.Fprintf(out, "rule %s not found in %s\n", rule, g.ignoreFile)
				} else {
					fmt.Fprintf(out, "removed %s from %s\n", rule, g.ignoreFile)
				}
				return nil
			}

			added, err := ignore.Append(g.ignoreFile, rule, reason)
			if err != nil {
				return err
			}
			if !added {
				fmt.Fprintf(out, "rule %s already in %s\n", rule, g.ignoreFile)
				return nil
			}
			fmt.Fprintf(out, "added %s to %s\n", rule, g.ignoreFile)
			warnIfUnmatched(g, args[0])
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&attr, "attr", "a", "", "attribute path to ignore, e.g. tags.LastScanned")
	f.StringVar(&reason, "reason", "", "comment written above the rule")
	f.BoolVarP(&list, "list", "l", false, "list current rules")
	f.BoolVar(&remove, "remove", false, "remove the rule instead of adding it")
	return cmd
}

// warnIfUnmatched helps catch typos by checking the pattern against the last scan.
func warnIfUnmatched(g *globalOpts, pattern string) {
	r, err := loadReport(g)
	if err != nil {
		return
	}
	for _, ws := range r.Workspaces {
		for _, rd := range ws.Resources {
			if ignore.MatchAddress(pattern, rd.Address) {
				return
			}
		}
	}
	fmt.Fprintf(os.Stderr, "note: %s matches no resource in the last scan\n", pattern)
}
