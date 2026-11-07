package cli

import (
	"github.com/spf13/cobra"

	"github.com/imarey96/drifter/pkg/drifterr"
	"github.com/imarey96/drifter/pkg/engine"
	"github.com/imarey96/drifter/pkg/render"
)

func newDiffCmd(g *globalOpts) *cobra.Command {
	var workspace string
	var showIgnored bool
	cmd := &cobra.Command{
		Use:   "diff [resource]",
		Short: "Show attribute-level differences for drifted resources",
		Long: `Shows, for each matching resource, which attributes changed outside IaC
(last applied state → live) and how live infrastructure differs from the
.tf configuration (live → code). Reads results from the last scan.

The resource argument accepts '*' wildcards. Omit it to show everything.`,
		Example: `  drifter diff aws_security_group.web
  drifter diff 'module.network.*'
  drifter diff --workspace envs/prod --json`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := g.resolveFormat("table")
			if err != nil {
				return err
			}
			r, err := loadReport(g)
			if err != nil {
				return err
			}
			pattern := ""
			if len(args) == 1 {
				pattern = args[0]
			}
			items := r.Find(pattern, workspace, showIgnored)
			if len(items) == 0 {
				if pattern == "" {
					return drifterr.New(drifterr.CodeInvalidInput, "no drifted resources in the last scan", "")
				}
				return drifterr.New(drifterr.CodeInvalidInput, "no drifted resource matches "+pattern,
					"run `drifter scan` to list drifted addresses, or add --show-ignored")
			}

			out := cmd.OutOrStdout()
			switch format {
			case "json":
				return render.JSON(out, items)
			case "markdown":
				return render.Markdown(out, subset(r, items), render.MarkdownOptions{ShowIgnored: showIgnored})
			}
			render.Terminal{W: out}.Diff(items)
			return nil
		},
	}
	cmd.Flags().StringVarP(&workspace, "workspace", "w", "", "only show resources from this workspace path")
	cmd.Flags().BoolVar(&showIgnored, "show-ignored", false, "include ignored resources")
	return cmd
}

// subset builds a report containing only the given resources.
func subset(r *engine.Report, items []engine.Located) *engine.Report {
	byWS := map[string][]engine.ResourceDrift{}
	for _, it := range items {
		byWS[it.Workspace] = append(byWS[it.Workspace], it.Resource)
	}
	out := &engine.Report{SchemaVersion: r.SchemaVersion, GeneratedAt: r.GeneratedAt}
	for _, ws := range r.Workspaces {
		if res, ok := byWS[ws.Path]; ok {
			ws.Resources = res
			out.Workspaces = append(out.Workspaces, ws)
		}
	}
	out.Summarize()
	return out
}
