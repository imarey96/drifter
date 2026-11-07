package cli

import (
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/imarey96/drifter/pkg/render"
)

func newReportCmd(g *globalOpts) *cobra.Command {
	var output, title string
	var showIgnored, failOnDrift bool
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Format the last scan as a PR comment or JSON payload",
		Long: `Renders the last scan results. Markdown output is GitHub/GitLab flavoured and
contains a <!-- drifter-report --> marker so CI can update an existing comment.`,
		Example: `  drifter report > drift.md
  drifter report --json --output drift.json
  gh pr comment "$PR" --body-file <(drifter report)`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, err := g.resolveFormat("markdown")
			if err != nil {
				return err
			}
			r, err := loadReport(g)
			if err != nil {
				return err
			}

			var out io.Writer = cmd.OutOrStdout()
			if output != "" {
				f, err := os.Create(output)
				if err != nil {
					return err
				}
				defer f.Close()
				out = f
			}

			switch format {
			case "json":
				err = render.JSON(out, r)
			case "markdown":
				err = render.Markdown(out, r, render.MarkdownOptions{Title: title, ShowIgnored: showIgnored})
			default:
				render.Terminal{W: out, ShowIgnored: showIgnored}.Scan(r)
			}
			if err != nil {
				return err
			}
			if failOnDrift && r.HasDrift() {
				return exitError{ExitDrift}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&output, "output", "o", "", "write to a file instead of stdout")
	f.StringVar(&title, "title", "", "heading for the markdown report")
	f.BoolVar(&showIgnored, "show-ignored", false, "include ignored resources")
	f.BoolVar(&failOnDrift, "fail-on-drift", false, "exit 2 when the report contains drift")
	return cmd
}
