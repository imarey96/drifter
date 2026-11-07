package tfcli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/imarey96/drifter/pkg/drifterr"
)

type pattern struct {
	code    drifterr.Code
	msg     string
	hint    string
	needles []string
}

var patterns = []pattern{
	{
		code: drifterr.CodeCredentials,
		msg:  "cloud provider credentials are missing or invalid",
		hint: "export credentials for the target account (e.g. AWS_PROFILE, GOOGLE_APPLICATION_CREDENTIALS, ARM_* variables) and retry",
		needles: []string{
			"No valid credential sources found",
			"NoCredentialProviders",
			"Unable to locate credentials",
			"failed to refresh cached credentials",
			"could not find default credentials",
			"ExpiredToken",
			"InvalidClientTokenId",
			"UnrecognizedClientException",
			"building AzureRM Client",
			"Please run 'az login'",
			"Error: configuring Terraform AWS Provider",
		},
	},
	{
		code: drifterr.CodeNotInitialized,
		msg:  "working directory is not initialised or providers are out of date",
		hint: "run `%s init` (or `init -upgrade` if the lock file changed) and retry",
		needles: []string{
			`Run "terraform init"`,
			`Run "tofu init"`,
			"Inconsistent dependency lock file",
			"Backend initialization required",
			"Module not installed",
			"Required plugins are not installed",
		},
	},
	{
		code:    drifterr.CodeConfigInvalid,
		msg:     "a required input variable has no value",
		hint:    "pass values with --var-file, or set TF_VAR_<name> in the environment",
		needles: []string{"No value for required variable"},
	},
	{
		code: drifterr.CodeConfigInvalid,
		msg:  "configuration is invalid",
		hint: "run `%s validate` for full diagnostics",
		needles: []string{
			"Unsupported block type",
			"Unsupported argument",
			"Missing required argument",
			"Reference to undeclared",
			"Invalid reference",
			"Argument or block definition required",
			"Invalid expression",
		},
	},
}

func (p *Provider) classify(err error, stderr string) *drifterr.Error {
	if errors.Is(err, context.DeadlineExceeded) {
		return drifterr.Wrap(drifterr.CodePlanFailed, err, "plan timed out", "raise --timeout or scan fewer workspaces at once")
	}
	if errors.Is(err, context.Canceled) {
		return drifterr.Wrap(drifterr.CodePlanFailed, err, "plan cancelled", "")
	}
	detail := extractDiagnostics(stderr)
	for _, pt := range patterns {
		for _, n := range pt.needles {
			if strings.Contains(stderr, n) {
				hint := pt.hint
				if strings.Contains(hint, "%s") {
					hint = fmt.Sprintf(hint, p.cmdName())
				}
				return &drifterr.Error{Code: pt.code, Msg: pt.msg, Hint: hint, Detail: detail}
			}
		}
	}
	return &drifterr.Error{
		Code:   drifterr.CodePlanFailed,
		Msg:    p.cmdName() + " plan failed",
		Hint:   "see the output above; re-run the plan by hand to debug",
		Detail: detail,
	}
}

// extractDiagnostics keeps the "Error:" blocks from stderr, which is where
// terraform puts actionable output, capped to a readable length.
func extractDiagnostics(stderr string) string {
	const maxLines = 40
	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	var out []string
	inErr := false
	for _, l := range lines {
		trimmed := strings.TrimLeft(l, "│╷╵ ")
		if strings.HasPrefix(trimmed, "Error:") {
			inErr = true
		}
		if inErr {
			out = append(out, strings.TrimRight(trimmed, " "))
		}
		if len(out) >= maxLines {
			out = append(out, "…")
			break
		}
	}
	if len(out) == 0 {
		// No structured diagnostics; fall back to the tail.
		if len(lines) > maxLines {
			lines = lines[len(lines)-maxLines:]
		}
		out = lines
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}
