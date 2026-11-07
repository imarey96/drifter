// Package tfcli implements provider.StateProvider by running the terraform or
// tofu binary against a working directory.
//
// It avoids side effects on the user's checkout where it can: plans run with
// -lock=false and write to a private temp directory that is removed
// afterwards, and uninitialised modules are initialised into a throwaway
// TF_DATA_DIR rather than ./.terraform.
package tfcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/imarey96/drifter/pkg/drifterr"
	"github.com/imarey96/drifter/pkg/hclcheck"
	"github.com/imarey96/drifter/pkg/provider"
	"github.com/imarey96/drifter/pkg/redact"
)

type Provider struct {
	Binary string // absolute path
	Kind   string // "terraform" or "opentofu"
	// Env is the base environment for child processes. Nil means os.Environ().
	Env []string
	// AutoInit initialises modules that have no .terraform directory into a
	// temporary data dir.
	AutoInit bool
	Scrubber *redact.Scrubber
}

// Detect locates a binary. pref is "auto", "terraform", or "tofu".
// Auto prefers terraform and falls back to tofu.
func Detect(pref string) (*Provider, error) {
	var candidates []string
	switch pref {
	case "", "auto":
		candidates = []string{"terraform", "tofu"}
	case "terraform":
		candidates = []string{"terraform"}
	case "tofu", "opentofu":
		candidates = []string{"tofu"}
	default:
		return nil, drifterr.New(drifterr.CodeInvalidInput,
			fmt.Sprintf("unknown engine %q", pref), "use --engine auto, terraform, or tofu")
	}
	for _, c := range candidates {
		if path, err := exec.LookPath(c); err == nil {
			kind := "terraform"
			if c == "tofu" {
				kind = "opentofu"
			}
			return &Provider{Binary: path, Kind: kind}, nil
		}
	}
	return nil, drifterr.New(drifterr.CodeBinaryNotFound,
		fmt.Sprintf("could not find %s on PATH", strings.Join(candidates, " or ")),
		"install Terraform (https://developer.hashicorp.com/terraform/install) or OpenTofu (https://opentofu.org/docs/intro/install/), or pass --plan-file with an existing `show -json` output")
}

func (p *Provider) Name() string { return p.Kind }

func (p *Provider) cmdName() string {
	if p.Kind == "opentofu" {
		return "tofu"
	}
	return "terraform"
}

// Version returns the engine version, e.g. "1.9.5".
func (p *Provider) Version(ctx context.Context) (string, error) {
	out, _, err := p.run(ctx, ".", p.baseEnv(), "version", "-json")
	if err != nil {
		return "", err
	}
	var v struct {
		TerraformVersion string `json:"terraform_version"`
	}
	if err := json.Unmarshal(out, &v); err != nil {
		return "", fmt.Errorf("parse version output: %w", err)
	}
	return v.TerraformVersion, nil
}

func (p *Provider) Plan(ctx context.Context, t provider.Target) (*provider.PlanOutput, error) {
	mod, err := hclcheck.ParseDir(t.Dir)
	if err != nil {
		return nil, drifterr.Wrap(drifterr.CodeInvalidInput, err, "cannot read "+t.Name(), "check that the path exists and is a directory")
	}
	if len(mod.Files) == 0 {
		return nil, drifterr.New(drifterr.CodeInvalidInput, "no .tf or .tf.json files in "+t.Name(),
			"point drifter at a root module directory, or use --recursive")
	}
	if mod.HasErrors() {
		return nil, &drifterr.Error{
			Code:   drifterr.CodeHCLSyntax,
			Msg:    "configuration has syntax errors",
			Hint:   "fix the errors above; `" + p.cmdName() + " validate` shows the same diagnostics",
			Detail: mod.FormatDiags(),
		}
	}

	tmp, err := os.MkdirTemp("", "drifter-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	if err := os.Chmod(tmp, 0o700); err != nil {
		return nil, err
	}

	env := p.baseEnv()
	if t.Workspace != "" {
		env = append(env, "TF_WORKSPACE="+t.Workspace)
	}
	if err := p.ensureInit(ctx, t, tmp, &env); err != nil {
		return nil, err
	}

	planFile := filepath.Join(tmp, "plan.tfplan")
	args := []string{"plan", "-input=false", "-no-color", "-lock=false", "-detailed-exitcode", "-out=" + planFile}
	for _, vf := range t.VarFiles {
		args = append(args, "-var-file="+vf)
	}
	_, stderr, err := p.run(ctx, t.Dir, env, args...)
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 2 {
		err = nil // changes present; expected with -detailed-exitcode
	}
	if err != nil {
		return nil, p.classify(err, stderr)
	}

	planJSON, stderr, err := p.run(ctx, t.Dir, env, "show", "-json", "-no-color", planFile)
	if err != nil {
		return nil, p.classify(err, stderr)
	}
	// The binary plan contains raw sensitive values; drop it immediately.
	_ = os.Remove(planFile)

	ver, _ := p.Version(ctx)
	return &provider.PlanOutput{Engine: p.Kind, EngineVersion: ver, PlanJSON: planJSON}, nil
}

func (p *Provider) ensureInit(ctx context.Context, t provider.Target, tmp string, env *[]string) error {
	if hasEnv(*env, "TF_DATA_DIR") {
		return nil
	}
	if _, err := os.Stat(filepath.Join(t.Dir, ".terraform")); err == nil {
		return nil
	}
	if !p.AutoInit {
		return drifterr.New(drifterr.CodeNotInitialized, t.Name()+" is not initialised",
			fmt.Sprintf("run `%s init` in %s, or drop --no-init to let drifter initialise into a temp dir", p.cmdName(), t.Name()))
	}
	*env = append(*env, "TF_DATA_DIR="+filepath.Join(tmp, "data"))
	args := []string{"init", "-input=false", "-no-color"}
	if _, err := os.Stat(filepath.Join(t.Dir, ".terraform.lock.hcl")); err == nil {
		args = append(args, "-lockfile=readonly")
	}
	if _, stderr, err := p.run(ctx, t.Dir, *env, args...); err != nil {
		de := p.classify(err, stderr)
		if de.Code == drifterr.CodePlanFailed {
			de.Msg = "init failed for " + t.Name()
		}
		return de
	}
	return nil
}

// Variables that could make the child process write secrets to disk or
// stderr, or alter flags behind our back.
var strippedEnv = []string{"TF_LOG", "TF_LOG_PATH", "TF_LOG_CORE", "TF_LOG_PROVIDER", "TF_CLI_ARGS", "TF_CLI_ARGS_plan", "TF_CLI_ARGS_init", "TF_CLI_ARGS_show"}

func (p *Provider) baseEnv() []string {
	src := p.Env
	if src == nil {
		src = os.Environ()
	}
	env := make([]string, 0, len(src)+3)
	for _, kv := range src {
		k, _, _ := strings.Cut(kv, "=")
		drop := false
		for _, s := range strippedEnv {
			if k == s {
				drop = true
				break
			}
		}
		if !drop {
			env = append(env, kv)
		}
	}
	return append(env, "TF_IN_AUTOMATION=1", "TF_INPUT=0", "CHECKPOINT_DISABLE=1")
}

func hasEnv(env []string, key string) bool {
	for _, kv := range env {
		if strings.HasPrefix(kv, key+"=") {
			return true
		}
	}
	return false
}

func (p *Provider) run(ctx context.Context, dir string, env []string, args ...string) ([]byte, string, error) {
	cmd := exec.CommandContext(ctx, p.Binary, args...)
	cmd.Dir = dir
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, "", ctx.Err()
	}
	return stdout.Bytes(), p.Scrubber.String(stderr.String()), err
}
