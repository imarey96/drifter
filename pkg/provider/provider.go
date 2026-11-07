// Package provider defines the StateProvider abstraction: something that can
// produce a plan document comparing live infrastructure, recorded state, and
// configuration for one root module.
//
// The local CLI uses tfcli.Provider, which shells out to terraform or tofu.
// A stateless worker can supply its own implementation (for example one that
// runs plans in a sandbox, or reads plan JSON uploaded by CI) and reuse the
// engine unchanged.
package provider

import (
	"context"
	"fmt"
	"os"
)

// Target identifies one root module to evaluate.
type Target struct {
	// Dir is the root module directory.
	Dir string
	// Label is how the target is shown in reports (usually a relative path).
	Label    string
	VarFiles []string
	// Workspace selects a terraform workspace. Empty means the current one.
	Workspace string
}

func (t Target) Name() string {
	if t.Label != "" {
		return t.Label
	}
	return t.Dir
}

// PlanOutput is the raw result of evaluating a target.
type PlanOutput struct {
	Engine        string // "terraform", "opentofu", or a custom identifier
	EngineVersion string
	// PlanJSON is the `show -json` document. It may contain sensitive values;
	// callers must not persist it unredacted.
	PlanJSON []byte
}

type StateProvider interface {
	Name() string
	Plan(ctx context.Context, t Target) (*PlanOutput, error)
}

// FileProvider serves a pre-generated plan JSON file for every target. It is
// useful in CI pipelines that already ran `terraform show -json`, and in tests.
type FileProvider struct {
	Path string
}

func (f FileProvider) Name() string { return "plan-file" }

func (f FileProvider) Plan(_ context.Context, _ Target) (*PlanOutput, error) {
	b, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, fmt.Errorf("read plan file: %w", err)
	}
	return &PlanOutput{Engine: "plan-file", PlanJSON: b}, nil
}
