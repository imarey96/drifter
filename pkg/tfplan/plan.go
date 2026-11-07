// Package tfplan decodes the machine-readable plan format produced by
// `terraform show -json` and `tofu show -json`.
package tfplan

import (
	"encoding/json"
	"fmt"
)

type Plan struct {
	FormatVersion    string           `json:"format_version"`
	TerraformVersion string           `json:"terraform_version"`
	ResourceDrift    []ResourceChange `json:"resource_drift"`
	ResourceChanges  []ResourceChange `json:"resource_changes"`
}

type ResourceChange struct {
	Address       string `json:"address"`
	ModuleAddress string `json:"module_address,omitempty"`
	Mode          string `json:"mode"`
	Type          string `json:"type"`
	Name          string `json:"name"`
	ProviderName  string `json:"provider_name"`
	Change        Change `json:"change"`
	ActionReason  string `json:"action_reason,omitempty"`
}

type Change struct {
	Actions         []string `json:"actions"`
	Before          any      `json:"before"`
	After           any      `json:"after"`
	AfterUnknown    any      `json:"after_unknown"`
	BeforeSensitive any      `json:"before_sensitive"`
	AfterSensitive  any      `json:"after_sensitive"`
}

// Parse decodes plan JSON and rejects documents that are not plans.
func Parse(data []byte) (*Plan, error) {
	var p Plan
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("decode plan JSON: %w", err)
	}
	if p.FormatVersion == "" {
		return nil, fmt.Errorf("input is not a plan document (missing format_version)")
	}
	return &p, nil
}
