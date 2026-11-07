// Package engine turns plan documents into classified drift reports.
//
// The engine performs no I/O of its own: plans come from a
// provider.StateProvider, and the caller decides where reports go. That keeps
// it usable from the CLI and from a stateless multi-tenant worker alike.
package engine

import (
	"context"
	"sort"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/imarey96/drifter/pkg/drifterr"
	"github.com/imarey96/drifter/pkg/ignore"
	"github.com/imarey96/drifter/pkg/provider"
	"github.com/imarey96/drifter/pkg/redact"
	"github.com/imarey96/drifter/pkg/tfplan"
)

type Engine struct {
	Provider provider.StateProvider
	Rules    *ignore.Rules
	Scrubber *redact.Scrubber
	// Parallelism caps concurrent plans. Values below 1 mean 1.
	Parallelism int
	// OnDone, if set, is called after each target finishes. It may be
	// called from multiple goroutines.
	OnDone func(WorkspaceReport)
	Now    func() time.Time
}

// Scan evaluates every target and returns a report. Per-target failures are
// recorded on the workspace; the returned error is non-nil only when the
// context is cancelled.
func (e *Engine) Scan(ctx context.Context, targets []provider.Target) (*Report, error) {
	now := time.Now
	if e.Now != nil {
		now = e.Now
	}
	results := make([]WorkspaceReport, len(targets))

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(max(e.Parallelism, 1))
	for i, t := range targets {
		g.Go(func() error {
			results[i] = e.scanOne(gctx, t)
			if e.OnDone != nil {
				e.OnDone(results[i])
			}
			return nil
		})
	}
	_ = g.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	r := &Report{SchemaVersion: SchemaVersion, GeneratedAt: now().UTC(), Workspaces: results}
	r.Summarize()
	return r, nil
}

func (e *Engine) scanOne(ctx context.Context, t provider.Target) WorkspaceReport {
	start := time.Now()
	ws := WorkspaceReport{Path: t.Name(), Resources: []ResourceDrift{}}
	defer func() { ws.DurationMS = time.Since(start).Milliseconds() }()

	out, err := e.Provider.Plan(ctx, t)
	if err != nil {
		ws.Error = e.toScanError(err)
		return ws
	}
	ws.Engine, ws.EngineVersion = out.Engine, out.EngineVersion

	p, err := tfplan.Parse(out.PlanJSON)
	if err != nil {
		ws.Error = e.toScanError(drifterr.Wrap(drifterr.CodePlanFailed, err, "could not read plan output", ""))
		return ws
	}
	if ws.EngineVersion == "" {
		ws.EngineVersion = p.TerraformVersion
	}
	ws.Resources = e.Analyze(p)
	return ws
}

// Analyze classifies the resources in a decoded plan and applies ignore rules.
func (e *Engine) Analyze(p *tfplan.Plan) []ResourceDrift {
	byAddr := map[string]*ResourceDrift{}
	get := func(rc tfplan.ResourceChange) *ResourceDrift {
		if rd, ok := byAddr[rc.Address]; ok {
			return rd
		}
		rd := &ResourceDrift{
			Address:       rc.Address,
			Type:          rc.Type,
			Name:          rc.Name,
			ModuleAddress: rc.ModuleAddress,
			ProviderName:  rc.ProviderName,
		}
		byAddr[rc.Address] = rd
		return rd
	}

	for _, rc := range p.ResourceDrift {
		act, ok := classify(rc)
		if !ok {
			continue
		}
		rd := get(rc)
		rd.Origin, rd.Action = OriginOutOfBand, act
		rd.OutOfBand = diffChange(rc.Change, e.Scrubber)
	}
	for _, rc := range p.ResourceChanges {
		act, ok := classify(rc)
		if !ok {
			continue
		}
		rd := get(rc)
		rd.Planned = diffChange(rc.Change, e.Scrubber)
		// For out-of-band drift the observed action (e.g. destroyed in the
		// console) is more useful than the corrective one (re-create).
		if rd.Origin == "" {
			rd.Origin, rd.Action = OriginUnapplied, act
		}
	}

	out := make([]ResourceDrift, 0, len(byAddr))
	for _, rd := range byAddr {
		applyIgnores(e.Rules, rd)
		out = append(out, *rd)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out
}

// ApplyIgnores re-evaluates rules against an existing report, for example one
// loaded from cache after .drifterignore changed, and recomputes the summary.
func ApplyIgnores(r *Report, rules *ignore.Rules) {
	for wi := range r.Workspaces {
		for ri := range r.Workspaces[wi].Resources {
			applyIgnores(rules, &r.Workspaces[wi].Resources[ri])
		}
	}
	r.Summarize()
}

func applyIgnores(rules *ignore.Rules, rd *ResourceDrift) {
	rd.Ignored, rd.IgnoreRule = false, ""
	if r, ok := rules.MatchResource(rd.Address); ok {
		rd.Ignored, rd.IgnoreRule = true, r.String()
		return
	}
	remaining := markIgnored(rules, rd.Address, rd.OutOfBand) + markIgnored(rules, rd.Address, rd.Planned)
	if rd.Action == ActionModified && remaining == 0 {
		rd.Ignored, rd.IgnoreRule = true, "all changed attributes"
	}
}

// markIgnored flags ignored changes and returns how many remain.
func markIgnored(rs *ignore.Rules, addr string, changes []AttributeChange) int {
	remaining := 0
	for i := range changes {
		changes[i].Ignored = rs.MatchAttribute(addr, changes[i].Path)
		if !changes[i].Ignored {
			remaining++
		}
	}
	return remaining
}

func classify(rc tfplan.ResourceChange) (Action, bool) {
	if rc.Mode != "" && rc.Mode != "managed" {
		return "", false
	}
	a := rc.Change.Actions
	switch {
	case len(a) == 1 && a[0] == "create":
		return ActionAdded, true
	case len(a) == 1 && a[0] == "update":
		return ActionModified, true
	case len(a) == 1 && a[0] == "delete":
		return ActionDestroyed, true
	case len(a) == 2:
		return ActionReplaced, true
	}
	return "", false // no-op, read, forget
}

func (e *Engine) toScanError(err error) *ScanError {
	if de, ok := drifterr.As(err); ok {
		return &ScanError{
			Code:    string(de.Code),
			Message: e.Scrubber.String(de.Error()),
			Hint:    de.Hint,
			Detail:  e.Scrubber.String(de.Detail),
		}
	}
	return &ScanError{Code: string(drifterr.CodePlanFailed), Message: e.Scrubber.String(err.Error())}
}
