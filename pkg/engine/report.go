package engine

import (
	"time"

	"github.com/imarey96/drifter/pkg/ignore"
)

const SchemaVersion = "1"

// Action is the effect a change has on a resource.
type Action string

const (
	ActionAdded     Action = "added"
	ActionModified  Action = "modified"
	ActionDestroyed Action = "destroyed"
	ActionReplaced  Action = "replaced"
)

// Origin says where a difference came from.
type Origin string

const (
	// OriginOutOfBand: live infrastructure changed outside IaC since the
	// last apply (console edits, scripts, other tools).
	OriginOutOfBand Origin = "out_of_band"
	// OriginUnapplied: configuration in the repo differs from live
	// infrastructure, but the live state matches what was last applied.
	OriginUnapplied Origin = "unapplied"
)

// ChangeKind describes a single attribute difference.
type ChangeKind string

const (
	ChangeAdded   ChangeKind = "added"
	ChangeRemoved ChangeKind = "removed"
	ChangeUpdated ChangeKind = "updated"
)

type AttributeChange struct {
	Path      string     `json:"path"`
	Kind      ChangeKind `json:"kind"`
	Before    any        `json:"before"`
	After     any        `json:"after"`
	Sensitive bool       `json:"sensitive,omitempty"`
	Unknown   bool       `json:"unknown,omitempty"` // value known only after apply
	Ignored   bool       `json:"ignored,omitempty"`
}

type ResourceDrift struct {
	Address       string `json:"address"`
	Type          string `json:"type"`
	Name          string `json:"name"`
	ModuleAddress string `json:"module_address,omitempty"`
	ProviderName  string `json:"provider_name"`
	Action        Action `json:"action"`
	Origin        Origin `json:"origin"`

	// OutOfBand holds last-applied state → live differences.
	OutOfBand []AttributeChange `json:"out_of_band,omitempty"`
	// Planned holds live → configuration differences (what an apply would do).
	Planned []AttributeChange `json:"planned,omitempty"`

	Ignored    bool   `json:"ignored,omitempty"`
	IgnoreRule string `json:"ignore_rule,omitempty"`
}

type WorkspaceReport struct {
	Path          string          `json:"path"`
	Engine        string          `json:"engine,omitempty"`
	EngineVersion string          `json:"engine_version,omitempty"`
	Resources     []ResourceDrift `json:"resources"`
	Error         *ScanError      `json:"error,omitempty"`
	DurationMS    int64           `json:"duration_ms"`
}

type ScanError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

type Summary struct {
	Workspaces int `json:"workspaces"`
	Drifted    int `json:"drifted"`
	OutOfBand  int `json:"out_of_band"`
	Unapplied  int `json:"unapplied"`
	Added      int `json:"added"`
	Modified   int `json:"modified"`
	Destroyed  int `json:"destroyed"`
	Replaced   int `json:"replaced"`
	Ignored    int `json:"ignored"`
	Errors     int `json:"errors"`
}

type Report struct {
	SchemaVersion string            `json:"schema_version"`
	GeneratedAt   time.Time         `json:"generated_at"`
	Summary       Summary           `json:"summary"`
	Workspaces    []WorkspaceReport `json:"workspaces"`
}

// HasDrift reports whether any non-ignored drift was found.
func (r *Report) HasDrift() bool { return r.Summary.Drifted > 0 }

// HasErrors reports whether any workspace failed to scan.
func (r *Report) HasErrors() bool { return r.Summary.Errors > 0 }

// Summarize recomputes the summary from workspace contents.
func (r *Report) Summarize() {
	s := Summary{Workspaces: len(r.Workspaces)}
	for _, ws := range r.Workspaces {
		if ws.Error != nil {
			s.Errors++
		}
		for _, rd := range ws.Resources {
			if rd.Ignored {
				s.Ignored++
				continue
			}
			s.Drifted++
			switch rd.Origin {
			case OriginOutOfBand:
				s.OutOfBand++
			case OriginUnapplied:
				s.Unapplied++
			}
			switch rd.Action {
			case ActionAdded:
				s.Added++
			case ActionModified:
				s.Modified++
			case ActionDestroyed:
				s.Destroyed++
			case ActionReplaced:
				s.Replaced++
			}
		}
	}
	r.Summary = s
}

// Located pairs a resource with the workspace it was found in.
type Located struct {
	Workspace string        `json:"workspace"`
	Resource  ResourceDrift `json:"resource"`
}

// Find returns resources whose address matches pattern ("*" is a wildcard).
// An empty pattern matches everything. workspace, if set, filters by path.
func (r *Report) Find(pattern, workspace string, includeIgnored bool) []Located {
	var out []Located
	for _, ws := range r.Workspaces {
		if workspace != "" && ws.Path != workspace {
			continue
		}
		for _, rd := range ws.Resources {
			if rd.Ignored && !includeIgnored {
				continue
			}
			if pattern == "" || ignore.MatchAddress(pattern, rd.Address) {
				out = append(out, Located{Workspace: ws.Path, Resource: rd})
			}
		}
	}
	return out
}
