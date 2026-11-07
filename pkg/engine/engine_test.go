package engine

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/imarey96/drifter/pkg/drifterr"
	"github.com/imarey96/drifter/pkg/ignore"
	"github.com/imarey96/drifter/pkg/provider"
	"github.com/imarey96/drifter/pkg/redact"
	"github.com/imarey96/drifter/pkg/tfplan"
)

func scanFixture(t *testing.T, rules string) *Report {
	t.Helper()
	rs, err := ignore.Parse(rules)
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{
		Provider: provider.FileProvider{Path: "../../testdata/plan.json"},
		Rules:    rs,
		Scrubber: redact.New(),
		Now:      func() time.Time { return time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC) },
	}
	r, err := e.Scan(context.Background(), []provider.Target{{Dir: ".", Label: "prod"}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func find(t *testing.T, r *Report, addr string) ResourceDrift {
	t.Helper()
	for _, rd := range r.Workspaces[0].Resources {
		if rd.Address == addr {
			return rd
		}
	}
	t.Fatalf("resource %s not in report", addr)
	return ResourceDrift{}
}

func TestClassification(t *testing.T) {
	r := scanFixture(t, "")

	cases := []struct {
		addr   string
		action Action
		origin Origin
	}{
		{"aws_security_group.web", ActionModified, OriginOutOfBand},
		{"aws_s3_bucket.legacy", ActionDestroyed, OriginOutOfBand},
		{"aws_db_instance.main", ActionModified, OriginUnapplied},
		{"aws_iam_role.ci", ActionAdded, OriginUnapplied},
		{"aws_lb.public", ActionReplaced, OriginUnapplied},
	}
	for _, c := range cases {
		rd := find(t, r, c.addr)
		if rd.Action != c.action || rd.Origin != c.origin {
			t.Errorf("%s: got %s/%s, want %s/%s", c.addr, rd.Action, rd.Origin, c.action, c.origin)
		}
	}

	for _, rd := range r.Workspaces[0].Resources {
		if strings.HasPrefix(rd.Address, "data.") || rd.Address == "aws_vpc.main" {
			t.Errorf("%s should be skipped", rd.Address)
		}
	}
	if r.Summary.Drifted != 8 || r.Summary.OutOfBand != 4 {
		t.Errorf("summary = %+v", r.Summary)
	}
}

func TestAttributeDiff(t *testing.T) {
	r := scanFixture(t, "")
	sg := find(t, r, "aws_security_group.web")

	want := map[string]AttributeChange{
		"ingress[0].cidr_blocks[0]": {Kind: ChangeUpdated, Before: "10.0.0.0/8", After: "0.0.0.0/0"},
		"tags.ModifiedBy":           {Kind: ChangeAdded, Before: nil, After: "console"},
	}
	if len(sg.OutOfBand) != len(want) {
		t.Fatalf("out-of-band changes = %+v", sg.OutOfBand)
	}
	for _, c := range sg.OutOfBand {
		w, ok := want[c.Path]
		if !ok || c.Kind != w.Kind || c.Before != w.Before || c.After != w.After {
			t.Errorf("unexpected change %+v", c)
		}
	}

	role := find(t, r, "aws_iam_role.ci")
	var unknown int
	for _, c := range role.Planned {
		if c.Unknown {
			unknown++
		}
	}
	if unknown != 2 {
		t.Errorf("expected arn and id unknown, got %+v", role.Planned)
	}
}

func TestSecretsNeverSerialized(t *testing.T) {
	r := scanFixture(t, "")
	b, _ := json.Marshal(r)
	for _, secret := range []string{"hunter2", "old-hunter2", "new-hunter2"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("report leaks %q", secret)
		}
	}
	db := find(t, r, "aws_db_instance.main")
	for _, c := range db.Planned {
		if c.Path == "password" && (!c.Sensitive || c.After != redact.Sensitive) {
			t.Errorf("password not masked: %+v", c)
		}
	}
}

func TestIgnoreRules(t *testing.T) {
	r := scanFixture(t, `
*:tags_all
module.monitoring.*
aws_autoscaling_group.*:desired_capacity
`)
	for _, addr := range []string{"aws_instance.app", "module.monitoring.aws_cloudwatch_metric_alarm.cpu", "aws_autoscaling_group.web"} {
		if rd := find(t, r, addr); !rd.Ignored {
			t.Errorf("%s should be ignored", addr)
		}
	}
	if find(t, r, "aws_security_group.web").Ignored {
		t.Error("security group should not be ignored")
	}
	if r.Summary.Ignored != 3 || r.Summary.Drifted != 5 {
		t.Errorf("summary = %+v", r.Summary)
	}
}

type failingProvider struct{ err error }

func (f failingProvider) Name() string { return "fail" }
func (f failingProvider) Plan(context.Context, provider.Target) (*provider.PlanOutput, error) {
	return nil, f.err
}

func TestProviderErrorIsScrubbed(t *testing.T) {
	err := &drifterr.Error{
		Code:   drifterr.CodeCredentials,
		Msg:    "no credentials",
		Detail: "using key AKIAIOSFODNN7EXAMPLE",
		Err:    errors.New("boom"),
	}
	e := &Engine{Provider: failingProvider{err}, Scrubber: redact.New()}
	r, _ := e.Scan(context.Background(), []provider.Target{{Dir: "a"}, {Dir: "b"}})
	if r.Summary.Errors != 2 {
		t.Fatalf("errors = %d", r.Summary.Errors)
	}
	se := r.Workspaces[0].Error
	if se.Code != string(drifterr.CodeCredentials) || strings.Contains(se.Detail, "AKIA") {
		t.Errorf("scan error = %+v", se)
	}
}

func TestHashesMaskedOnSensitiveResources(t *testing.T) {
	sha1 := "61f8c4624338c9f1c8e644d7c53aef4da49ff1e3"
	before := map[string]any{
		"content":      "s3cr3t",
		"content_md5":  "c25fc14b6d98599bcafa60f7a968f71f",
		"content_sha1": sha1,
		"id":           sha1,
		"filename":     "./out/secret.txt",
	}
	sensitive := tfplan.Change{
		Actions:         []string{"delete"},
		Before:          before,
		BeforeSensitive: map[string]any{"content": true},
		AfterSensitive:  false,
	}
	for _, c := range diffChange(sensitive, redact.New()) {
		masked := c.Before == redact.Sensitive
		if want := c.Path != "filename"; masked != want {
			t.Errorf("%s: masked=%v, want %v (value %v)", c.Path, masked, want, c.Before)
		}
	}

	// Without sensitive values, digests are useful drift signal and stay
	// visible, even when the schema marks a null attribute sensitive.
	plain := tfplan.Change{
		Actions:         []string{"delete"},
		Before:          map[string]any{"etag": "abc123", "sensitive_content": nil},
		BeforeSensitive: map[string]any{"sensitive_content": true},
	}
	if got := diffChange(plain, redact.New()); got[0].Before != "abc123" {
		t.Errorf("etag masked on non-sensitive resource: %v", got[0].Before)
	}
}

func TestNormalisationOnlyUpdatesAreDropped(t *testing.T) {
	p := &tfplan.Plan{ResourceDrift: []tfplan.ResourceChange{{
		Address: "google_storage_bucket.logs",
		Mode:    "managed",
		Change: tfplan.Change{
			Actions: []string{"update"},
			Before:  map[string]any{"name": "logs", "labels": nil},
			After:   map[string]any{"name": "logs", "labels": map[string]any{}},
		},
	}}}
	e := &Engine{Scrubber: redact.New()}
	if got := e.Analyze(p); len(got) != 0 {
		t.Errorf("null → {} reported as drift: %+v", got)
	}
}
