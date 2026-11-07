package tfcli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/imarey96/drifter/pkg/drifterr"
	"github.com/imarey96/drifter/pkg/provider"
	"github.com/imarey96/drifter/pkg/redact"
)

func fakeProvider(t *testing.T, mode string) (*Provider, string) {
	t.Helper()
	bin, _ := filepath.Abs("../../../testdata/fakebin/terraform")
	plan, _ := filepath.Abs("../../../testdata/plan.json")
	logFile := filepath.Join(t.TempDir(), "calls.log")
	env := append(os.Environ(),
		"FAKE_TF_PLAN="+plan,
		"FAKE_TF_MODE="+mode,
		"FAKE_TF_LOG="+logFile,
		"TF_LOG=TRACE",
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENGbPxRfiCYEXAMPLEKEY",
	)
	return &Provider{
		Binary:   bin,
		Kind:     "terraform",
		Env:      env,
		AutoInit: true,
		Scrubber: redact.FromEnv(env),
	}, logFile
}

func copyWorkspace(t *testing.T, name string) string {
	t.Helper()
	dst := t.TempDir()
	b, err := os.ReadFile(filepath.Join("../../../testdata/workspaces", name, "main.tf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "main.tf"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestPlanUninitialisedUsesTempDataDir(t *testing.T) {
	p, logFile := fakeProvider(t, "drift")
	dir := copyWorkspace(t, "prod")

	out, err := p.Plan(context.Background(), provider.Target{Dir: dir})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if out.EngineVersion != "1.9.5" || !strings.Contains(string(out.PlanJSON), "resource_drift") {
		t.Errorf("unexpected output: %s %d bytes", out.EngineVersion, len(out.PlanJSON))
	}
	if _, err := os.Stat(filepath.Join(dir, ".terraform")); err == nil {
		t.Error("drifter created .terraform in the user's directory")
	}

	log, _ := os.ReadFile(logFile)
	if !strings.Contains(string(log), "init data_dir=/") {
		t.Errorf("init did not use a temp TF_DATA_DIR:\n%s", log)
	}
	if strings.Contains(string(log), "tf_log=TRACE") {
		t.Errorf("TF_LOG leaked into child env:\n%s", log)
	}
}

func TestPlanCredentialErrorIsClassifiedAndScrubbed(t *testing.T) {
	p, _ := fakeProvider(t, "creds")
	_, err := p.Plan(context.Background(), provider.Target{Dir: copyWorkspace(t, "prod")})
	de, ok := drifterr.As(err)
	if !ok || de.Code != drifterr.CodeCredentials {
		t.Fatalf("got %v, want credentials error", err)
	}
	if strings.Contains(de.Detail, "wJalrXUtnFEMI") {
		t.Errorf("secret leaked into detail: %s", de.Detail)
	}
	if !strings.Contains(de.Detail, "No valid credential sources found") {
		t.Errorf("detail lost the diagnostic: %s", de.Detail)
	}
}

func TestPlanSyntaxErrorBeforeRunningBinary(t *testing.T) {
	p, logFile := fakeProvider(t, "drift")
	_, err := p.Plan(context.Background(), provider.Target{Dir: copyWorkspace(t, "broken")})
	de, ok := drifterr.As(err)
	if !ok || de.Code != drifterr.CodeHCLSyntax {
		t.Fatalf("got %v, want HCL syntax error", err)
	}
	if !strings.Contains(de.Detail, "main.tf:") {
		t.Errorf("detail lacks file location: %s", de.Detail)
	}
	if _, err := os.Stat(logFile); err == nil {
		t.Error("binary was invoked despite syntax errors")
	}
}

func TestDetectMissingBinary(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	_, err := Detect("auto")
	if de, ok := drifterr.As(err); !ok || de.Code != drifterr.CodeBinaryNotFound {
		t.Fatalf("got %v, want binary-not-found", err)
	}
}
