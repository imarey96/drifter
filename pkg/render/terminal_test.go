package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/imarey96/drifter/pkg/engine"
)

func TestDiffSummarisesDestroyed(t *testing.T) {
	rd := engine.ResourceDrift{
		Address: "google_storage_bucket.logs",
		Action:  engine.ActionDestroyed,
		Origin:  engine.OriginOutOfBand,
		OutOfBand: []engine.AttributeChange{
			{Path: "id", Kind: engine.ChangeRemoved, Before: "drifter-test-logs"},
			{Path: "location", Kind: engine.ChangeRemoved, Before: "US-CENTRAL1"},
		},
		Planned: []engine.AttributeChange{{Path: "location", Kind: engine.ChangeAdded, After: "US-CENTRAL1"}},
	}
	items := []engine.Located{{Workspace: "stack", Resource: rd}}

	var short bytes.Buffer
	Terminal{W: &short}.Diff(items)
	out := short.String()
	if !strings.Contains(out, `apply would re-create it (was id "drifter-test-logs")`) || strings.Contains(out, "location") {
		t.Errorf("summary output:\n%s", out)
	}

	var full bytes.Buffer
	Terminal{W: &full, Full: true}.Diff(items)
	if !strings.Contains(full.String(), "location") {
		t.Errorf("--full output lacks attributes:\n%s", full.String())
	}
}
