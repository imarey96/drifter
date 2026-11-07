package ignore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMatching(t *testing.T) {
	rs, err := Parse(`
# comment
aws_autoscaling_group.*:desired_capacity
*:tags_all
module.monitoring.*
aws_instance.web["a:b"]   # colon inside index key
`)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := rs.MatchResource("module.monitoring.aws_cloudwatch_metric_alarm.cpu"); !ok {
		t.Error("expected module.monitoring.* to match")
	}
	if _, ok := rs.MatchResource(`aws_instance.web["a:b"]`); !ok {
		t.Error("expected quoted index address to match whole resource")
	}
	if _, ok := rs.MatchResource("aws_instance.app"); ok {
		t.Error("aws_instance.app should not be ignored")
	}
	if !rs.MatchAttribute("aws_autoscaling_group.web", "desired_capacity") {
		t.Error("desired_capacity should be ignored")
	}
	if !rs.MatchAttribute("aws_s3_bucket.logs", "tags_all.Owner") {
		t.Error("tags_all children should be ignored")
	}
	if rs.MatchAttribute("aws_s3_bucket.logs", "tags.Owner") {
		t.Error("tags.Owner should not match tags_all rule")
	}
}

func TestAppendAndRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFile)
	r, _ := ParseRule("aws_instance.app:tags.LastScanned")

	added, err := Append(path, r, "set by nightly scanner")
	if err != nil || !added {
		t.Fatalf("Append = %v, %v", added, err)
	}
	if added, _ := Append(path, r, ""); added {
		t.Error("duplicate rule was appended")
	}
	rs, _ := Load(path)
	if !rs.MatchAttribute("aws_instance.app", "tags.LastScanned") {
		t.Error("appended rule not effective")
	}
	if n, err := Remove(path, r); err != nil || n != 1 {
		t.Fatalf("Remove = %d, %v", n, err)
	}
	b, _ := os.ReadFile(path)
	rs, _ = Parse(string(b))
	if len(rs.List()) != 0 {
		t.Errorf("rules left after remove: %v", rs.List())
	}
}
