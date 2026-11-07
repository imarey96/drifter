package hclcheck

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverRoots(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "envs/prod/main.tf"), `terraform { backend "s3" {} }`)
	write(t, filepath.Join(root, "envs/dev/main.tf.json"), `{"terraform": {"cloud": {}}}`)
	write(t, filepath.Join(root, "envs/qa/main.tf"), `resource "null_resource" "x" {}`)
	write(t, filepath.Join(root, "envs/qa/.terraform.lock.hcl"), ``)
	write(t, filepath.Join(root, "modules/vpc/main.tf"), `variable "cidr" {}`)
	write(t, filepath.Join(root, "envs/prod/.terraform/modules/x/main.tf"), `terraform { backend "s3" {} }`)

	got, err := DiscoverRoots(root)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"envs/dev": true, "envs/prod": true, "envs/qa": true}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for _, g := range got {
		rel, _ := filepath.Rel(root, g)
		if !want[rel] {
			t.Errorf("unexpected root %s", rel)
		}
	}
}

func TestParseDirReportsLocation(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "main.tf"), "resource \"a\" \"b\" {\n  x = \n}\n")
	m, err := ParseDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !m.HasErrors() {
		t.Fatal("expected syntax error")
	}
	if got := m.FormatDiags(); got[:7] != "main.tf" {
		t.Errorf("diagnostic lacks relative file: %q", got)
	}
}
