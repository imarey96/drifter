package redact

import (
	"strings"
	"testing"
)

func TestScrubString(t *testing.T) {
	s := FromEnv([]string{"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG", "HOME=/Users/x", "GITHUB_TOKEN=abc"})

	cases := map[string]string{
		"key AKIAIOSFODNN7EXAMPLE leaked":            "key (redacted) leaked",
		"secret wJalrXUtnFEMI/K7MDENG in stderr":     "secret (redacted) in stderr",
		"postgres://admin:hunter22@db:5432/app":      "postgres://(redacted)@db:5432/app",
		"home is /Users/x":                           "home is /Users/x",
		"short token abc stays (below length floor)": "short token abc stays (below length floor)",
	}
	for in, want := range cases {
		if got := s.String(in); got != want {
			t.Errorf("String(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestScrubPEM(t *testing.T) {
	in := "x\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nabc\n-----END RSA PRIVATE KEY-----\ny"
	got := (&Scrubber{}).String(in)
	if strings.Contains(got, "MIIEow") {
		t.Fatalf("PEM body not scrubbed: %q", got)
	}
}

func TestScrubValue(t *testing.T) {
	v := map[string]any{
		"name":        "web",
		"db_password": "hunter22",
		"nested":      []any{map[string]any{"api_key": "k", "id": "AKIAIOSFODNN7EXAMPLE"}},
	}
	got := (&Scrubber{}).Value(v).(map[string]any)
	if got["db_password"] != Redacted {
		t.Errorf("db_password not redacted: %v", got["db_password"])
	}
	inner := got["nested"].([]any)[0].(map[string]any)
	if inner["api_key"] != Redacted || inner["id"] != Redacted {
		t.Errorf("nested values not redacted: %v", inner)
	}
	if got["name"] != "web" {
		t.Errorf("name changed: %v", got["name"])
	}
}
