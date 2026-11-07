// Package redact scrubs secrets from strings and structured values before
// they are logged, cached, or rendered.
package redact

import (
	"regexp"
	"sort"
	"strings"
)

const (
	Redacted  = "(redacted)"
	Sensitive = "(sensitive)"
)

var patterns = []*regexp.Regexp{
	regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`),                                               // AWS access key IDs
	regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`), // PEM keys
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`),                                            // GitHub tokens
	regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`),                                              // GitLab tokens
	regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`),                                          // Slack tokens
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`),         // JWTs
	regexp.MustCompile(`(?i)\b(sig|signature|x-amz-signature|x-amz-security-token)=[^&\s"]+`),       // presigned URL params
}

// userinfo in URLs: scheme://user:password@host
var urlCreds = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@`)

var sensitiveKey = regexp.MustCompile(`(?i)(password|passwd|secret|token|private_key|api_key|apikey|access_key|credential|client_secret|connection_string|sas_key)`)

// Env var names whose values are treated as secrets when scrubbing tool output.
var sensitiveEnv = regexp.MustCompile(`(?i)(SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|ACCESS_KEY|API_KEY|CLIENT_SECRET|SESSION)`)

// Scrubber removes known secret values and secret-shaped strings.
// The zero value only applies pattern-based scrubbing.
type Scrubber struct {
	literals []string // sorted longest first
}

// New returns a Scrubber that also removes the given literal values.
func New(literals ...string) *Scrubber {
	s := &Scrubber{}
	for _, l := range literals {
		// Short values cause false positives and leak little.
		if len(l) >= 6 {
			s.literals = append(s.literals, l)
		}
	}
	sort.Slice(s.literals, func(i, j int) bool { return len(s.literals[i]) > len(s.literals[j]) })
	return s
}

// FromEnv builds a Scrubber seeded with the values of secret-looking
// environment variables (KEY=VALUE pairs, as from os.Environ).
func FromEnv(environ []string) *Scrubber {
	var vals []string
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if ok && v != "" && sensitiveEnv.MatchString(k) {
			vals = append(vals, v)
		}
	}
	return New(vals...)
}

// String scrubs a single string.
func (s *Scrubber) String(in string) string {
	if in == "" {
		return in
	}
	out := in
	if s != nil {
		for _, l := range s.literals {
			out = strings.ReplaceAll(out, l, Redacted)
		}
	}
	for _, p := range patterns {
		out = p.ReplaceAllString(out, Redacted)
	}
	out = urlCreds.ReplaceAllString(out, "${1}"+Redacted+"@")
	return out
}

// Value scrubs strings nested anywhere inside a decoded JSON value.
func (s *Scrubber) Value(v any) any {
	switch t := v.(type) {
	case string:
		return s.String(t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, vv := range t {
			if IsSensitiveKey(k) {
				out[k] = Redacted
				continue
			}
			out[k] = s.Value(vv)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, vv := range t {
			out[i] = s.Value(vv)
		}
		return out
	default:
		return v
	}
}

// IsSensitiveKey reports whether an attribute name looks like it holds a secret.
func IsSensitiveKey(k string) bool { return sensitiveKey.MatchString(k) }
