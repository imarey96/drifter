package engine

import (
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/imarey96/drifter/pkg/redact"
	"github.com/imarey96/drifter/pkg/tfplan"
)

var identRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)

// Attributes holding a digest of other content, e.g. content_sha256,
// source_code_hash, etag.
var hashKeyRe = regexp.MustCompile(`(?i)(^|_)(md5|sha1|sha224|sha256|sha384|sha512|base64sha256|base64sha512|checksum|hash|digest|etag)$`)

// diffChange flattens a plan change into leaf-level attribute differences,
// masking sensitive values and scrubbing secrets from the rest.
//
// Providers often expose digests of sensitive content unmarked (the local
// provider's content_md5, for one). A digest of a short secret can be
// brute-forced, so on resources with any sensitive value, hash attributes
// and any attribute sharing a hash's value (such as an id derived from it)
// are masked too.
func diffChange(c tfplan.Change, scrub *redact.Scrubber) []AttributeChange {
	d := differ{scrub: scrub}
	if hasSensitiveValue(c.Before, c.BeforeSensitive) || hasSensitiveValue(c.After, c.AfterSensitive) {
		d.hashes = map[string]bool{}
		collectHashes(c.Before, d.hashes)
		collectHashes(c.After, d.hashes)
	}
	d.walk("", c.Before, c.After, c.BeforeSensitive, c.AfterSensitive, c.AfterUnknown)
	sort.SliceStable(d.out, func(i, j int) bool { return d.out[i].Path < d.out[j].Path })
	return d.out
}

type differ struct {
	scrub  *redact.Scrubber
	hashes map[string]bool // digest values to mask; nil when the resource has no sensitive values
	out    []AttributeChange
}

func (d *differ) walk(path string, before, after, bSens, aSens, unknown any) {
	if isTrue(bSens) || isTrue(aSens) {
		if !reflect.DeepEqual(before, after) || isTrue(unknown) {
			d.emit(path, before, after, true, isTrue(unknown))
		}
		return
	}
	if isTrue(unknown) {
		d.emit(path, before, nil, false, true)
		return
	}

	bm, bIsMap := before.(map[string]any)
	am, aIsMap := after.(map[string]any)
	if (bIsMap || before == nil) && (aIsMap || after == nil) && (bIsMap || aIsMap) {
		keys := map[string]struct{}{}
		for k := range bm {
			keys[k] = struct{}{}
		}
		for k := range am {
			keys[k] = struct{}{}
		}
		um, _ := unknown.(map[string]any)
		for k := range um {
			keys[k] = struct{}{}
		}
		for k := range keys {
			d.walk(joinKey(path, k), bm[k], am[k], child(bSens, k), child(aSens, k), child(unknown, k))
		}
		return
	}

	bl, bIsList := before.([]any)
	al, aIsList := after.([]any)
	if (bIsList || before == nil) && (aIsList || after == nil) && (bIsList || aIsList) {
		n := max(len(bl), len(al))
		if ul, ok := unknown.([]any); ok {
			n = max(n, len(ul))
		}
		for i := 0; i < n; i++ {
			d.walk(path+"["+strconv.Itoa(i)+"]", at(bl, i), at(al, i), idx(bSens, i), idx(aSens, i), idx(unknown, i))
		}
		return
	}

	if !reflect.DeepEqual(before, after) {
		d.emit(path, before, after, false, false)
	}
}

func (d *differ) emit(path string, before, after any, sensitive, unknown bool) {
	c := AttributeChange{Path: path, Sensitive: sensitive, Unknown: unknown}
	switch {
	case before == nil && (after != nil || unknown):
		c.Kind = ChangeAdded
	case after == nil && !unknown:
		c.Kind = ChangeRemoved
	default:
		c.Kind = ChangeUpdated
	}

	switch {
	case sensitive:
		c.Before, c.After = maskIfSet(before, redact.Sensitive), maskIfSet(after, redact.Sensitive)
	case d.isHash(path, before, after):
		c.Sensitive = true
		c.Before, c.After = maskIfSet(before, redact.Sensitive), maskIfSet(after, redact.Sensitive)
	case redact.IsSensitiveKey(lastSegment(path)):
		c.Before, c.After = maskIfSet(before, redact.Redacted), maskIfSet(after, redact.Redacted)
	default:
		c.Before, c.After = d.scrub.Value(before), d.scrub.Value(after)
	}
	if unknown {
		c.After = nil
	}
	d.out = append(d.out, c)
}

func (d *differ) isHash(path string, before, after any) bool {
	if d.hashes == nil {
		return false
	}
	if hashKeyRe.MatchString(lastSegment(path)) {
		return true
	}
	for _, v := range []any{before, after} {
		if s, ok := v.(string); ok && d.hashes[s] {
			return true
		}
	}
	return false
}

// collectHashes records string values of hash-named attributes anywhere in v.
func collectHashes(v any, into map[string]bool) {
	switch t := v.(type) {
	case map[string]any:
		for k, vv := range t {
			if s, ok := vv.(string); ok && s != "" && hashKeyRe.MatchString(k) {
				into[s] = true
				continue
			}
			collectHashes(vv, into)
		}
	case []any:
		for _, vv := range t {
			collectHashes(vv, into)
		}
	}
}

// hasSensitiveValue reports whether any attribute marked sensitive actually
// holds a value. Schemas often mark optional attributes sensitive (such as the
// local provider's deprecated sensitive_content), and those marks appear even
// when the attribute is null.
func hasSensitiveValue(v, marks any) bool {
	if v == nil {
		return false
	}
	switch m := marks.(type) {
	case bool:
		return m
	case map[string]any:
		vm, _ := v.(map[string]any)
		for k, mm := range m {
			if hasSensitiveValue(vm[k], mm) {
				return true
			}
		}
	case []any:
		vl, _ := v.([]any)
		for i, mm := range m {
			if hasSensitiveValue(at(vl, i), mm) {
				return true
			}
		}
	}
	return false
}

func maskIfSet(v any, mask string) any {
	if v == nil {
		return nil
	}
	return mask
}

func joinKey(path, k string) string {
	if identRe.MatchString(k) {
		if path == "" {
			return k
		}
		return path + "." + k
	}
	return path + "[" + strconv.Quote(k) + "]"
}

// lastSegment returns the attribute or map key name at the end of path,
// skipping list indices: `a.b[0]` → "b", `tags["k.v"]` → "k.v".
func lastSegment(path string) string {
	if strings.HasSuffix(path, `"]`) {
		if i := strings.LastIndex(path, `["`); i >= 0 {
			if s, err := strconv.Unquote(path[i+1 : len(path)-1]); err == nil {
				return s
			}
		}
	}
	if strings.HasSuffix(path, "]") {
		if i := strings.LastIndex(path, "["); i >= 0 {
			return lastSegment(path[:i])
		}
	}
	if i := strings.LastIndex(path, "."); i >= 0 {
		return path[i+1:]
	}
	return path
}

func isTrue(v any) bool { b, ok := v.(bool); return ok && b }

func child(v any, k string) any {
	if isTrue(v) {
		return true
	}
	if m, ok := v.(map[string]any); ok {
		return m[k]
	}
	return nil
}

func idx(v any, i int) any {
	if isTrue(v) {
		return true
	}
	if l, ok := v.([]any); ok && i < len(l) {
		return l[i]
	}
	return nil
}

func at(l []any, i int) any {
	if i < len(l) {
		return l[i]
	}
	return nil
}
