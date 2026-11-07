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

// diffChange flattens a plan change into leaf-level attribute differences,
// masking sensitive values and scrubbing secrets from the rest.
func diffChange(c tfplan.Change, scrub *redact.Scrubber) []AttributeChange {
	d := differ{scrub: scrub}
	d.walk("", c.Before, c.After, c.BeforeSensitive, c.AfterSensitive, c.AfterUnknown)
	sort.SliceStable(d.out, func(i, j int) bool { return d.out[i].Path < d.out[j].Path })
	return d.out
}

type differ struct {
	scrub *redact.Scrubber
	out   []AttributeChange
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
