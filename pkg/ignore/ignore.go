// Package ignore loads and evaluates .drifterignore rules.
//
// Each non-comment line has the form
//
//	<address-pattern>[:<attribute-pattern>]
//
// where `*` matches any run of characters (including dots and brackets) and
// everything else is literal. An attribute pattern also matches nested
// children, so `tags` covers `tags.Owner` and `tags["k8s.io/role"]`.
package ignore

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
)

const DefaultFile = ".drifterignore"

type Rule struct {
	Address   string `json:"address"`
	Attribute string `json:"attribute,omitempty"`

	addrRe *regexp.Regexp
	attrRe *regexp.Regexp
}

func (r Rule) String() string {
	if r.Attribute == "" {
		return r.Address
	}
	return r.Address + ":" + r.Attribute
}

type Rules struct {
	rules []Rule
}

func ParseRule(line string) (Rule, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return Rule{}, errors.New("empty rule")
	}
	// Addresses may contain ":" only inside quoted index keys, so split on
	// the last colon that sits outside brackets.
	addr, attr := splitRule(line)
	if addr == "" {
		return Rule{}, fmt.Errorf("rule %q has no address", line)
	}
	r := Rule{Address: addr, Attribute: attr, addrRe: glob(addr, false)}
	if attr != "" {
		r.attrRe = glob(attr, true)
	}
	return r, nil
}

func splitRule(s string) (string, string) {
	depth := 0
	for i := len(s) - 1; i >= 0; i-- {
		switch s[i] {
		case ']':
			depth++
		case '[':
			depth--
		case ':':
			if depth == 0 {
				return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
			}
		}
	}
	return s, ""
}

func glob(p string, prefix bool) *regexp.Regexp {
	parts := strings.Split(p, "*")
	for i := range parts {
		parts[i] = regexp.QuoteMeta(parts[i])
	}
	expr := "^" + strings.Join(parts, ".*")
	if prefix {
		expr += `(?:[.\[].*)?`
	}
	return regexp.MustCompile(expr + "$")
}

func Parse(content string) (*Rules, error) {
	rs := &Rules{}
	sc := bufio.NewScanner(strings.NewReader(content))
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Allow trailing comments separated by whitespace.
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		r, err := ParseRule(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		rs.rules = append(rs.rules, r)
	}
	return rs, sc.Err()
}

// Load reads rules from path. A missing file yields an empty rule set.
func Load(path string) (*Rules, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &Rules{}, nil
	}
	if err != nil {
		return nil, err
	}
	rs, err := Parse(string(b))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return rs, nil
}

func (rs *Rules) List() []Rule {
	if rs == nil {
		return nil
	}
	return append([]Rule(nil), rs.rules...)
}

// MatchResource reports whether the whole resource is ignored.
func (rs *Rules) MatchResource(addr string) (Rule, bool) {
	if rs == nil {
		return Rule{}, false
	}
	for _, r := range rs.rules {
		if r.Attribute == "" && r.addrRe.MatchString(addr) {
			return r, true
		}
	}
	return Rule{}, false
}

// MatchAttribute reports whether a single attribute change on addr is ignored.
func (rs *Rules) MatchAttribute(addr, attrPath string) bool {
	if rs == nil {
		return false
	}
	for _, r := range rs.rules {
		if r.attrRe != nil && r.addrRe.MatchString(addr) && r.attrRe.MatchString(attrPath) {
			return true
		}
	}
	return false
}

const fileHeader = `# .drifterignore — rules that suppress expected drift.
#
#   <address>                 ignore the whole resource
#   <address>:<attribute>     ignore one attribute (and its children)
#
# '*' matches anything. Examples:
#   aws_autoscaling_group.*:desired_capacity
#   *:tags_all
#   module.monitoring.*
`

// Append adds a rule to the file at path, creating it with a header if
// needed. It returns false if an identical rule already exists.
func Append(path string, r Rule, comment string) (bool, error) {
	existing, err := Load(path)
	if err != nil {
		return false, err
	}
	for _, e := range existing.rules {
		if e.String() == r.String() {
			return false, nil
		}
	}

	var b strings.Builder
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		b.WriteString(fileHeader)
	}
	b.WriteString("\n")
	if comment != "" {
		b.WriteString("# " + strings.ReplaceAll(comment, "\n", " ") + "\n")
	}
	b.WriteString(r.String() + "\n")

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return false, err
	}
	defer f.Close()
	_, err = f.WriteString(b.String())
	return err == nil, err
}

// Remove deletes rule lines that exactly match r. It returns how many were removed.
func Remove(path string, r Rule) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	lines := strings.Split(string(b), "\n")
	out := lines[:0]
	removed := 0
	for _, l := range lines {
		if strings.TrimSpace(l) == r.String() {
			removed++
			continue
		}
		out = append(out, l)
	}
	if removed == 0 {
		return 0, nil
	}
	return removed, os.WriteFile(path, []byte(strings.Join(out, "\n")), 0o644)
}

// MatchAddress reports whether addr matches a glob pattern using the same
// syntax as rule addresses.
func MatchAddress(pattern, addr string) bool { return glob(pattern, false).MatchString(addr) }
