package sbom

import (
	"slices"
	"strings"
)

// LicenseTerms: canonical license keys for comparison
// "A AND B" == [A, B]; LicenseRef-x == sha256:x == x; OR/WITH kept whole
func LicenseTerms(lics []string) []string {
	m := LicenseTermNames(lics)
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// LicenseTermNames: canonical key -> display name
func LicenseTermNames(lics []string) map[string]string {
	out := map[string]string{}
	for _, l := range lics {
		l = stripOuterParens(strings.TrimSpace(l))
		if l == "" {
			continue
		}
		parts := []string{l}
		if isExpression(strings.Fields(l)) && !strings.ContainsAny(l, "()") && !hasOp(l, "OR") && !hasOp(l, "WITH") {
			parts = splitOp(l, "AND")
		}
		for _, p := range parts {
			name, key := termKey(p)
			if _, ok := out[key]; name != "" && !ok {
				out[key] = name
			}
		}
	}
	return out
}

// termKey: per-id keys; SPDX expression structure kept, so
// LicenseRef-MIT-OR-Apache-2.0 != MIT OR Apache-2.0
func termKey(term string) (name, key string) {
	term = strings.TrimSpace(term)
	words := strings.Fields(strings.NewReplacer("(", " ( ", ")", " ) ").Replace(term))
	if !isExpression(words) {
		// single id or free text ("Apache 2.0"): SPDX LicenseRef folding
		name = trimLicenseRef(term)
		return name, licenseKey(name)
	}
	for i, w := range words {
		switch w {
		case "AND", "OR", "WITH", "(", ")":
		default:
			words[i] = licenseKey(trimLicenseRef(w))
		}
	}
	return term, strings.Join(words, " ")
}

// isExpression: ids joined by AND/OR/WITH, no two ids in a row
func isExpression(words []string) bool {
	ops, prevID := 0, false
	for _, w := range words {
		switch w {
		case "AND", "OR", "WITH":
			ops++
			prevID = false
		case "(", ")":
		default:
			if prevID {
				return false
			}
			prevID = true
		}
	}
	return ops > 0
}
// licenseKey: case-folded, SPDX idstring chars (MIT/X11 == MIT-X11)
func licenseKey(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 'a' - 'A'
		}
		return '-'
	}, s)
}

func trimLicenseRef(s string) string {
	s = strings.TrimSpace(s)
	for _, pre := range []string{"LicenseRef-", "sha256:"} {
		if len(s) > len(pre) && strings.EqualFold(s[:len(pre)], pre) {
			s = s[len(pre):]
		}
	}
	return osgiLicense(s)
}

// osgiLicense: OSGi Bundle-License "<url>;description=BUSL-1.1" -> BUSL-1.1
// also SPDX-folded "https---...-description-BUSL-1.1"
func osgiLicense(s string) string {
	low := strings.ToLower(s)
	for _, sep := range []string{";description=", "-description-"} {
		i := strings.Index(low, sep)
		url := strings.HasPrefix(low, "http:") || strings.HasPrefix(low, "https:") || strings.HasPrefix(low, "http---") || strings.HasPrefix(low, "https---")
		if i <= 0 || !url {
			continue
		}
		desc, _, _ := strings.Cut(s[i+len(sep):], ";")
		if desc = strings.TrimSpace(desc); desc != "" && !strings.ContainsAny(desc, " \t") {
			return desc
		}
	}
	return s
}

func hasOp(s, op string) bool {
	return len(splitOp(s, op)) > 1
}

// splitOp: split on " op "; SPDX operators are case-sensitive
func splitOp(s, op string) []string {
	f := strings.Fields(s)
	var out []string
	start := 0
	for i, w := range f {
		if w == op {
			out = append(out, strings.Join(f[start:i], " "))
			start = i + 1
		}
	}
	return append(out, strings.Join(f[start:], " "))
}

// SameLicenses: equal after LicenseTerms
func SameLicenses(a, b []string) bool {
	return slices.Equal(LicenseTerms(a), LicenseTerms(b))
}

// stripOuterParens: "(A AND B)" -> "A AND B"
func stripOuterParens(s string) string {
	for len(s) > 1 && s[0] == '(' && s[len(s)-1] == ')' {
		depth := 0
		for i := 0; i < len(s)-1; i++ {
			switch s[i] {
			case '(':
				depth++
			case ')':
				depth--
			}
			if depth == 0 {
				return s // first paren closes early: "(A) OR (B)"
			}
		}
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}

// LicenseIDs: every license id in the expressions (AND/OR/WITH split)
func LicenseIDs(lics []string) map[string]string {
	out := map[string]string{}
	for _, l := range lics {
		// whole value too: free text like "SEE LICENSE IN LICENSE.txt"
		if name, key := termKey(stripOuterParens(l)); name != "" {
			out[key] = name
		}
		words := strings.Fields(strings.NewReplacer("(", " ", ")", " ").Replace(l))
		if !isExpression(words) {
			continue // free text: whole value only
		}
		for _, w := range words {
			switch w {
			case "AND", "OR", "WITH":
				continue
			}
			if name := trimLicenseRef(w); name != "" {
				if _, ok := out[licenseKey(name)]; !ok {
					out[licenseKey(name)] = name
				}
			}
		}
	}
	return out
}

// LicenseKey: comparison key for one license id or name
func LicenseKey(id string) string {
	_, key := termKey(id)
	return key
}
