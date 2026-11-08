package identity

import (
	"net/url"
	"regexp"
	"strings"
)

// ComponentIdentity holds fields for canonical ID computation.
type ComponentIdentity struct {
	PURL      string
	CPEs      []string
	BOMRef    string
	SPDXID    string
	Namespace string
	Name      string
}

// ComputeID generates a canonical identity. Precedence: PURL > CPE > BOM-ref/SPDXID > namespace/name > name.
func ComputeID(c ComponentIdentity) string {
	if c.PURL != "" {
		return NormalizePURL(c.PURL)
	}

	if len(c.CPEs) > 0 {
		for _, cpe := range c.CPEs {
			normalized := NormalizeCPE(cpe)
			if normalized != "" {
				return normalized
			}
		}
	}

	if c.BOMRef != "" {
		return "ref:" + c.BOMRef
	}
	if c.SPDXID != "" {
		return "ref:" + c.SPDXID
	}

	if c.Namespace != "" {
		return c.Namespace + "/" + c.Name
	}

	return c.Name
}

var osPackageTypes = map[string]bool{
	"rpm": true, "deb": true, "apk": true, "alpm": true,
}

// NormalizePURL strips version and qualifiers from a PURL. The subpath is
// kept: pkg:github/o/r#a and pkg:github/o/r#b are different packages.
func NormalizePURL(purl string) string {
	if purl == "" {
		return ""
	}
	purl, subpath, _ := strings.Cut(purl, "#")
	purl, _, _ = strings.Cut(purl, "?")
	if idx := strings.LastIndex(purl, "@"); idx != -1 {
		purl = purl[:idx]
	}

	// Strip distro namespace for OS package types
	// e.g. pkg:rpm/amzn/bash → pkg:rpm/bash
	if strings.HasPrefix(purl, "pkg:") {
		rest := purl[4:]
		if ptype, afterType, ok := strings.Cut(rest, "/"); ok {
			if osPackageTypes[ptype] {
				if _, name, ok := strings.Cut(afterType, "/"); ok {
					purl = "pkg:" + ptype + "/" + name
				}
			}
		}
	}

	if subpath = strings.Trim(subpath, "/"); subpath != "" {
		purl += "#" + subpath
	}
	return purl
}

// pep503Separators matches runs of PyPI name separators.
var pep503Separators = regexp.MustCompile(`[-_.]+`)

// MatchKey folds an ID for comparison where the ecosystem treats names as
// case-insensitive: npm (lowercase) and PyPI (PEP 503). Other IDs are
// returned unchanged; Go module paths and file paths are case-sensitive.
func MatchKey(id string) string {
	switch {
	case strings.HasPrefix(id, "pkg:npm/"):
		name, subpath, found := strings.Cut(id, "#")
		if found {
			return strings.ToLower(name) + "#" + subpath
		}
		return strings.ToLower(name)
	case strings.HasPrefix(id, "pkg:pypi/"):
		name, subpath, _ := strings.Cut(id[len("pkg:pypi/"):], "#")
		key := "pkg:pypi/" + pep503Separators.ReplaceAllString(strings.ToLower(name), "-")
		if subpath != "" {
			key += "#" + subpath
		}
		return key
	}
	return id
}

// ExtractPURLVersion extracts the version from a PURL.
func ExtractPURLVersion(purl string) string {
	if purl == "" {
		return ""
	}
	purl, _, _ = strings.Cut(purl, "#")
	purl, _, _ = strings.Cut(purl, "?")
	if idx := strings.LastIndex(purl, "@"); idx != -1 {
		ver := purl[idx+1:]
		if decoded, err := url.QueryUnescape(ver); err == nil {
			return decoded
		}
		return ver
	}
	return ""
}

// NormalizeCPE extracts vendor:product from CPE 2.2/2.3.
func NormalizeCPE(cpe string) string {
	if cpe == "" {
		return ""
	}

	if strings.HasPrefix(cpe, "cpe:2.3:") {
		parts := strings.Split(cpe, ":")
		if len(parts) >= 5 {
			vendor := parts[3]
			product := parts[4]
			if vendor != "" && vendor != "*" && product != "" && product != "*" {
				return "cpe:" + vendor + ":" + product
			}
		}
		return ""
	}

	if strings.HasPrefix(cpe, "cpe:/") {
		rest := cpe[5:] // remove "cpe:/"
		parts := strings.Split(rest, ":")
		if len(parts) >= 3 {
			vendor := parts[1]
			product := parts[2]
			if vendor != "" && product != "" {
				return "cpe:" + vendor + ":" + product
			}
		}
		return ""
	}

	return ""
}
