package analysis

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

// Stats holds SBOM statistics.
type Stats struct {
	TotalComponents   int              `json:"total_components"`
	ByType            map[string]int   `json:"by_type,omitempty"`
	ByLicense         map[string]int   `json:"by_license,omitempty"`
	WithoutLicense    int              `json:"without_license"`
	WithHashes        int              `json:"with_hashes"`
	WithoutHashes     int              `json:"without_hashes"`
	TotalDependencies int              `json:"total_dependencies"`
	WithDependencies  int              `json:"with_dependencies"`
	DuplicateCount    int              `json:"duplicate_count"`
	Duplicates        []DuplicateGroup `json:"duplicates,omitempty"`

	ByLanguage        map[string]int   `json:"by_language,omitempty"`
	ByFoundBy         map[string]int   `json:"by_found_by,omitempty"`
	LicenseCategories *LicenseCategory `json:"license_categories,omitempty"`
	WithCPEs          int              `json:"with_cpes"`
	WithoutCPEs       int              `json:"without_cpes"`
	WithPURL          int              `json:"with_purl"`
	WithoutPURL       int              `json:"without_purl"`
}

// LicenseCategory groups license counts.
type LicenseCategory struct {
	Copyleft    int `json:"copyleft"`    // GPL, LGPL, AGPL, etc.
	Permissive  int `json:"permissive"`  // MIT, BSD, Apache, etc.
	PublicDomain int `json:"public_domain"`
	Unknown     int `json:"unknown"`
}

// ComputeStats calculates SBOM statistics.
func ComputeStats(comps []sbom.Component) Stats {
	stats := Stats{
		ByType:     make(map[string]int),
		ByLicense:  make(map[string]int),
		ByLanguage: make(map[string]int),
		ByFoundBy:  make(map[string]int),
	}

	stats.TotalComponents = len(comps)
	licenseCategories := &LicenseCategory{}

	for _, c := range comps {
		ptype := ExtractPURLType(c.PURL)
		if ptype == "unknown" && c.PURL == "" {
			ptype = ExtractPURLType(c.ID)
		}
		stats.ByType[ptype]++

		if c.Language != "" {
			stats.ByLanguage[c.Language]++
		}

		if c.FoundBy != "" {
			stats.ByFoundBy[c.FoundBy]++
		}

		if len(c.Licenses) == 0 {
			stats.WithoutLicense++
			licenseCategories.Unknown++
		} else {
			for _, lic := range c.Licenses {
				stats.ByLicense[lic]++
			}
			category := CategorizeLicense(c.Licenses[0])
			switch category {
			case "copyleft":
				licenseCategories.Copyleft++
			case "permissive":
				licenseCategories.Permissive++
			case "public_domain":
				licenseCategories.PublicDomain++
			default:
				licenseCategories.Unknown++
			}
		}

		if len(c.Hashes) > 0 {
			stats.WithHashes++
		} else {
			stats.WithoutHashes++
		}

		if len(c.CPEs) > 0 {
			stats.WithCPEs++
		} else {
			stats.WithoutCPEs++
		}

		if c.PURL != "" {
			stats.WithPURL++
		} else {
			stats.WithoutPURL++
		}

		if len(c.Dependencies) > 0 {
			stats.WithDependencies++
			stats.TotalDependencies += len(c.Dependencies)
		}
	}

	if stats.TotalComponents > 0 {
		stats.LicenseCategories = licenseCategories
	}

	if len(stats.ByLanguage) == 0 {
		stats.ByLanguage = nil
	}
	if len(stats.ByFoundBy) == 0 {
		stats.ByFoundBy = nil
	}

	dups := DetectDuplicates(comps)
	stats.DuplicateCount = len(dups)
	if len(dups) > 0 {
		stats.Duplicates = dups
	}

	return stats
}

// CategorizeLicense returns copyleft/permissive/public_domain/unknown.
func CategorizeLicense(license string) string {
	lic := strings.ToUpper(license)

	copyleftPrefixes := []string{"GPL", "LGPL", "AGPL", "MPL", "EPL", "CPL", "CDDL", "EUPL"}
	for _, prefix := range copyleftPrefixes {
		if strings.Contains(lic, prefix) {
			return "copyleft"
		}
	}

	permissivePrefixes := []string{"MIT", "BSD", "APACHE", "ISC", "ZLIB", "UNLICENSE", "WTFPL", "CC0", "EXPAT", "X11"}
	for _, prefix := range permissivePrefixes {
		if strings.Contains(lic, prefix) {
			return "permissive"
		}
	}

	if strings.Contains(lic, "PUBLIC-DOMAIN") || strings.Contains(lic, "PUBLIC DOMAIN") || strings.Contains(lic, "PUBLICDOMAIN") {
		return "public_domain"
	}

	return "unknown"
}

// ExtractPURLType extracts the type segment from a PURL.
func ExtractPURLType(purl string) string {
	if purl == "" || !strings.HasPrefix(purl, "pkg:") {
		return "unknown"
	}
	rest := purl[4:]
	if ptype, _, ok := strings.Cut(rest, "/"); ok {
		return ptype
	}
	return "unknown"
}

// PrintStats prints SBOM statistics.
func PrintStats(stats Stats) {
	fmt.Printf("\n📦 SBOM Statistics\n")
	fmt.Printf("==================\n\n")

	fmt.Printf("Total Components: %d\n\n", stats.TotalComponents)

	if len(stats.ByType) > 0 {
		fmt.Printf("By Package Type:\n")
		types := SortedKeys(stats.ByType)
		for _, t := range types {
			fmt.Printf("  %-12s %d\n", t, stats.ByType[t])
		}
		fmt.Println()
	}

	fmt.Printf("Licenses:\n")
	fmt.Printf("  With license:    %d\n", stats.TotalComponents-stats.WithoutLicense)
	fmt.Printf("  Without license: %d\n", stats.WithoutLicense)
	if len(stats.ByLicense) > 0 {
		fmt.Printf("\n  Top Licenses:\n")
		licenses := SortedByValue(stats.ByLicense)
		count := 0
		for _, lic := range licenses {
			if count >= 10 {
				fmt.Printf("    ... and %d more\n", len(licenses)-10)
				break
			}
			fmt.Printf("    %-30s %d\n", lic, stats.ByLicense[lic])
			count++
		}
	}
	fmt.Println()

	fmt.Printf("Integrity:\n")
	fmt.Printf("  With hashes:    %d\n", stats.WithHashes)
	fmt.Printf("  Without hashes: %d\n", stats.WithoutHashes)
	fmt.Println()

	fmt.Printf("Dependencies:\n")
	fmt.Printf("  Components with deps: %d\n", stats.WithDependencies)
	fmt.Printf("  Total dep relations:  %d\n", stats.TotalDependencies)
	fmt.Println()

	if stats.DuplicateCount > 0 {
		fmt.Printf("⚠️  Duplicates Found: %d\n", stats.DuplicateCount)
		for _, d := range stats.Duplicates {
			fmt.Printf("  %s: %v\n", d.Name, d.Versions)
		}
		fmt.Println()
	}
}

func SortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func SortedByValue(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return m[keys[i]] > m[keys[j]]
	})
	return keys
}

// SBOMSide holds one side of a diff.
type SBOMSide struct {
	FileName string        `json:"file_name"`
	FileSize int64         `json:"file_size"`
	Info     sbom.SBOMInfo `json:"info"`
	Stats    Stats         `json:"stats"`
}

// DiffOverview holds side-by-side comparison.
type DiffOverview struct {
	Before SBOMSide `json:"before"`
	After  SBOMSide `json:"after"`
}

// ComputeDiffOverview builds the comparison overview.
func ComputeDiffOverview(file1, file2 string, comps1, comps2 []sbom.Component, info1, info2 sbom.SBOMInfo) DiffOverview {
	var size1, size2 int64
	if fi, err := os.Stat(file1); err == nil {
		size1 = fi.Size()
	}
	if fi, err := os.Stat(file2); err == nil {
		size2 = fi.Size()
	}

	return DiffOverview{
		Before: SBOMSide{
			FileName: file1,
			FileSize: size1,
			Info:     info1,
			Stats:    ComputeStats(comps1),
		},
		After: SBOMSide{
			FileName: file2,
			FileSize: size2,
			Info:     info2,
			Stats:    ComputeStats(comps2),
		},
	}
}
