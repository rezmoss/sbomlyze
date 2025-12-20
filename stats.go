package main

import (
	"fmt"
	"sort"
	"strings"
)

type SBOMStats struct {
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
}

func computeStats(comps []Component) SBOMStats {
	stats := SBOMStats{
		ByType:    make(map[string]int),
		ByLicense: make(map[string]int),
	}

	stats.TotalComponents = len(comps)

	for _, c := range comps {
		// Count by type
		ptype := extractPURLType(c.ID)
		stats.ByType[ptype]++

		// Count licenses
		if len(c.Licenses) == 0 {
			stats.WithoutLicense++
		} else {
			for _, lic := range c.Licenses {
				stats.ByLicense[lic]++
			}
		}

		// Count hashes
		if len(c.Hashes) > 0 {
			stats.WithHashes++
		} else {
			stats.WithoutHashes++
		}

		// Count dependencies
		if len(c.Dependencies) > 0 {
			stats.WithDependencies++
			stats.TotalDependencies += len(c.Dependencies)
		}
	}

	// Detect duplicates
	dups := detectDuplicates(comps)
	stats.DuplicateCount = len(dups)
	if len(dups) > 0 {
		stats.Duplicates = dups
	}

	return stats
}

func extractPURLType(purl string) string {
	if purl == "" || !strings.HasPrefix(purl, "pkg:") {
		return "unknown"
	}
	// pkg:type/...
	rest := purl[4:] // remove "pkg:"
	idx := strings.Index(rest, "/")
	if idx == -1 {
		return "unknown"
	}
	return rest[:idx]
}

func printStats(stats SBOMStats) {
	fmt.Printf("\n📦 SBOM Statistics\n")
	fmt.Printf("==================\n\n")

	fmt.Printf("Total Components: %d\n\n", stats.TotalComponents)

	// By type
	if len(stats.ByType) > 0 {
		fmt.Printf("By Package Type:\n")
		types := sortedKeys(stats.ByType)
		for _, t := range types {
			fmt.Printf("  %-12s %d\n", t, stats.ByType[t])
		}
		fmt.Println()
	}

	// Licenses
	fmt.Printf("Licenses:\n")
	fmt.Printf("  With license:    %d\n", stats.TotalComponents-stats.WithoutLicense)
	fmt.Printf("  Without license: %d\n", stats.WithoutLicense)
	if len(stats.ByLicense) > 0 {
		fmt.Printf("\n  Top Licenses:\n")
		licenses := sortedByValue(stats.ByLicense)
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

	// Hashes
	fmt.Printf("Integrity:\n")
	fmt.Printf("  With hashes:    %d\n", stats.WithHashes)
	fmt.Printf("  Without hashes: %d\n", stats.WithoutHashes)
	fmt.Println()

	// Dependencies
	fmt.Printf("Dependencies:\n")
	fmt.Printf("  Components with deps: %d\n", stats.WithDependencies)
	fmt.Printf("  Total dep relations:  %d\n", stats.TotalDependencies)
	fmt.Println()

	// Duplicates
	if stats.DuplicateCount > 0 {
		fmt.Printf("⚠️  Duplicates Found: %d\n", stats.DuplicateCount)
		for _, d := range stats.Duplicates {
			fmt.Printf("  %s: %v\n", d.Name, d.Versions)
		}
		fmt.Println()
	}
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedByValue(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return m[keys[i]] > m[keys[j]]
	})
	return keys
}
