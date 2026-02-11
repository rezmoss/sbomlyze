package analysis

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

// Finding represents a single auto-detected insight from the diff
type Finding struct {
	Icon    string `json:"icon"`    // emoji for text output
	Message string `json:"message"` // human-readable finding
}

// KeyFindings holds the computed list of findings
type KeyFindings struct {
	Findings []Finding `json:"findings"`
}

// ComputeSingleFindings analyzes a single SBOM and produces key insights
func ComputeSingleFindings(stats Stats, info sbom.SBOMInfo, comps []sbom.Component) KeyFindings {
	var findings []Finding

	findings = append(findings, detectSingleOS(info)...)
	findings = append(findings, detectDominantType(stats)...)
	findings = append(findings, detectDataQuality(stats)...)
	findings = append(findings, detectDuplicateWarning(stats)...)
	findings = append(findings, detectCatalogerBreakdown(stats)...)

	return KeyFindings{Findings: findings}
}

// detectSingleOS reports OS/distro for a single SBOM
func detectSingleOS(info sbom.SBOMInfo) []Finding {
	os := info.OSPrettyName
	if os == "" {
		os = info.OSName
	}
	if os == "" {
		return nil
	}
	msg := fmt.Sprintf("OS/Distro: %s", os)
	if info.OSVersion != "" && !strings.Contains(os, info.OSVersion) {
		msg = fmt.Sprintf("OS/Distro: %s %s", os, info.OSVersion)
	}
	return []Finding{{Icon: "\U0001f4bb", Message: msg}}
}

// detectDominantType reports the top ecosystem(s) by package count
func detectDominantType(stats Stats) []Finding {
	if len(stats.ByType) == 0 {
		return nil
	}

	total := stats.TotalComponents
	if total == 0 {
		return nil
	}

	types := SortedByValue(stats.ByType)
	// Report top type if it dominates (>60%)
	topType := types[0]
	topCount := stats.ByType[topType]
	pct := float64(topCount) / float64(total) * 100

	if pct >= 60.0 {
		return []Finding{{
			Icon:    "\U0001f4e6",
			Message: fmt.Sprintf("Dominated by %s: %s of %s packages (%.1f%%)", topType, fmtCount(topCount), fmtCount(total), pct),
		}}
	}

	// Otherwise summarize top 3
	limit := len(types)
	if limit > 3 {
		limit = 3
	}
	parts := make([]string, limit)
	for i := 0; i < limit; i++ {
		t := types[i]
		parts[i] = fmt.Sprintf("%s (%s)", t, fmtCount(stats.ByType[t]))
	}
	remaining := len(types) - limit
	msg := fmt.Sprintf("Top ecosystems: %s", strings.Join(parts, ", "))
	if remaining > 0 {
		msg += fmt.Sprintf(" + %d more", remaining)
	}
	return []Finding{{Icon: "\U0001f4e6", Message: msg}}
}

// detectDataQuality highlights significant gaps in data quality
func detectDataQuality(stats Stats) []Finding {
	if stats.TotalComponents == 0 {
		return nil
	}

	var findings []Finding
	total := stats.TotalComponents

	// License coverage
	licensePct := float64(total-stats.WithoutLicense) / float64(total) * 100
	if licensePct < 50.0 {
		findings = append(findings, Finding{
			Icon:    "\u26a0\ufe0f",
			Message: fmt.Sprintf("Low license coverage: %.1f%% (%d of %d missing)", licensePct, stats.WithoutLicense, total),
		})
	}

	// Hash coverage
	hashPct := float64(stats.WithHashes) / float64(total) * 100
	if hashPct < 50.0 {
		findings = append(findings, Finding{
			Icon:    "\u26a0\ufe0f",
			Message: fmt.Sprintf("Low hash coverage: %.1f%% (%d of %d missing)", hashPct, stats.WithoutHashes, total),
		})
	}

	// PURL coverage
	purlPct := float64(stats.WithPURL) / float64(total) * 100
	if purlPct < 80.0 {
		findings = append(findings, Finding{
			Icon:    "\u26a0\ufe0f",
			Message: fmt.Sprintf("Low PURL coverage: %.1f%% (%d of %d missing)", purlPct, stats.WithoutPURL, total),
		})
	}

	return findings
}

// detectDuplicateWarning warns about duplicates in a single SBOM
func detectDuplicateWarning(stats Stats) []Finding {
	if stats.DuplicateCount == 0 {
		return nil
	}
	return []Finding{{
		Icon:    "\u26a0\ufe0f",
		Message: fmt.Sprintf("%d duplicate component groups detected", stats.DuplicateCount),
	}}
}

// detectCatalogerBreakdown summarizes which scanners/catalogers contributed
func detectCatalogerBreakdown(stats Stats) []Finding {
	if len(stats.ByFoundBy) == 0 {
		return nil
	}

	catalogers := SortedByValue(stats.ByFoundBy)
	limit := len(catalogers)
	if limit > 3 {
		limit = 3
	}
	parts := make([]string, limit)
	for i := 0; i < limit; i++ {
		c := catalogers[i]
		parts[i] = fmt.Sprintf("%s (%s)", c, fmtCount(stats.ByFoundBy[c]))
	}
	remaining := len(catalogers) - limit
	msg := fmt.Sprintf("Top catalogers: %s", strings.Join(parts, ", "))
	if remaining > 0 {
		msg += fmt.Sprintf(" + %d more", remaining)
	}
	return []Finding{{Icon: "\U0001f50d", Message: msg}}
}

// ComputeKeyFindings analyzes a DiffResult and DiffOverview to produce key insights
func ComputeKeyFindings(result DiffResult, overview DiffOverview) KeyFindings {
	var findings []Finding

	findings = append(findings, detectScanContextMismatch(overview)...)
	findings = append(findings, detectVanishedEcosystems(overview)...)
	findings = append(findings, detectOSChange(overview)...)
	findings = append(findings, detectDominantPathPattern(result)...)
	findings = append(findings, detectStableTypes(overview)...)
	findings = append(findings, detectSharedVersionStability(result, overview)...)
	findings = append(findings, detectCatalogerGaps(overview)...)

	return KeyFindings{Findings: findings}
}

// detectScanContextMismatch warns if schema version or scan scope changed
func detectScanContextMismatch(overview DiffOverview) []Finding {
	var findings []Finding

	bScope := overview.Before.Info.SearchScope
	aScope := overview.After.Info.SearchScope
	if bScope != "" && aScope != "" && bScope != aScope {
		findings = append(findings, Finding{
			Icon:    "\u26a0\ufe0f",
			Message: fmt.Sprintf("Warning: scan scope changed (%s \u2192 %s) \u2014 diff may reflect scan depth, not system changes", bScope, aScope),
		})
	}

	bSchema := overview.Before.Info.SchemaVersion
	aSchema := overview.After.Info.SchemaVersion
	if bSchema != "" && aSchema != "" && bSchema != aSchema {
		findings = append(findings, Finding{
			Icon:    "\u26a0\ufe0f",
			Message: fmt.Sprintf("Warning: schema version changed (%s \u2192 %s) \u2014 PURL format may differ", bSchema, aSchema),
		})
	}

	return findings
}

// detectVanishedEcosystems finds package types that went from >0 to 0 or 0 to >0
func detectVanishedEcosystems(overview DiffOverview) []Finding {
	var findings []Finding

	bTypes := overview.Before.Stats.ByType
	aTypes := overview.After.Stats.ByType

	// Types that vanished (before > 0, after == 0)
	vanished := make([]string, 0)
	for t := range bTypes {
		if bTypes[t] > 0 && aTypes[t] == 0 {
			vanished = append(vanished, t)
		}
	}
	sort.Slice(vanished, func(i, j int) bool {
		return bTypes[vanished[i]] > bTypes[vanished[j]]
	})
	for _, t := range vanished {
		findings = append(findings, Finding{
			Icon:    "\u274c",
			Message: fmt.Sprintf("%s ecosystem entirely removed (%s \u2192 0 packages)", t, fmtCount(bTypes[t])),
		})
	}

	// Types that appeared (before == 0, after > 0)
	appeared := make([]string, 0)
	for t := range aTypes {
		if aTypes[t] > 0 && bTypes[t] == 0 {
			appeared = append(appeared, t)
		}
	}
	sort.Slice(appeared, func(i, j int) bool {
		return aTypes[appeared[i]] > aTypes[appeared[j]]
	})
	for _, t := range appeared {
		findings = append(findings, Finding{
			Icon:    "\u2795",
			Message: fmt.Sprintf("New ecosystem: %s (%d packages)", t, aTypes[t]),
		})
	}

	return findings
}

// detectOSChange detects changes in OS/distro between the two SBOMs
func detectOSChange(overview DiffOverview) []Finding {
	bOS := overview.Before.Info.OSPrettyName
	aOS := overview.After.Info.OSPrettyName
	// Fall back to OSName if PrettyName is empty
	if bOS == "" {
		bOS = overview.Before.Info.OSName
	}
	if aOS == "" {
		aOS = overview.After.Info.OSName
	}

	if bOS == aOS {
		return nil
	}

	// Both empty - nothing to report
	if bOS == "" && aOS == "" {
		return nil
	}

	bLabel := bOS
	if bLabel == "" {
		bLabel = "unknown"
	}
	aLabel := aOS
	if aLabel == "" {
		aLabel = "unknown"
	}

	msg := fmt.Sprintf("OS changed: %s \u2192 %s", bLabel, aLabel)
	if aLabel == "unknown" {
		msg = fmt.Sprintf("OS detection lost: %s \u2192 %s", bLabel, aLabel)
	}
	if bLabel == "unknown" {
		msg = fmt.Sprintf("OS detection gained: %s \u2192 %s", bLabel, aLabel)
	}

	return []Finding{{Icon: "\U0001f4bb", Message: msg}}
}

// detectDominantPathPattern finds if removed/added packages are concentrated in one path prefix and type
func detectDominantPathPattern(result DiffResult) []Finding {
	var findings []Finding

	if f := dominantPattern(result.Removed, "removed"); f != nil {
		findings = append(findings, *f)
	}
	if f := dominantPattern(result.Added, "added"); f != nil {
		findings = append(findings, *f)
	}

	return findings
}

func dominantPattern(comps []sbom.Component, direction string) *Finding {
	if len(comps) < 20 {
		return nil
	}

	// Group by PURL type + top-level path prefix
	type typePathKey struct {
		ptype string
		path  string
	}
	counts := make(map[typePathKey]int)
	typeCounts := make(map[string]int)

	for _, c := range comps {
		ptype := ExtractPURLType(c.PURL)
		if ptype == "unknown" && c.PURL == "" {
			ptype = ExtractPURLType(c.ID)
		}
		typeCounts[ptype]++

		prefix := topPathPrefix(c.Locations)
		if prefix != "" {
			counts[typePathKey{ptype, prefix}]++
		}
	}

	// Find the dominant type+path combo
	var bestKey typePathKey
	var bestCount int
	for k, v := range counts {
		if v > bestCount {
			bestKey = k
			bestCount = v
		}
	}

	total := len(comps)
	pct := float64(bestCount) / float64(total) * 100

	if pct < 50.0 || bestCount < 10 {
		return nil
	}

	return &Finding{
		Icon:    "\U0001f4c1",
		Message: fmt.Sprintf("%.1f%% of %s packages are %s, concentrated in %s", pct, direction, bestKey.ptype, bestKey.path),
	}
}

// topPathPrefix extracts the first 3 segments of the first location path
func topPathPrefix(locations []string) string {
	if len(locations) == 0 {
		return ""
	}
	path := locations[0]
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) > 3 {
		parts = parts[:3]
	}
	return "/" + strings.Join(parts, "/")
}

// detectStableTypes finds package types with identical counts between before and after
func detectStableTypes(overview DiffOverview) []Finding {
	bTypes := overview.Before.Stats.ByType
	aTypes := overview.After.Stats.ByType

	var stable []string
	for t, bCount := range bTypes {
		if bCount > 10 && aTypes[t] == bCount {
			stable = append(stable, t)
		}
	}

	if len(stable) == 0 {
		return nil
	}

	// Sort by count descending
	sort.Slice(stable, func(i, j int) bool {
		return bTypes[stable[i]] > bTypes[stable[j]]
	})

	parts := make([]string, len(stable))
	for i, t := range stable {
		parts[i] = fmt.Sprintf("%s (%s)", t, fmtCount(bTypes[t]))
	}

	return []Finding{{
		Icon:    "\u2705",
		Message: fmt.Sprintf("Core system packages stable: %s unchanged", strings.Join(parts, ", ")),
	}}
}

// detectSharedVersionStability reports how many shared packages have version changes
func detectSharedVersionStability(result DiffResult, overview DiffOverview) []Finding {
	// Shared = total before - removed (approximately)
	totalBefore := overview.Before.Stats.TotalComponents
	removed := len(result.Removed)
	shared := totalBefore - removed
	if shared <= 0 {
		return nil
	}

	// Count version changes among Changed
	versionChanges := 0
	for _, c := range result.Changed {
		if c.Drift != nil && c.Drift.Type == DriftTypeVersion {
			versionChanges++
		}
	}

	if versionChanges == 0 {
		return []Finding{{
			Icon:    "\U0001f504",
			Message: fmt.Sprintf("0 version changes among %s shared packages \u2014 no actual upgrades", fmtCount(shared)),
		}}
	}

	return []Finding{{
		Icon:    "\U0001f504",
		Message: fmt.Sprintf("%d version upgrades among %s shared packages", versionChanges, fmtCount(shared)),
	}}
}

// detectCatalogerGaps finds scanners that found packages in Before but none in After
func detectCatalogerGaps(overview DiffOverview) []Finding {
	bFoundBy := overview.Before.Stats.ByFoundBy
	aFoundBy := overview.After.Stats.ByFoundBy
	if len(bFoundBy) == 0 {
		return nil
	}

	var findings []Finding
	// Sort catalogers by count descending for deterministic output
	catalogers := SortedByValue(bFoundBy)
	for _, cat := range catalogers {
		bCount := bFoundBy[cat]
		aCount := aFoundBy[cat]
		if bCount > 0 && aCount == 0 {
			findings = append(findings, Finding{
				Icon:    "\U0001f50d",
				Message: fmt.Sprintf("%s found %s packages in Before but none in After", cat, fmtCount(bCount)),
			})
		}
	}

	return findings
}

// fmtCount formats a number with commas for readability
func fmtCount(n int) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	s := fmt.Sprintf("%d", n)
	// Insert commas from right
	var result []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}
