package analysis

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

var versionNumRe = regexp.MustCompile(`^(\d+)`)

// Finding is a single insight.
type Finding struct {
	Icon    string `json:"icon"`    // emoji for text output
	Message string `json:"message"` // human-readable finding
}

// KeyFindings holds computed insights.
type KeyFindings struct {
	Findings []Finding `json:"findings"`
}

// ComputeSingleFindings produces insights for a single SBOM.
func ComputeSingleFindings(stats Stats, info sbom.SBOMInfo, comps []sbom.Component) KeyFindings {
	var findings []Finding

	findings = append(findings, detectSingleOS(info)...)
	findings = append(findings, detectDominantType(stats)...)
	findings = append(findings, detectFilesystemFootprint(info)...)
	findings = append(findings, detectRelationshipDensity(info, stats)...)
	findings = append(findings, detectLocationHotspots(comps)...)
	findings = append(findings, detectLicenseRiskProfile(stats)...)
	findings = append(findings, detectDataQuality(stats)...)
	findings = append(findings, detectDuplicateWarning(stats)...)
	findings = append(findings, detectCatalogerBreakdown(stats)...)

	return KeyFindings{Findings: findings}
}

func detectFilesystemFootprint(info sbom.SBOMInfo) []Finding {
	if info.FilesCount == 0 {
		return nil
	}
	return []Finding{{
		Icon:    "\U0001f4c2",
		Message: fmt.Sprintf("%s files tracked on filesystem", fmtCount(info.FilesCount)),
	}}
}

func detectRelationshipDensity(info sbom.SBOMInfo, stats Stats) []Finding {
	if len(info.RelationshipCounts) == 0 {
		return nil
	}
	contains := info.RelationshipCounts["contains"]
	depOf := info.RelationshipCounts["dependency-of"]
	if contains == 0 && depOf == 0 {
		return nil
	}
	parts := make([]string, 0, 2)
	if contains > 0 {
		parts = append(parts, fmt.Sprintf("%s containment", fmtCount(contains)))
	}
	if depOf > 0 {
		parts = append(parts, fmt.Sprintf("%s dependency", fmtCount(depOf)))
	}
	return []Finding{{
		Icon:    "\U0001f517",
		Message: fmt.Sprintf("Relationships: %s", strings.Join(parts, " + ")),
	}}
}

func detectLocationHotspots(comps []sbom.Component) []Finding {
	if len(comps) < 20 {
		return nil
	}
	dirCounts := make(map[string]int)
	for _, c := range comps {
		prefix := topPathPrefix(c.Locations)
		if prefix != "" {
			dirCounts[prefix]++
		}
	}
	if len(dirCounts) == 0 {
		return nil
	}
	dirs := SortedByValue(dirCounts)
	limit := len(dirs)
	if limit > 4 {
		limit = 4
	}
	parts := make([]string, limit)
	for i := 0; i < limit; i++ {
		d := dirs[i]
		parts[i] = fmt.Sprintf("%s (%s)", d, fmtCount(dirCounts[d]))
	}
	return []Finding{{
		Icon:    "\U0001f4c1",
		Message: fmt.Sprintf("Top directories: %s", strings.Join(parts, ", ")),
	}}
}

func detectLicenseRiskProfile(stats Stats) []Finding {
	if stats.LicenseCategories == nil || stats.TotalComponents == 0 {
		return nil
	}
	lc := stats.LicenseCategories
	total := stats.TotalComponents
	var parts []string
	if lc.Permissive > 0 {
		parts = append(parts, fmt.Sprintf("%.0f%% permissive", float64(lc.Permissive)/float64(total)*100))
	}
	if lc.Copyleft > 0 {
		parts = append(parts, fmt.Sprintf("%.0f%% copyleft", float64(lc.Copyleft)/float64(total)*100))
	}
	unknownPct := float64(lc.Unknown) / float64(total) * 100
	if unknownPct > 10 {
		parts = append(parts, fmt.Sprintf("%.0f%% unknown", unknownPct))
	}
	if len(parts) == 0 {
		return nil
	}
	return []Finding{{
		Icon:    "\U0001f4dc",
		Message: fmt.Sprintf("License profile: %s", strings.Join(parts, ", ")),
	}}
}

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

func detectDominantType(stats Stats) []Finding {
	if len(stats.ByType) == 0 {
		return nil
	}

	total := stats.TotalComponents
	if total == 0 {
		return nil
	}

	types := SortedByValue(stats.ByType)
	topType := types[0]
	topCount := stats.ByType[topType]
	pct := float64(topCount) / float64(total) * 100

	if pct >= 60.0 {
		return []Finding{{
			Icon:    "\U0001f4e6",
			Message: fmt.Sprintf("Dominated by %s: %s of %s packages (%.1f%%)", topType, fmtCount(topCount), fmtCount(total), pct),
		}}
	}

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

func detectDataQuality(stats Stats) []Finding {
	if stats.TotalComponents == 0 {
		return nil
	}

	var findings []Finding
	total := stats.TotalComponents

	licensePct := float64(total-stats.WithoutLicense) / float64(total) * 100
	if licensePct < 50.0 {
		findings = append(findings, Finding{
			Icon:    "\u26a0\ufe0f",
			Message: fmt.Sprintf("Low license coverage: %.1f%% (%d of %d missing)", licensePct, stats.WithoutLicense, total),
		})
	}

	hashPct := float64(stats.WithHashes) / float64(total) * 100
	if hashPct < 50.0 {
		findings = append(findings, Finding{
			Icon:    "\u26a0\ufe0f",
			Message: fmt.Sprintf("Low hash coverage: %.1f%% (%d of %d missing)", hashPct, stats.WithoutHashes, total),
		})
	}

	purlPct := float64(stats.WithPURL) / float64(total) * 100
	if purlPct < 80.0 {
		findings = append(findings, Finding{
			Icon:    "\u26a0\ufe0f",
			Message: fmt.Sprintf("Low PURL coverage: %.1f%% (%d of %d missing)", purlPct, stats.WithoutPURL, total),
		})
	}

	return findings
}

func detectDuplicateWarning(stats Stats) []Finding {
	if stats.DuplicateCount == 0 {
		return nil
	}
	return []Finding{{
		Icon:    "\u26a0\ufe0f",
		Message: fmt.Sprintf("%d duplicate component groups detected", stats.DuplicateCount),
	}}
}

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

// ComputeKeyFindings produces insights from a diff.
func ComputeKeyFindings(result DiffResult, overview DiffOverview) KeyFindings {
	var findings []Finding

	findings = append(findings, detectScanContextMismatch(overview)...)
	findings = append(findings, detectAttackSurfaceDelta(overview)...)
	findings = append(findings, detectVanishedEcosystems(overview)...)
	findings = append(findings, detectOSChange(overview)...)
	findings = append(findings, detectVersionChangeAnalysis(result, overview)...)
	findings = append(findings, detectIntegrityDriftContext(result)...)
	findings = append(findings, detectDominantPathPattern(result)...)
	findings = append(findings, detectRemovalHotspots(result)...)
	findings = append(findings, detectStableTypes(overview)...)
	findings = append(findings, detectLicenseCategoryShift(overview)...)
	findings = append(findings, detectCatalogerGaps(overview)...)

	return KeyFindings{Findings: findings}
}

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

func detectVanishedEcosystems(overview DiffOverview) []Finding {
	var findings []Finding

	bTypes := overview.Before.Stats.ByType
	aTypes := overview.After.Stats.ByType

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

func detectOSChange(overview DiffOverview) []Finding {
	bOS := overview.Before.Info.OSPrettyName
	aOS := overview.After.Info.OSPrettyName
	if bOS == "" {
		bOS = overview.Before.Info.OSName
	}
	if aOS == "" {
		aOS = overview.After.Info.OSName
	}

	if bOS == aOS {
		return nil
	}

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

func parseVersionParts(v string) []int {
	parts := regexp.MustCompile(`[.\-_]`).Split(v, -1)
	var nums []int
	for _, p := range parts {
		m := versionNumRe.FindString(p)
		if m != "" {
			n, _ := strconv.Atoi(m)
			nums = append(nums, n)
		}
	}
	return nums
}

// compareVersions returns 1 if b>a (upgrade), -1 if b<a (downgrade), 0 if equal/unclear
func compareVersions(from, to string) int {
	pf := parseVersionParts(from)
	pt := parseVersionParts(to)
	if len(pf) == 0 || len(pt) == 0 {
		return 0
	}
	maxLen := len(pf)
	if len(pt) > maxLen {
		maxLen = len(pt)
	}
	for i := 0; i < maxLen; i++ {
		var a, b int
		if i < len(pf) {
			a = pf[i]
		}
		if i < len(pt) {
			b = pt[i]
		}
		if b > a {
			return 1
		}
		if b < a {
			return -1
		}
	}
	return 0
}

func classifySemVerChange(from, to string) string {
	pf := parseVersionParts(from)
	pt := parseVersionParts(to)
	if len(pf) == 0 || len(pt) == 0 {
		return "unknown"
	}
	var fMajor, tMajor int
	fMajor = pf[0]
	tMajor = pt[0]
	if fMajor != tMajor {
		return "major"
	}
	var fMinor, tMinor int
	if len(pf) > 1 {
		fMinor = pf[1]
	}
	if len(pt) > 1 {
		tMinor = pt[1]
	}
	if fMinor != tMinor {
		return "minor"
	}
	return "patch"
}

func detectVersionChangeAnalysis(result DiffResult, overview DiffOverview) []Finding {
	totalBefore := overview.Before.Stats.TotalComponents
	removed := len(result.Removed)
	shared := totalBefore - removed
	if shared <= 0 {
		return nil
	}

	var upgrades, downgrades, unclear int
	var majorUp, minorUp, patchUp int
	type downgradeInfo struct {
		name    string
		from    string
		to      string
	}
	var topDowngrades []downgradeInfo

	for _, c := range result.Changed {
		if c.Drift == nil || c.Drift.Type != DriftTypeVersion {
			continue
		}
		vFrom := c.Before.Version
		vTo := c.After.Version
		dir := compareVersions(vFrom, vTo)
		switch dir {
		case 1:
			upgrades++
			switch classifySemVerChange(vFrom, vTo) {
			case "major":
				majorUp++
			case "minor":
				minorUp++
			default:
				patchUp++
			}
		case -1:
			downgrades++
			if len(topDowngrades) < 5 {
				topDowngrades = append(topDowngrades, downgradeInfo{c.Name, vFrom, vTo})
			}
		default:
			unclear++
		}
	}

	totalChanges := upgrades + downgrades + unclear
	if totalChanges == 0 {
		return []Finding{{
			Icon:    "\U0001f504",
			Message: fmt.Sprintf("0 version changes among %s shared packages \u2014 no actual upgrades", fmtCount(shared)),
		}}
	}

	var findings []Finding

	if downgrades > 0 {
		names := make([]string, len(topDowngrades))
		for i, d := range topDowngrades {
			names[i] = fmt.Sprintf("%s %s\u2192%s", d.name, d.from, d.to)
		}
		msg := fmt.Sprintf("%d version downgrades detected: %s", downgrades, strings.Join(names, ", "))
		if downgrades > len(topDowngrades) {
			msg += fmt.Sprintf(" + %d more", downgrades-len(topDowngrades))
		}
		findings = append(findings, Finding{
			Icon:    "\U0001f6a8",
			Message: msg,
		})
	}

	if upgrades > 0 {
		msg := fmt.Sprintf("%d version upgrades", upgrades)
		if majorUp > 0 || minorUp > 0 {
			parts := make([]string, 0, 3)
			if majorUp > 0 {
				parts = append(parts, fmt.Sprintf("%d major", majorUp))
			}
			if minorUp > 0 {
				parts = append(parts, fmt.Sprintf("%d minor", minorUp))
			}
			if patchUp > 0 {
				parts = append(parts, fmt.Sprintf("%d patch", patchUp))
			}
			msg += fmt.Sprintf(" (%s)", strings.Join(parts, ", "))
		}
		msg += fmt.Sprintf(" among %s shared packages", fmtCount(shared))
		findings = append(findings, Finding{
			Icon:    "\U0001f504",
			Message: msg,
		})
	}

	return findings
}

func detectAttackSurfaceDelta(overview DiffOverview) []Finding {
	bTotal := overview.Before.Stats.TotalComponents
	aTotal := overview.After.Stats.TotalComponents
	if bTotal == 0 && aTotal == 0 {
		return nil
	}

	var parts []string

	pkgDelta := aTotal - bTotal
	if pkgDelta != 0 {
		pct := float64(pkgDelta) / float64(bTotal) * 100
		parts = append(parts, fmt.Sprintf("%+d packages (%.1f%%)", pkgDelta, pct))
	}

	bFiles := overview.Before.Info.FilesCount
	aFiles := overview.After.Info.FilesCount
	if bFiles > 0 && aFiles > 0 && bFiles != aFiles {
		fileDelta := aFiles - bFiles
		pct := float64(fileDelta) / float64(bFiles) * 100
		parts = append(parts, fmt.Sprintf("%+d files (%.1f%%)", fileDelta, pct))
	}

	bContains := overview.Before.Info.RelationshipCounts["contains"]
	aContains := overview.After.Info.RelationshipCounts["contains"]
	if bContains > 0 && aContains > 0 && bContains != aContains {
		relDelta := aContains - bContains
		pct := float64(relDelta) / float64(bContains) * 100
		parts = append(parts, fmt.Sprintf("%+d relationships (%.1f%%)", relDelta, pct))
	}

	if len(parts) == 0 {
		return nil
	}

	icon := "\U0001f4c9" // chart decreasing
	if pkgDelta > 0 {
		icon = "\U0001f4c8" // chart increasing
	}

	return []Finding{{
		Icon:    icon,
		Message: fmt.Sprintf("Attack surface: %s", strings.Join(parts, ", ")),
	}}
}

func detectRemovalHotspots(result DiffResult) []Finding {
	var findings []Finding
	if f := pathHotspots(result.Removed, "removal"); f != nil {
		findings = append(findings, *f)
	}
	if f := pathHotspots(result.Added, "addition"); f != nil {
		findings = append(findings, *f)
	}
	return findings
}

func pathHotspots(comps []sbom.Component, direction string) *Finding {
	if len(comps) < 20 {
		return nil
	}
	dirCounts := make(map[string]int)
	for _, c := range comps {
		prefix := topPathPrefix(c.Locations)
		if prefix != "" {
			dirCounts[prefix]++
		}
	}
	if len(dirCounts) == 0 {
		return nil
	}
	dirs := SortedByValue(dirCounts)
	limit := len(dirs)
	if limit > 4 {
		limit = 4
	}
	parts := make([]string, limit)
	for i := 0; i < limit; i++ {
		d := dirs[i]
		parts[i] = fmt.Sprintf("%s (%s)", d, fmtCount(dirCounts[d]))
	}
	return &Finding{
		Icon:    "\U0001f4c1",
		Message: fmt.Sprintf("Top %s areas: %s", direction, strings.Join(parts, ", ")),
	}
}

func detectIntegrityDriftContext(result DiffResult) []Finding {
	typeCounts := make(map[string]int)
	for _, c := range result.Changed {
		if c.Drift == nil || c.Drift.Type != DriftTypeIntegrity {
			continue
		}
		ptype := ExtractPURLType(c.Before.PURL)
		if ptype == "unknown" && c.Before.PURL == "" {
			ptype = ExtractPURLType(c.Before.ID)
		}
		typeCounts[ptype]++
	}
	if len(typeCounts) == 0 {
		return nil
	}

	types := SortedByValue(typeCounts)
	parts := make([]string, 0, len(types))
	for _, t := range types {
		note := ""
		switch t {
		case "rpm", "deb", "apk":
			note = " (expected for rebuilds)"
		case "maven", "npm", "pypi", "golang":
			note = " (review recommended)"
		}
		parts = append(parts, fmt.Sprintf("%d %s%s", typeCounts[t], t, note))
	}

	total := 0
	for _, v := range typeCounts {
		total += v
	}

	return []Finding{{
		Icon:    "\u26a0\ufe0f",
		Message: fmt.Sprintf("Integrity drift (%d total): %s", total, strings.Join(parts, ", ")),
	}}
}

func detectLicenseCategoryShift(overview DiffOverview) []Finding {
	bLC := overview.Before.Stats.LicenseCategories
	aLC := overview.After.Stats.LicenseCategories
	if bLC == nil || aLC == nil {
		return nil
	}

	var parts []string
	if d := aLC.Copyleft - bLC.Copyleft; d != 0 {
		parts = append(parts, fmt.Sprintf("copyleft %+d", d))
	}
	if d := aLC.Permissive - bLC.Permissive; d != 0 {
		parts = append(parts, fmt.Sprintf("permissive %+d", d))
	}

	if len(parts) == 0 {
		return nil
	}

	return []Finding{{
		Icon:    "\U0001f4dc",
		Message: fmt.Sprintf("License shift: %s", strings.Join(parts, ", ")),
	}}
}

func detectCatalogerGaps(overview DiffOverview) []Finding {
	bFoundBy := overview.Before.Stats.ByFoundBy
	aFoundBy := overview.After.Stats.ByFoundBy
	if len(bFoundBy) == 0 {
		return nil
	}

	var findings []Finding
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

func fmtCount(n int) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	s := fmt.Sprintf("%d", n)
	var result []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}
