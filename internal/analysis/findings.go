package analysis

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rezmoss/sbomlyze/internal/identity"
	"github.com/rezmoss/sbomlyze/internal/sbom"
)

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

	// pkg-quality findings exclude file/os comps
	pkgStats := stats
	if pkg := sbom.PackageComponents(comps); len(pkg) != len(comps) {
		pkgStats = ComputeStats(pkg)
	}

	findings = append(findings, detectSingleOS(info)...)
	findings = append(findings, detectDominantType(pkgStats)...)
	findings = append(findings, detectFilesystemFootprint(info)...)
	findings = append(findings, detectRelationshipDensity(info, stats)...)
	findings = append(findings, detectLocationHotspots(comps)...)
	findings = append(findings, detectLicenseRiskProfile(pkgStats)...)
	findings = append(findings, detectDataQuality(pkgStats)...)
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
	limit := min(len(dirs), 4)
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

	limit := min(len(types), 3)
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
	limit := min(len(catalogers), 3)
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
	findings = append(findings, detectFileChanges(result)...)
	findings = append(findings, detectOwnedFileDrift(result)...)
	findings = append(findings, detectDominantPathPattern(result)...)
	findings = append(findings, detectRemovalHotspots(result)...)
	findings = append(findings, detectStableTypes(overview, result)...)
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
		if bTypes[vanished[i]] != bTypes[vanished[j]] {
			return bTypes[vanished[i]] > bTypes[vanished[j]]
		}
		return vanished[i] < vanished[j]
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
		if aTypes[appeared[i]] != aTypes[appeared[j]] {
			return aTypes[appeared[i]] > aTypes[appeared[j]]
		}
		return appeared[i] < appeared[j]
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
		// ties: smallest type/path, deterministic
		if v > bestCount || (v == bestCount && (k.ptype < bestKey.ptype || (k.ptype == bestKey.ptype && k.path < bestKey.path))) {
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

// componentType: PURL type for grouping findings
func componentType(c sbom.Component) string {
	ptype := ExtractPURLType(c.PURL)
	if ptype == "unknown" && c.PURL == "" {
		ptype = ExtractPURLType(c.ID)
	}
	return ptype
}

// changesByType: per-type changed and any-change counts
func changesByType(result DiffResult) (changed map[string]int, any map[string]int) {
	changed = make(map[string]int)
	any = make(map[string]int)
	for _, c := range result.Changed {
		t := componentType(c.Before)
		changed[t]++
		any[t]++
	}
	for _, c := range result.Added {
		any[componentType(c)]++
	}
	for _, c := range result.Removed {
		any[componentType(c)]++
	}
	for _, m := range result.Moved {
		any[ExtractPURLType(m.ID)]++
	}
	return changed, any
}

// detectStableTypes: "unchanged" only w/ zero changes
func detectStableTypes(overview DiffOverview, result DiffResult) []Finding {
	bTypes := overview.Before.Stats.ByType
	aTypes := overview.After.Stats.ByType
	changed, anyChange := changesByType(result)

	var stable, sameCount []string
	for t, bCount := range bTypes {
		if bCount > 10 && aTypes[t] == bCount {
			if anyChange[t] == 0 {
				stable = append(stable, t)
			} else {
				sameCount = append(sameCount, t)
			}
		}
	}
	byCount := func(list []string) {
		sort.Slice(list, func(i, j int) bool {
			if bTypes[list[i]] != bTypes[list[j]] {
				return bTypes[list[i]] > bTypes[list[j]]
			}
			return list[i] < list[j]
		})
	}
	byCount(stable)
	byCount(sameCount)

	var findings []Finding
	if len(stable) > 0 {
		parts := make([]string, len(stable))
		for i, t := range stable {
			parts[i] = fmt.Sprintf("%s (%s)", t, fmtCount(bTypes[t]))
		}
		findings = append(findings, Finding{
			Icon:    "\u2705",
			Message: fmt.Sprintf("Core system packages stable: %s unchanged", strings.Join(parts, ", ")),
		})
	}
	for _, t := range sameCount {
		detail := fmt.Sprintf("%d version changes", changed[t])
		if other := anyChange[t] - changed[t]; other > 0 {
			detail += fmt.Sprintf(", %d added/removed/moved", other)
		}
		findings = append(findings, Finding{
			Icon:    "\U0001f504",
			Message: fmt.Sprintf("%s: %s packages before and after (%s)", t, fmtCount(bTypes[t]), detail),
		})
	}
	return findings
}

func detectVersionChangeAnalysis(result DiffResult, overview DiffOverview) []Finding {
	shared := result.SharedPackages
	if shared <= 0 {
		return nil
	}

	type change struct{ name, from, to string }
	type tally struct {
		occurrences int
		distinct    map[string]bool
		samples     []change
	}
	newTally := func() *tally { return &tally{distinct: make(map[string]bool)} }
	up, down, unknown, none := newTally(), newTally(), newTally(), newTally()
	levels := make(map[string]int) // distinct upgrades per level

	for _, c := range result.Changed {
		if c.Drift == nil || c.Drift.Type != DriftTypeVersion {
			continue
		}
		var t *tally
		switch c.Drift.Direction {
		case DirectionUpgrade:
			t = up
		case DirectionDowngrade:
			t = down
		case DirectionNone:
			t = none
		default:
			t = unknown
		}
		t.occurrences++
		key := identityKey(c.ID) + "\x00" + c.Drift.VersionFrom + "\x00" + c.Drift.VersionTo
		if t.distinct[key] {
			continue
		}
		t.distinct[key] = true
		if t == up {
			levels[c.Drift.Level]++
		}
		if len(t.samples) < 5 {
			t.samples = append(t.samples, change{c.Name, c.Drift.VersionFrom, c.Drift.VersionTo})
		}
	}

	if up.occurrences+down.occurrences+unknown.occurrences+none.occurrences == 0 {
		return []Finding{{
			Icon:    "\U0001f504",
			Message: fmt.Sprintf("0 version changes among %s shared packages \u2014 no actual upgrades", fmtCount(shared)),
		}}
	}

	// occurrences: note when a change hits many locs
	occurrences := func(t *tally) string {
		if t.occurrences == len(t.distinct) {
			return ""
		}
		return fmt.Sprintf(" across %d occurrences", t.occurrences)
	}
	list := func(t *tally) string {
		names := make([]string, len(t.samples))
		for i, d := range t.samples {
			names[i] = fmt.Sprintf("%s %s\u2192%s", d.name, d.from, d.to)
		}
		msg := strings.Join(names, ", ")
		if n := len(t.distinct) - len(t.samples); n > 0 {
			msg += fmt.Sprintf(" + %d more", n)
		}
		return msg
	}

	var findings []Finding

	if len(down.distinct) > 0 {
		findings = append(findings, Finding{
			Icon:    "\U0001f6a8",
			Message: fmt.Sprintf("%d version downgrades detected%s: %s", len(down.distinct), occurrences(down), list(down)),
		})
	}

	if len(up.distinct) > 0 {
		msg := fmt.Sprintf("%d version upgrades", len(up.distinct))
		if levels[LevelMajor] > 0 || levels[LevelMinor] > 0 || levels[LevelPrerelease] > 0 {
			parts := make([]string, 0, 4)
			for _, l := range []string{LevelMajor, LevelMinor, LevelPatch, LevelPrerelease} {
				if levels[l] > 0 {
					parts = append(parts, fmt.Sprintf("%d %s", levels[l], l))
				}
			}
			msg += fmt.Sprintf(" (%s)", strings.Join(parts, ", "))
		}
		msg += fmt.Sprintf("%s among %s shared packages", occurrences(up), fmtCount(shared))
		findings = append(findings, Finding{
			Icon:    "\U0001f504",
			Message: msg,
		})
	}

	if len(unknown.distinct) > 0 {
		findings = append(findings, Finding{
			Icon:    "\u2753",
			Message: fmt.Sprintf("%d version changes with unknown direction%s: %s", len(unknown.distinct), occurrences(unknown), list(unknown)),
		})
	}

	if len(none.distinct) > 0 {
		findings = append(findings, Finding{
			Icon:    "\U0001f504",
			Message: fmt.Sprintf("%d version label changes with equal precedence%s: %s", len(none.distinct), occurrences(none), list(none)),
		})
	}

	return findings
}

// identityKey: case-folded ID for distinct counts
func identityKey(id string) string {
	return identity.MatchKey(id)
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
	limit := min(len(dirs), 4)
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

// detectOwnedFileDrift: same-ver file changes, identical upgrades
func detectOwnedFileDrift(result DiffResult) []Finding {
	var findings []Finding
	if n := len(result.OwnedFileDrift); n > 0 {
		limit := min(n, 5)
		parts := make([]string, limit)
		config := 0
		for _, d := range result.OwnedFileDrift {
			if len(d.GatedFiles(false)) == 0 {
				config++
			}
		}
		for i, d := range result.OwnedFileDrift[:limit] {
			parts[i] = fmt.Sprintf("%s %s (%s %s", d.Name, d.Version, d.Files[0].Change, d.Files[0].Path)
			if len(d.Files) > 1 {
				parts[i] += fmt.Sprintf(" +%d", len(d.Files)-1)
			}
			parts[i] += ")"
		}
		msg := fmt.Sprintf("%d packages changed owned files without a version change: %s", n, strings.Join(parts, ", "))
		if n > limit {
			msg += fmt.Sprintf(" + %d more", n-limit)
		}
		if config > 0 {
			msg += fmt.Sprintf(" (%d config files only)", config)
		}
		findings = append(findings, Finding{Icon: "\u26a0\ufe0f", Message: msg})
	}

	var same []string
	for _, c := range result.Changed {
		if c.Drift != nil && c.Drift.Files != nil && c.Drift.Files.AllMatch {
			same = append(same, fmt.Sprintf("%s %s\u2192%s", c.Name, c.Drift.VersionFrom, c.Drift.VersionTo))
		}
	}
	if len(same) > 0 {
		limit := min(len(same), 5)
		msg := fmt.Sprintf("%d version changes where all recorded owned files are byte-identical: %s", len(same), strings.Join(same[:limit], ", "))
		if len(same) > limit {
			msg += fmt.Sprintf(" + %d more", len(same)-limit)
		}
		findings = append(findings, Finding{Icon: "\u2139\ufe0f", Message: msg})
	}
	return findings
}

// detectFileChanges: changed file entries, not pkg drift
func detectFileChanges(result DiffResult) []Finding {
	n := len(result.FileChanges)
	if n == 0 {
		return nil
	}
	limit := min(n, 5)
	paths := make([]string, limit)
	for i := 0; i < limit; i++ {
		paths[i] = result.FileChanges[i].Path
	}
	msg := fmt.Sprintf("%d file entries changed content (not package integrity drift): %s", n, strings.Join(paths, ", "))
	if n > limit {
		msg += fmt.Sprintf(" + %d more", n-limit)
	}
	return []Finding{{Icon: "\U0001f4c4", Message: msg}}
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
