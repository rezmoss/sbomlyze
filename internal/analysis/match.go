package analysis

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/rezmoss/sbomlyze/internal/identity"
	"github.com/rezmoss/sbomlyze/internal/sbom"
)

// occurrence: one (identity, version, location) pkg
type occurrence struct {
	c       sbom.Component
	key     string // identity match key
	loc     string // location match key ("" if none)
	display string // location shown in output
	sortKey string // canonical order; pairing ignores input order
}

// versionPathSuffixes: segments embedding pkg version, masked
var versionPathSuffixes = []string{".dist-info", ".egg-info", ".jar", ".war", ".ear", ".gemspec"}

const versionPlaceholder = "{version}"

// locationMatchKey masks own version in known segments
func locationMatchKey(path, version string) string {
	if version == "" {
		return path
	}
	segs := strings.Split(path, "/")
	for i, seg := range segs {
		for _, suffix := range versionPathSuffixes {
			tail := "-" + version + suffix
			if strings.HasSuffix(seg, tail) && len(seg) > len(tail) {
				segs[i] = seg[:len(seg)-len(tail)] + "-" + versionPlaceholder + suffix
			}
		}
		// gems/<name>-<version>/
		if i > 0 && segs[i-1] == "gems" && strings.HasSuffix(seg, "-"+version) && len(seg) > len(version)+1 {
			segs[i] = seg[:len(seg)-len(version)] + versionPlaceholder
		}
	}
	return strings.Join(segs, "/")
}

// primaryLocation: min loc key, Syft primary preferred
func primaryLocation(c sbom.Component) (key, display string) {
	locs := c.PrimaryLocations
	if len(locs) == 0 {
		locs = c.Locations
	}
	for _, loc := range locs {
		k := locationMatchKey(loc, c.Version)
		if display == "" || k < key || (k == key && loc < display) {
			key, display = k, loc
		}
	}
	return key, display
}

func digestFingerprint(d map[string]string) string {
	var b strings.Builder
	for _, k := range slices.Sorted(maps.Keys(d)) {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(d[k])
		b.WriteByte(';')
	}
	return b.String()
}

func licenseFingerprint(lics []string) string {
	return strings.Join(sbom.LicenseTerms(lics), "\x00")
}

func newOccurrence(c sbom.Component) occurrence {
	o := occurrence{c: c, key: identity.MatchKey(c.ID)}
	o.loc, o.display = primaryLocation(c)
	o.sortKey = strings.Join([]string{
		c.Version, digestFingerprint(c.DigestSet()), licenseFingerprint(c.Licenses),
		c.Name, c.PURL, c.BOMRef, c.SPDXID, c.Supplier, c.Type, strings.Join(c.Locations, "\x01"),
	}, "\x00")
	return o
}

func sortOccurrences(occ []occurrence) {
	sort.SliceStable(occ, func(i, j int) bool { return occ[i].sortKey < occ[j].sortKey })
}

// exactKey: equal keys mean unchanged
func (o occurrence) exactKey() string {
	return o.c.Version + "\x00" + digestFingerprint(o.c.DigestSet()) + "\x00" + licenseFingerprint(o.c.Licenses)
}

func splitFiles(comps []sbom.Component) (pkgs, files []sbom.Component) {
	for _, c := range comps {
		if c.Type == "file" {
			files = append(files, c)
		} else {
			pkgs = append(pkgs, c)
		}
	}
	return pkgs, files
}

type matcher struct {
	result *DiffResult
	// file inventories for owned-file diff
	bi, ai *fileIndex
	// coverage over same-version pkg pairs
	coverage DigestCoverage
}

// pair: compare pair, count digest coverage
func (m *matcher) pair(b, a occurrence) {
	if !b.c.IsEvidence() {
		m.result.SharedPackages++
	}
	if b.c.Version == a.c.Version && b.c.Version != "" && !b.c.IsEvidence() && !a.c.IsEvidence() {
		m.countCoverage(b.c.DigestSet(), a.c.DigestSet())
	}
	loc := a.display
	if loc == "" {
		loc = b.display
	}
	var delta *FileDelta
	// only when both SBOMs can record file ownership (not CycloneDX)
	if !b.c.IsEvidence() && m.bi.ownership() && m.ai.ownership() && (len(b.c.OwnedFiles) > 0 || len(a.c.OwnedFiles) > 0) {
		files, d := ownedFileDelta(b.c, a.c, m.bi, m.ai)
		delta = &d
		if b.c.Version == a.c.Version && b.c.Version != "" && len(files) > 0 {
			m.result.OwnedFileDrift = append(m.result.OwnedFileDrift, OwnedFileDrift{
				ID: b.c.ID, Name: b.c.Name, Version: b.c.Version, Location: loc, Files: files,
			})
		}
	}
	changes := sbom.CompareComponents(b.c, a.c)
	if len(changes) == 0 {
		return
	}
	drift := ClassifyDrift(b.c, a.c)
	if drift.Type == DriftTypeVersion {
		drift.Files = delta
	}
	m.result.Changed = append(m.result.Changed, ChangedComponent{
		ID:       b.c.ID,
		Name:     b.c.Name,
		Location: loc,
		Before:   b.c,
		After:    a.c,
		Changes:  changes,
		Drift:    &drift,
	})
}

func (m *matcher) countCoverage(before, after map[string]string) {
	m.coverage.SameVersionPairs++
	shared := 0
	for kind := range after {
		if _, ok := before[kind]; ok {
			shared++
			m.coverage.ByKind[kind]++
		}
	}
	switch {
	case shared > 0:
		m.coverage.Comparable++
	case len(before) > 0 && len(after) > 0:
		m.coverage.DisjointKinds++
	case len(before) > 0:
		m.coverage.BeforeOnly++
	case len(after) > 0:
		m.coverage.AfterOnly++
	}
}

// matchPackages: occurrence matching; rules in README
func matchPackages(before, after []sbom.Component, bi, ai *fileIndex, result *DiffResult) {
	m := &matcher{result: result, bi: bi, ai: ai, coverage: DigestCoverage{ByKind: map[string]int{}}}

	type groupKey struct{ key, loc string }
	groups := make(map[groupKey]*[2][]occurrence)
	add := func(side int, c sbom.Component) {
		o := newOccurrence(c)
		k := groupKey{o.key, o.loc}
		g := groups[k]
		if g == nil {
			g = &[2][]occurrence{}
			groups[k] = g
		}
		g[side] = append(g[side], o)
	}
	for _, c := range before {
		add(0, c)
	}
	for _, c := range after {
		add(1, c)
		if !c.IsEvidence() {
			m.coverage.PackagesTotal++
		}
	}

	keys := slices.SortedFunc(maps.Keys(groups), func(x, y groupKey) int {
		if c := strings.Compare(x.key, y.key); c != 0 {
			return c
		}
		return strings.Compare(x.loc, y.loc)
	})

	var poolBefore, poolAfter []occurrence
	for _, k := range keys {
		g := groups[k]
		bs, as := g[0], g[1]
		sortOccurrences(bs)
		sortOccurrences(as)

		bs, as = pairBy(bs, as, occurrence.exactKey, m.pair)
		bs, as = pairBy(bs, as, func(o occurrence) string { return o.c.Version }, m.pair)

		switch {
		case len(bs) == 1 && len(as) == 1:
			m.pair(bs[0], as[0])
		case len(bs) > 0 && len(as) > 0:
			vsc := VersionSetChange{ID: bs[0].c.ID, Name: bs[0].c.Name, Location: as[0].display}
			for _, o := range bs {
				vsc.RemovedVersions = append(vsc.RemovedVersions, o.c.Version)
				result.Removed = append(result.Removed, o.c)
			}
			for _, o := range as {
				vsc.AddedVersions = append(vsc.AddedVersions, o.c.Version)
				result.Added = append(result.Added, o.c)
			}
			result.VersionSetChanges = append(result.VersionSetChanges, vsc)
		default:
			poolBefore = append(poolBefore, bs...)
			poolAfter = append(poolAfter, as...)
		}
	}

	poolBefore, poolAfter = matchUnlocated(poolBefore, poolAfter, m.pair)
	poolBefore, poolAfter = matchMoved(poolBefore, poolAfter, result)
	poolBefore, poolAfter = matchRelocated(poolBefore, poolAfter, locationSet(before), locationSet(after), m.pair)

	for _, o := range poolBefore {
		result.Removed = append(result.Removed, o.c)
	}
	for _, o := range poolAfter {
		result.Added = append(result.Added, o.c)
	}

	if m.coverage.PackagesTotal > 0 || m.coverage.SameVersionPairs > 0 {
		cov := m.coverage
		result.DigestCoverage = &cov
	}
}

// pairBy: pair equal keys in order; inputs sorted
func pairBy(bs, as []occurrence, key func(occurrence) string, pair func(b, a occurrence)) ([]occurrence, []occurrence) {
	if len(bs) == 0 || len(as) == 0 {
		return bs, as
	}
	byKey := make(map[string][]int)
	for i, o := range as {
		k := key(o)
		byKey[k] = append(byKey[k], i)
	}
	usedA := make([]bool, len(as))
	var restB []occurrence
	for _, b := range bs {
		k := key(b)
		if idx := byKey[k]; len(idx) > 0 {
			pair(b, as[idx[0]])
			usedA[idx[0]] = true
			byKey[k] = idx[1:]
			continue
		}
		restB = append(restB, b)
	}
	var restA []occurrence
	for i, a := range as {
		if !usedA[i] {
			restA = append(restA, a)
		}
	}
	return restB, restA
}

func groupByKey(occ []occurrence, key func(occurrence) string) map[string][]int {
	out := make(map[string][]int)
	for i, o := range occ {
		k := key(o)
		out[k] = append(out[k], i)
	}
	return out
}

func remove(occ []occurrence, used map[int]bool) []occurrence {
	var out []occurrence
	for i, o := range occ {
		if !used[i] {
			out = append(out, o)
		}
	}
	return out
}

// matchUnlocated: missing location matches any location
func matchUnlocated(bs, as []occurrence, pair func(b, a occurrence)) ([]occurrence, []occurrence) {
	bByID := groupByKey(bs, func(o occurrence) string { return o.key })
	aByID := groupByKey(as, func(o occurrence) string { return o.key })
	unlocated := func(occ []occurrence, idx []int) bool {
		for _, i := range idx {
			if occ[i].loc != "" {
				return false
			}
		}
		return true
	}
	pick := func(occ []occurrence, idx []int) []occurrence {
		out := make([]occurrence, len(idx))
		for i, j := range idx {
			out[i] = occ[j]
		}
		sortOccurrences(out)
		return out
	}
	var restB, restA []occurrence
	usedB, usedA := map[int]bool{}, map[int]bool{}
	for _, id := range slices.Sorted(maps.Keys(bByID)) {
		bi, ai := bByID[id], aByID[id]
		if len(ai) == 0 || (!unlocated(bs, bi) && !unlocated(as, ai)) {
			continue
		}
		for _, i := range bi {
			usedB[i] = true
		}
		for _, i := range ai {
			usedA[i] = true
		}
		lb, la := pick(bs, bi), pick(as, ai)
		lb, la = pairBy(lb, la, occurrence.exactKey, pair)
		lb, la = pairBy(lb, la, func(o occurrence) string { return o.c.Version }, pair)
		if len(lb) == 1 && len(la) == 1 {
			pair(lb[0], la[0])
			continue
		}
		restB = append(restB, lb...)
		restA = append(restA, la...)
	}
	return append(remove(bs, usedB), restB...), append(remove(as, usedA), restA...)
}

// matchMoved: same id+version, 1:1, other location
func matchMoved(bs, as []occurrence, result *DiffResult) ([]occurrence, []occurrence) {
	idVer := func(o occurrence) string { return o.key + "\x00" + o.c.Version }
	bBy := groupByKey(bs, idVer)
	aBy := groupByKey(as, idVer)
	usedB, usedA := map[int]bool{}, map[int]bool{}
	for _, k := range slices.Sorted(maps.Keys(bBy)) {
		bi, ai := bBy[k], aBy[k]
		if len(bi) != 1 || len(ai) != 1 {
			continue
		}
		b, a := bs[bi[0]], as[ai[0]]
		if b.loc == "" || a.loc == "" {
			continue
		}
		if !b.c.IsEvidence() {
			result.SharedPackages++
		}
		result.Moved = append(result.Moved, MovedComponent{
			ID: b.c.ID, Name: b.c.Name, Version: b.c.Version, From: b.display, To: a.display,
		})
		// moves keep license diffs; never integrity drift
		if lics := diffLicenses(b.c.Licenses, a.c.Licenses); len(lics) > 0 {
			result.Changed = append(result.Changed, ChangedComponent{
				ID: b.c.ID, Name: b.c.Name, Location: a.display, Before: b.c, After: a.c,
				Changes: []string{fmt.Sprintf("licenses: %v -> %v", b.c.Licenses, a.c.Licenses)},
				Drift:   &DriftInfo{Type: DriftTypeMetadata, LicensesDiff: lics},
			})
		}
		usedB[bi[0]], usedA[ai[0]] = true, true
	}
	return remove(bs, usedB), remove(as, usedA)
}

// locationSet: all location keys of comps
func locationSet(comps []sbom.Component) map[string]bool {
	set := make(map[string]bool)
	for _, c := range comps {
		for _, loc := range c.Locations {
			set[locationMatchKey(loc, c.Version)] = true
		}
	}
	return set
}

// matchRelocated: pair 1:1 when the location was replaced
func matchRelocated(bs, as []occurrence, beforeLocs, afterLocs map[string]bool, pair func(b, a occurrence)) ([]occurrence, []occurrence) {
	gone := func(o occurrence, other map[string]bool) bool {
		for _, loc := range o.c.Locations {
			if other[locationMatchKey(loc, o.c.Version)] {
				return false
			}
		}
		return o.loc != ""
	}
	bByID := groupByKey(bs, func(o occurrence) string { return o.key })
	aByID := groupByKey(as, func(o occurrence) string { return o.key })
	usedB, usedA := map[int]bool{}, map[int]bool{}
	for _, id := range slices.Sorted(maps.Keys(bByID)) {
		bi, ai := bByID[id], aByID[id]
		if len(bi) != 1 || len(ai) != 1 {
			continue
		}
		b, a := bs[bi[0]], as[ai[0]]
		if !gone(b, afterLocs) || !gone(a, beforeLocs) {
			continue
		}
		pair(b, a)
		usedB[bi[0]], usedA[ai[0]] = true, true
	}
	return remove(bs, usedB), remove(as, usedA)
}

// filePath: CycloneDX names files by path
func filePath(c sbom.Component) string {
	if c.Name != "" {
		return c.Name
	}
	if len(c.Locations) > 0 {
		return c.Locations[0]
	}
	return c.ID
}

func componentOrder(x, y sbom.Component) int {
	if c := strings.Compare(x.ID, y.ID); c != 0 {
		return c
	}
	return strings.Compare(newOccurrence(x).sortKey, newOccurrence(y).sortKey)
}

func sortResult(r *DiffResult) {
	slices.SortStableFunc(r.Added, componentOrder)
	slices.SortStableFunc(r.Removed, componentOrder)
	slices.SortStableFunc(r.Changed, func(x, y ChangedComponent) int {
		for _, c := range []int{
			strings.Compare(x.ID, y.ID), strings.Compare(x.Location, y.Location),
			componentOrder(x.Before, y.Before), componentOrder(x.After, y.After),
		} {
			if c != 0 {
				return c
			}
		}
		return 0
	})
	slices.SortStableFunc(r.Moved, func(x, y MovedComponent) int {
		return strings.Compare(x.ID+"\x00"+x.Version+"\x00"+x.From, y.ID+"\x00"+y.Version+"\x00"+y.From)
	})
	slices.SortStableFunc(r.VersionSetChanges, func(x, y VersionSetChange) int {
		return strings.Compare(x.ID+"\x00"+x.Location, y.ID+"\x00"+y.Location)
	})
	slices.SortStableFunc(r.FileChanges, func(x, y FileChange) int {
		return strings.Compare(x.Path, y.Path)
	})
	slices.SortStableFunc(r.OwnedFileDrift, func(x, y OwnedFileDrift) int {
		return strings.Compare(x.ID+"\x00"+x.Location+"\x00"+x.Version, y.ID+"\x00"+y.Location+"\x00"+y.Version)
	})
}
