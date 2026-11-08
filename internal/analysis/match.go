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

// occurrence is one package component: an (identity, version, location) tuple.
type occurrence struct {
	c       sbom.Component
	key     string // identity match key
	loc     string // location match key ("" when the SBOM has no location)
	display string // location shown in output
	sortKey string // canonical order; pairing never depends on input order
}

// versionPathSuffixes are path segments that embed the package version, such
// as foo-1.2.dist-info or foo-1.2.jar. The version is masked in the location
// key so a version change at the same place is still one location.
var versionPathSuffixes = []string{".dist-info", ".egg-info", ".jar", ".war", ".ear", ".gemspec"}

const versionPlaceholder = "{version}"

// locationMatchKey masks the component's own version in recognised
// version-bearing path segments. Nothing else in the path is altered.
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

// primaryLocation returns the smallest location by match key, so the choice
// does not depend on the order locations are listed in. Syft's primary
// evidence locations are preferred over supporting files when known.
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
	s := slices.Clone(lics)
	sort.Strings(s)
	return strings.Join(s, "\x00")
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

// exactKey: two occurrences with the same exactKey are unchanged.
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
	// coverage is accumulated over same-version package pairs
	coverage DigestCoverage
}

// pair records a before/after occurrence pair: compares it, and counts digest
// coverage when the version is unchanged.
func (m *matcher) pair(b, a occurrence) {
	if !b.c.IsEvidence() {
		m.result.SharedPackages++
	}
	if b.c.Version == a.c.Version && b.c.Version != "" && !b.c.IsEvidence() && !a.c.IsEvidence() {
		m.countCoverage(b.c.DigestSet(), a.c.DigestSet())
	}
	changes := sbom.CompareComponents(b.c, a.c)
	if len(changes) == 0 {
		return
	}
	drift := ClassifyDrift(b.c, a.c)
	loc := a.display
	if loc == "" {
		loc = b.display
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

// matchPackages pairs package occurrences:
//  1. group by identity and location; cancel identical records
//  2. same version at the same location: compare (integrity / metadata drift)
//  3. one leftover on each side at the same location: version change
//  4. several leftovers at one location: version-set change, all of them
//     added/removed (no guessed pairing)
//  5. an identity with no location on one side matches its single leftover
//     on the other side
//  6. same identity and version at a different location, one on each side: moved
//  7. relocated: the identity's single leftover on each side, when the before
//     location is gone from the after SBOM and the after location is new
//     (an image's python3.11/ became python3.12/): version change
//  8. everything else is added or removed. A location that still exists on
//     the other side is never paired across: the package left that lockfile.
func matchPackages(before, after []sbom.Component, result *DiffResult) {
	m := &matcher{result: result, coverage: DigestCoverage{ByKind: map[string]int{}}}

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

// pairBy pairs occurrences with equal keys in canonical order and returns the
// leftovers. Both inputs must be sorted.
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

// matchUnlocated handles identities with no location on one side (e.g. a
// format without locations): an absent location is unknown, not different,
// so the identity's leftovers are matched as if they shared one location.
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

// matchMoved reports same identity and version, one occurrence on each side,
// at different locations.
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
		// a move can carry a license change; digests are only compared at
		// one location, so a move is never integrity drift
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

// locationSet holds every location key of the given components.
func locationSet(comps []sbom.Component) map[string]bool {
	set := make(map[string]bool)
	for _, c := range comps {
		for _, loc := range c.Locations {
			set[locationMatchKey(loc, c.Version)] = true
		}
	}
	return set
}

// matchRelocated pairs an identity's single leftover on each side when its
// before location no longer exists after and its after location did not
// exist before: the container was replaced, not the package moved between
// two live lockfiles.
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

// filePath is the path of a file entry: CycloneDX names files by path.
func filePath(c sbom.Component) string {
	if c.Name != "" {
		return c.Name
	}
	if len(c.Locations) > 0 {
		return c.Locations[0]
	}
	return c.ID
}

// matchFiles compares file entries by path. Content changes go to
// FileChanges; files that appear or disappear stay in Added/Removed.
func matchFiles(before, after []sbom.Component, result *DiffResult) {
	byPath := func(comps []sbom.Component) map[string][]sbom.Component {
		out := make(map[string][]sbom.Component)
		for _, c := range comps {
			out[filePath(c)] = append(out[filePath(c)], c)
		}
		for _, list := range out {
			sort.SliceStable(list, func(i, j int) bool {
				return digestFingerprint(list[i].Hashes)+list[i].ID < digestFingerprint(list[j].Hashes)+list[j].ID
			})
		}
		return out
	}
	b, a := byPath(before), byPath(after)
	paths := slices.Sorted(maps.Keys(b))
	for p := range a {
		if _, ok := b[p]; !ok {
			paths = append(paths, p)
		}
	}
	for _, p := range paths {
		bs, as := b[p], a[p]
		// identical content first, then pair the rest in canonical order
		usedA := make([]bool, len(as))
		var restB []sbom.Component
		for _, bc := range bs {
			found := false
			for i, ac := range as {
				if !usedA[i] && maps.Equal(bc.Hashes, ac.Hashes) {
					usedA[i], found = true, true
					break
				}
			}
			if !found {
				restB = append(restB, bc)
			}
		}
		var restA []sbom.Component
		for i, ac := range as {
			if !usedA[i] {
				restA = append(restA, ac)
			}
		}
		n := min(len(restB), len(restA))
		for i := 0; i < n; i++ {
			result.FileChanges = append(result.FileChanges, FileChange{
				Path: p, HashesBefore: restB[i].Hashes, HashesAfter: restA[i].Hashes,
			})
		}
		result.Removed = append(result.Removed, restB[n:]...)
		result.Added = append(result.Added, restA[n:]...)
	}
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
}
