package analysis

import (
	"regexp"
	"strconv"
	"strings"

	mmsemver "github.com/Masterminds/semver/v3"
	"golang.org/x/mod/semver"
)

// Version change direction.
const (
	DirectionUpgrade   = "upgrade"
	DirectionDowngrade = "downgrade"
	DirectionNone      = "none" // equal precedence, e.g. build metadata only
	DirectionUnknown   = "unknown"
)

// Version change level.
const (
	LevelMajor      = "major"
	LevelMinor      = "minor"
	LevelPatch      = "patch"
	LevelPrerelease = "prerelease" // same core; pre-release/pseudo/post/dev differs
	LevelNone       = "none"
	LevelUnknown    = "unknown"
)

// VersionOrdering is one version-ordering rule set; feeds the website.
type VersionOrdering struct {
	Ecosystems []string `json:"ecosystems"` // PURL types
	Rule       string   `json:"rule"`
	Oracle     string   `json:"oracle,omitempty"` // tool it is tested against (testdata/version-oracle)
	compare    func(from, to string) (string, string)
}

var versionOrderings = []VersionOrdering{
	{[]string{"golang", "github"}, "golang.org/x/mod/semver (pseudo-versions, +incompatible, go1.x)", "", compareGoSemver},
	{[]string{"npm", "cargo", "composer", "swift", "hex", "pub"}, "SemVer", "", compareSemver},
	{[]string{"pypi"}, "PEP 440", "", comparePEP440},
	{[]string{"gem"}, "RubyGems Gem::Version", "gem", compareGem},
	{[]string{"deb"}, "dpkg (epoch, ~, revision)", "deb", compareDeb},
	{[]string{"rpm"}, "rpmvercmp (epoch, ~, ^, release)", "rpm", compareRPM},
	{[]string{"alpm"}, "pacman vercmp (pkgrel only when both have one)", "alpm", compareAlpm},
	{[]string{"apk"}, "apk-tools (_alpha.._p suffixes, -rN)", "apk", compareAPK},
	{[]string{"maven"}, "Maven ComparableVersion", "maven", compareMaven},
	{[]string{"generic"}, "Dotted numbers only (20.11.1, 11.0.22+7); anything else unknown", "", compareNumeric},
}

var orderingByEcosystem = func() map[string]VersionOrdering {
	m := make(map[string]VersionOrdering)
	for _, o := range versionOrderings {
		for _, e := range o.Ecosystems {
			m[e] = o
		}
	}
	return m
}()

// VersionOrderings lists the supported version-ordering rules.
func VersionOrderings() []VersionOrdering {
	return versionOrderings
}

// ClassifyVersionChange: per-ecosystem order; else unknown
func ClassifyVersionChange(ecosystem, from, to string) (direction, level string) {
	if o, ok := orderingByEcosystem[ecosystem]; ok {
		return o.compare(from, to)
	}
	return DirectionUnknown, LevelUnknown
}

func directionOf(cmp int) string {
	switch {
	case cmp < 0:
		return DirectionUpgrade
	case cmp > 0:
		return DirectionDowngrade
	}
	return DirectionNone
}

func compareGoSemver(from, to string) (string, string) {
	f, t := withV(from), withV(to)
	if !semver.IsValid(f) || !semver.IsValid(t) {
		return DirectionUnknown, LevelUnknown
	}
	cmp := semver.Compare(f, t)
	if cmp == 0 {
		return DirectionNone, LevelNone
	}
	fc, tc := semver.Canonical(f), semver.Canonical(t)
	switch {
	case semver.Major(fc) != semver.Major(tc):
		return directionOf(cmp), LevelMajor
	case semver.MajorMinor(fc) != semver.MajorMinor(tc):
		return directionOf(cmp), LevelMinor
	case goCore(fc) != goCore(tc):
		return directionOf(cmp), LevelPatch
	}
	return directionOf(cmp), LevelPrerelease
}

// withV adds "v"; go1.x (stdlib) -> v1.x
func withV(v string) string {
	switch {
	case strings.HasPrefix(v, "v"):
		return v
	case strings.HasPrefix(v, "go"):
		return "v" + v[2:]
	}
	return "v" + v
}

// goCore strips pre-release and build
func goCore(canonical string) string {
	core, _, _ := strings.Cut(canonical, "+")
	core, _, _ = strings.Cut(core, "-")
	return core
}

func compareSemver(from, to string) (string, string) {
	f, err1 := mmsemver.NewVersion(from)
	t, err2 := mmsemver.NewVersion(to)
	if err1 != nil || err2 != nil {
		return DirectionUnknown, LevelUnknown
	}
	cmp := f.Compare(t)
	if cmp == 0 {
		return DirectionNone, LevelNone
	}
	switch {
	case f.Major() != t.Major():
		return directionOf(cmp), LevelMajor
	case f.Minor() != t.Minor():
		return directionOf(cmp), LevelMinor
	case f.Patch() != t.Patch():
		return directionOf(cmp), LevelPatch
	}
	return directionOf(cmp), LevelPrerelease
}

// PEP 440 regex: https://peps.python.org/pep-0440/#appendix-b-parsing-version-strings-with-regular-expressions
var pep440Re = regexp.MustCompile(`(?i)^\s*v?` +
	`(?:(?P<epoch>[0-9]+)!)?` +
	`(?P<release>[0-9]+(?:\.[0-9]+)*)` +
	`(?:[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>[0-9]+)?)?` +
	`(?:-(?P<post_n1>[0-9]+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?)?` +
	`(?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?` +
	`(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?\s*$`)

// pep440Version: has* flags mark absent pre/post/dev
type pep440Version struct {
	epoch   int
	release []int
	hasPre  bool
	preL    int // a=0, b=1, rc=2
	preN    int
	hasPost bool
	postN   int
	hasDev  bool
	devN    int
	local   []string
}

func parsePEP440(s string) (pep440Version, bool) {
	m := pep440Re.FindStringSubmatch(s)
	if m == nil {
		return pep440Version{}, false
	}
	g := func(name string) string { return m[pep440Re.SubexpIndex(name)] }
	atoi := func(s string) int { n, _ := strconv.Atoi(s); return n }

	var v pep440Version
	v.epoch = atoi(g("epoch"))
	for _, p := range strings.Split(g("release"), ".") {
		v.release = append(v.release, atoi(p))
	}
	for len(v.release) > 1 && v.release[len(v.release)-1] == 0 {
		v.release = v.release[:len(v.release)-1]
	}
	if l := strings.ToLower(g("pre_l")); l != "" {
		v.hasPre = true
		v.preN = atoi(g("pre_n"))
		switch l {
		case "a", "alpha":
			v.preL = 0
		case "b", "beta":
			v.preL = 1
		default: // c, rc, pre, preview
			v.preL = 2
		}
	}
	if n := g("post_n1"); n != "" {
		v.hasPost, v.postN = true, atoi(n)
	} else if g("post_l") != "" {
		v.hasPost, v.postN = true, atoi(g("post_n2"))
	}
	if g("dev_l") != "" {
		v.hasDev, v.devN = true, atoi(g("dev_n"))
	}
	if l := g("local"); l != "" {
		v.local = strings.FieldsFunc(strings.ToLower(l), func(r rune) bool { return r == '-' || r == '_' || r == '.' })
	}
	return v, true
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func cmpRelease(a, b []int) int {
	for i := 0; i < max(len(a), len(b)); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if c := cmpInt(x, y); c != 0 {
			return c
		}
	}
	return 0
}

// preKey: dev-only < pre-release < final
func (v pep440Version) preKey() (rank, l, n int) {
	switch {
	case !v.hasPre && !v.hasPost && v.hasDev:
		return 0, 0, 0
	case !v.hasPre:
		return 2, 0, 0
	}
	return 1, v.preL, v.preN
}

func cmpLocal(a, b []string) int {
	for i := 0; i < min(len(a), len(b)); i++ {
		an, aErr := strconv.Atoi(a[i])
		bn, bErr := strconv.Atoi(b[i])
		switch {
		case aErr == nil && bErr == nil:
			if c := cmpInt(an, bn); c != 0 {
				return c
			}
		case aErr == nil: // numeric segments sort after alphanumeric
			return 1
		case bErr == nil:
			return -1
		default:
			if c := strings.Compare(a[i], b[i]); c != 0 {
				return c
			}
		}
	}
	return cmpInt(len(a), len(b))
}

func cmpPEP440(a, b pep440Version) int {
	if c := cmpInt(a.epoch, b.epoch); c != 0 {
		return c
	}
	if c := cmpRelease(a.release, b.release); c != 0 {
		return c
	}
	ar, al, an := a.preKey()
	br, bl, bn := b.preKey()
	for _, c := range []int{cmpInt(ar, br), cmpInt(al, bl), cmpInt(an, bn)} {
		if c != 0 {
			return c
		}
	}
	if a.hasPost != b.hasPost {
		if a.hasPost {
			return 1
		}
		return -1
	}
	if c := cmpInt(a.postN, b.postN); c != 0 {
		return c
	}
	if a.hasDev != b.hasDev {
		if a.hasDev {
			return -1
		}
		return 1
	}
	if c := cmpInt(a.devN, b.devN); c != 0 {
		return c
	}
	return cmpLocal(a.local, b.local)
}

func comparePEP440(from, to string) (string, string) {
	f, ok1 := parsePEP440(from)
	t, ok2 := parsePEP440(to)
	if !ok1 || !ok2 {
		return DirectionUnknown, LevelUnknown
	}
	cmp := cmpPEP440(f, t)
	if cmp == 0 {
		return DirectionNone, LevelNone
	}
	part := func(r []int, i int) int {
		if i < len(r) {
			return r[i]
		}
		return 0
	}
	switch {
	case f.epoch != t.epoch || part(f.release, 0) != part(t.release, 0):
		return directionOf(cmp), LevelMajor
	case part(f.release, 1) != part(t.release, 1):
		return directionOf(cmp), LevelMinor
	case cmpRelease(f.release, t.release) != 0:
		return directionOf(cmp), LevelPatch
	}
	return directionOf(cmp), LevelPrerelease
}

var numericVersionRe = regexp.MustCompile(`^\d+(\.\d+)*(\+\d+)?$`)

// cmpDigits: compare digit strings of any length
func cmpDigits(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return len(a) - len(b)
	}
	return strings.Compare(a, b)
}

// compareNumeric: dotted numbers + optional +build; else unknown
func compareNumeric(from, to string) (string, string) {
	if !numericVersionRe.MatchString(from) || !numericVersionRe.MatchString(to) {
		return DirectionUnknown, LevelUnknown
	}
	fc, fb, _ := strings.Cut(from, "+")
	tc, tb, _ := strings.Cut(to, "+")
	f, t := strings.Split(fc, "."), strings.Split(tc, ".")
	for i := 0; i < max(len(f), len(t)); i++ {
		fi, ti := "0", "0"
		if i < len(f) {
			fi = f[i]
		}
		if i < len(t) {
			ti = t[i]
		}
		if c := cmpDigits(fi, ti); c != 0 {
			level := LevelPatch
			switch i {
			case 0:
				level = LevelMajor
			case 1:
				level = LevelMinor
			}
			return directionOf(c), level
		}
	}
	if c := cmpDigits(fb, tb); c != 0 {
		return directionOf(c), LevelRevision
	}
	return DirectionNone, LevelNone
}
