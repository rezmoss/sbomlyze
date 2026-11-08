package analysis

import (
	"regexp"
	"strconv"
	"strings"

	mvn "github.com/masahiro331/go-mvn-version"
)

// LevelRevision: only packaging revision changed
const LevelRevision = "revision"

var digitsRe = regexp.MustCompile(`\d+`)

// numericLevel: major/minor/patch from first 3 numbers
func numericLevel(from, to string) string {
	f, t := digitsRe.FindAllString(from, 3), digitsRe.FindAllString(to, 3)
	num := func(s []string, i int) int {
		if i >= len(s) {
			return 0
		}
		n, _ := strconv.Atoi(s[i])
		return n
	}
	switch {
	case num(f, 0) != num(t, 0):
		return LevelMajor
	case num(f, 1) != num(t, 1):
		return LevelMinor
	}
	return LevelPatch
}

// evr is epoch:upstream-revision (deb, rpm, alpm).
type evr struct {
	epoch, upstream, revision string
	hasRevision               bool
}

func parseEVR(v string) evr {
	var e evr
	if i := strings.IndexByte(v, ':'); i >= 0 {
		e.epoch, v = v[:i], v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		e.upstream, e.revision, e.hasRevision = v[:i], v[i+1:], true
	} else {
		e.upstream = v
	}
	return e
}

// epochValue: empty = 0; non-numeric invalid
func epochValue(s string) (int, bool) {
	if s == "" {
		return 0, true
	}
	n, err := strconv.Atoi(s)
	return n, err == nil && n >= 0
}

// classifyEVR: direction/level from part comparisons
func classifyEVR(f, t evr, cmpEpoch, cmpUpstream, cmpRevision int) (string, string) {
	switch {
	case cmpEpoch != 0:
		return directionOf(cmpEpoch), LevelMajor
	case cmpUpstream != 0:
		return directionOf(cmpUpstream), numericLevel(f.upstream, t.upstream)
	case cmpRevision != 0:
		return directionOf(cmpRevision), LevelRevision
	}
	return DirectionNone, LevelNone
}

// --- Debian (dpkg) ---------------------------------------------------------

func dpkgOrder(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return 0
	case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
		return int(c)
	case c == '~':
		return -1
	case c != 0:
		return int(c) + 256
	}
	return 0
}

// dpkgVerrevcmp is dpkg's verrevcmp (lib/dpkg/version.c).
func dpkgVerrevcmp(a, b string) int {
	at := func(s string, i int) byte {
		if i < len(s) {
			return s[i]
		}
		return 0
	}
	isDigit := func(c byte) bool { return c >= '0' && c <= '9' }
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		firstDiff := 0
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := dpkgOrder(at(a, i)), dpkgOrder(at(b, j))
			if ac != bc {
				return ac - bc
			}
			i++
			j++
		}
		for at(a, i) == '0' {
			i++
		}
		for at(b, j) == '0' {
			j++
		}
		for isDigit(at(a, i)) && isDigit(at(b, j)) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if isDigit(at(a, i)) {
			return 1
		}
		if isDigit(at(b, j)) {
			return -1
		}
		if firstDiff != 0 {
			return firstDiff
		}
	}
	return 0
}

var debUpstreamRe = regexp.MustCompile(`^[0-9][A-Za-z0-9.+~:-]*$`)

func compareDeb(from, to string) (string, string) {
	f, t := parseEVR(from), parseEVR(to)
	fe, ok1 := epochValue(f.epoch)
	te, ok2 := epochValue(t.epoch)
	if !ok1 || !ok2 || !debUpstreamRe.MatchString(f.upstream) || !debUpstreamRe.MatchString(t.upstream) {
		return DirectionUnknown, LevelUnknown
	}
	return classifyEVR(f, t, sign(fe-te), sign(dpkgVerrevcmp(f.upstream, t.upstream)), sign(dpkgVerrevcmp(f.revision, t.revision)))
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// --- RPM -------------------------------------------------------------------

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isDigitByte(c byte) bool { return c >= '0' && c <= '9' }

// rpmvercmp: rpm's rpmvercmp (rpmio/rpmver.c), w/ ~ ^
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}
		ca, cb := byte(0), byte(0)
		if i < len(a) {
			ca = a[i]
		}
		if j < len(b) {
			cb = b[j]
		}
		if ca == '~' || cb == '~' {
			if ca != '~' {
				return 1
			}
			if cb != '~' {
				return -1
			}
			i++
			j++
			continue
		}
		if ca == '^' || cb == '^' {
			switch {
			case i >= len(a):
				return -1
			case j >= len(b):
				return 1
			case ca != '^':
				return 1
			case cb != '^':
				return -1
			}
			i++
			j++
			continue
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		si, sj := i, j
		isNum := isDigitByte(a[i])
		if isNum {
			for i < len(a) && isDigitByte(a[i]) {
				i++
			}
			for j < len(b) && isDigitByte(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlnum(a[i]) && !isDigitByte(a[i]) {
				i++
			}
			for j < len(b) && isAlnum(b[j]) && !isDigitByte(b[j]) {
				j++
			}
		}
		if sj == j { // segment types differ: numeric newer
			if isNum {
				return 1
			}
			return -1
		}
		sa, sb := a[si:i], b[sj:j]
		if isNum {
			sa, sb = strings.TrimLeft(sa, "0"), strings.TrimLeft(sb, "0")
			if len(sa) != len(sb) {
				return sign(len(sa) - len(sb))
			}
		}
		if c := strings.Compare(sa, sb); c != 0 {
			return c
		}
	}
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i < len(a):
		return 1
	}
	return -1
}

func compareRPM(from, to string) (string, string) {
	f, t := parseEVR(from), parseEVR(to)
	fe, ok1 := epochValue(f.epoch)
	te, ok2 := epochValue(t.epoch)
	if !ok1 || !ok2 || f.upstream == "" || t.upstream == "" {
		return DirectionUnknown, LevelUnknown
	}
	return classifyEVR(f, t, sign(fe-te), rpmvercmp(f.upstream, t.upstream), rpmvercmp(f.revision, t.revision))
}

// --- Arch Linux (pacman/libalpm) -------------------------------------------

// alpmRpmvercmp: libalpm's rpmvercmp, no ~ or ^
func alpmRpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		pi, pj := i, j
		for i < len(a) && !isAlnum(a[i]) {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) {
			j++
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		if i-pi != j-pj {
			if i-pi < j-pj {
				return -1
			}
			return 1
		}
		si, sj := i, j
		isNum := isDigitByte(a[i])
		if isNum {
			for i < len(a) && isDigitByte(a[i]) {
				i++
			}
			for j < len(b) && isDigitByte(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlnum(a[i]) && !isDigitByte(a[i]) {
				i++
			}
			for j < len(b) && isAlnum(b[j]) && !isDigitByte(b[j]) {
				j++
			}
		}
		if sj == j {
			if isNum {
				return 1
			}
			return -1
		}
		sa, sb := a[si:i], b[sj:j]
		if isNum {
			sa, sb = strings.TrimLeft(sa, "0"), strings.TrimLeft(sb, "0")
			if len(sa) != len(sb) {
				return sign(len(sa) - len(sb))
			}
		}
		if c := strings.Compare(sa, sb); c != 0 {
			return c
		}
	}
	if i >= len(a) && j >= len(b) {
		return 0
	}
	isAlpha := func(s string, k int) bool { return k < len(s) && isAlnum(s[k]) && !isDigitByte(s[k]) }
	if (i >= len(a) && !isAlpha(b, j)) || isAlpha(a, i) {
		return -1
	}
	return 1
}

func compareAlpm(from, to string) (string, string) {
	f, t := parseEVR(from), parseEVR(to)
	if f.upstream == "" || t.upstream == "" {
		return DirectionUnknown, LevelUnknown
	}
	fe, te := f.epoch, t.epoch
	if fe == "" {
		fe = "0"
	}
	if te == "" {
		te = "0"
	}
	cmpRel := 0
	if f.hasRevision && t.hasRevision { // pkgrel only if both have one
		cmpRel = alpmRpmvercmp(f.revision, t.revision)
	}
	return classifyEVR(f, t, alpmRpmvercmp(fe, te), alpmRpmvercmp(f.upstream, t.upstream), cmpRel)
}

// --- Alpine (apk-tools) ----------------------------------------------------

// apk token types, apk-tools order (lib/version.c)
const (
	apkDigitOrZero = iota
	apkDigit
	apkLetter
	apkSuffix
	apkSuffixNo
	apkRevisionNo
	apkEnd
	apkInvalid
)

var apkValidRe = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)*[a-z]?(?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)[0-9]*)*(?:-r[0-9]+)?$`)

var apkPreSuffixes = []string{"alpha", "beta", "pre", "rc"}
var apkPostSuffixes = []string{"cvs", "svn", "git", "hg", "p"}

type apkLexer struct {
	s   string
	typ int
}

func (l *apkLexer) next() {
	if l.s == "" {
		l.typ = apkEnd
		return
	}
	c := l.s[0]
	n := apkInvalid
	switch {
	case (l.typ == apkDigit || l.typ == apkDigitOrZero) && c >= 'a' && c <= 'z':
		n = apkLetter
	case l.typ == apkLetter && isDigitByte(c):
		n = apkDigit
	case l.typ == apkSuffix && isDigitByte(c):
		n = apkSuffixNo
	default:
		switch c {
		case '.':
			n = apkDigitOrZero
		case '_':
			n = apkSuffix
		case '-':
			if len(l.s) > 1 && l.s[1] == 'r' {
				n = apkRevisionNo
				l.s = l.s[1:]
			}
		}
		l.s = l.s[1:]
	}
	// types only advance, except new component/suffix/digits
	allowedBack := (n == apkDigitOrZero && l.typ == apkDigit) || (n == apkSuffix && l.typ == apkSuffixNo) || (n == apkDigit && l.typ == apkLetter)
	if n < l.typ && !allowedBack {
		n = apkInvalid
	}
	l.typ = n
}

func (l *apkLexer) token() int {
	if l.s == "" {
		l.typ = apkEnd
		return 0
	}
	v, i, nt := 0, 0, apkInvalid
	switch l.typ {
	case apkDigitOrZero, apkDigit, apkSuffixNo, apkRevisionNo:
		if l.typ == apkDigitOrZero && l.s[0] == '0' { // leading zeros: fewer zeros sort higher
			for i < len(l.s) && l.s[i] == '0' {
				i++
			}
			v, nt = -i, apkDigit
			break
		}
		for i < len(l.s) && isDigitByte(l.s[i]) {
			v = v*10 + int(l.s[i]-'0')
			i++
		}
	case apkLetter:
		v, i = int(l.s[0]), 1
	case apkSuffix:
		found := false
		for k, suf := range apkPreSuffixes {
			if strings.HasPrefix(l.s, suf) {
				v, i, found = k-len(apkPreSuffixes), len(suf), true
				break
			}
		}
		if !found {
			for k, suf := range apkPostSuffixes {
				if strings.HasPrefix(l.s, suf) {
					v, i, found = k, len(suf), true
					break
				}
			}
		}
		if !found {
			l.typ = apkInvalid
			return -1
		}
	default:
		l.typ = apkInvalid
		return -1
	}
	l.s = l.s[i:]
	switch {
	case l.s == "":
		l.typ = apkEnd
	case nt != apkInvalid && (isDigitByte(l.s[0]) || l.s[0] == '.'):
		// after leading zeros: rest of component
		l.typ = nt
	default:
		l.next()
	}
	return v
}

// apkVersionCompare is apk-tools' apk_version_compare.
func apkVersionCompare(a, b string) int {
	la, lb := &apkLexer{s: a, typ: apkDigit}, &apkLexer{s: b, typ: apkDigit}
	av, bv := 0, 0
	for la.typ == lb.typ && la.typ != apkEnd && la.typ != apkInvalid && av == bv {
		av, bv = la.token(), lb.token()
	}
	switch {
	case av < bv:
		return -1
	case av > bv:
		return 1
	case la.typ == lb.typ:
		return 0
	}
	if la.typ == apkSuffix {
		t := *la
		if t.token() < 0 {
			return -1
		}
	}
	if lb.typ == apkSuffix {
		t := *lb
		if t.token() < 0 {
			return 1
		}
	}
	switch {
	case la.typ > lb.typ:
		return -1
	case lb.typ > la.typ:
		return 1
	}
	return 0
}

// apkSplitRevision: "1.2.3-r4" -> "1.2.3"
func apkSplitRevision(v string) string {
	if i := strings.LastIndex(v, "-r"); i >= 0 {
		return v[:i]
	}
	return v
}

func compareAPK(from, to string) (string, string) {
	if !apkValidRe.MatchString(from) || !apkValidRe.MatchString(to) {
		return DirectionUnknown, LevelUnknown
	}
	c := apkVersionCompare(from, to)
	if c == 0 {
		return DirectionNone, LevelNone
	}
	fu, tu := apkSplitRevision(from), apkSplitRevision(to)
	if apkVersionCompare(fu, tu) == 0 {
		return directionOf(c), LevelRevision
	}
	return directionOf(c), numericLevel(fu, tu)
}

// --- RubyGems (Gem::Version) -----------------------------------------------

var gemRe = regexp.MustCompile(`^\s*[0-9]+(?:\.[0-9a-zA-Z]+)*(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\s*$`)
var gemSegRe = regexp.MustCompile(`[0-9]+|[a-zA-Z]+`)

type gemSegment struct {
	num   int
	str   string
	isNum bool
}

// gemSegments: Gem::Version#canonical_segments
func gemSegments(v string) ([]gemSegment, bool) {
	v = strings.TrimSpace(v)
	if !gemRe.MatchString(v) {
		return nil, false
	}
	v = strings.ReplaceAll(v, "-", ".pre.")
	var segs []gemSegment
	for _, s := range gemSegRe.FindAllString(v, -1) {
		if n, err := strconv.Atoi(s); err == nil {
			segs = append(segs, gemSegment{num: n, isNum: true})
		} else {
			segs = append(segs, gemSegment{str: s})
		}
	}
	split := len(segs)
	for i, s := range segs {
		if !s.isNum {
			split = i
			break
		}
	}
	trim := func(part []gemSegment) []gemSegment {
		for len(part) > 0 && part[len(part)-1].isNum && part[len(part)-1].num == 0 {
			part = part[:len(part)-1]
		}
		return part
	}
	return append(trim(segs[:split:split]), trim(segs[split:])...), true
}

func cmpGem(a, b []gemSegment) int {
	for i := 0; i < max(len(a), len(b)); i++ {
		x, y := gemSegment{isNum: true}, gemSegment{isNum: true}
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		switch {
		case x.isNum && y.isNum:
			if c := sign(x.num - y.num); c != 0 {
				return c
			}
		case !x.isNum && y.isNum:
			return -1
		case x.isNum && !y.isNum:
			return 1
		default:
			if c := strings.Compare(x.str, y.str); c != 0 {
				return c
			}
		}
	}
	return 0
}

func compareGem(from, to string) (string, string) {
	f, ok1 := gemSegments(from)
	t, ok2 := gemSegments(to)
	if !ok1 || !ok2 {
		return DirectionUnknown, LevelUnknown
	}
	c := cmpGem(f, t)
	if c == 0 {
		return DirectionNone, LevelNone
	}
	// release: numbers before first letter segment
	release := func(s []gemSegment) []string {
		var out []string
		for _, g := range s {
			if !g.isNum {
				break
			}
			out = append(out, strconv.Itoa(g.num))
		}
		return out
	}
	rf, rt := release(f), release(t)
	if strings.Join(rf, ".") == strings.Join(rt, ".") {
		return directionOf(c), LevelPrerelease
	}
	return directionOf(c), numericLevel(strings.Join(rf, "."), strings.Join(rt, "."))
}

// --- Maven -----------------------------------------------------------------

func compareMaven(from, to string) (string, string) {
	f, err1 := mvn.NewVersion(from)
	t, err2 := mvn.NewVersion(to)
	if err1 != nil || err2 != nil {
		return DirectionUnknown, LevelUnknown
	}
	c := sign(f.Compare(t))
	if c == 0 {
		return DirectionNone, LevelNone
	}
	return directionOf(c), numericLevel(from, to)
}
