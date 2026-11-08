package analysis

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVersionOracle: comparators vs ecosystem tools
func TestVersionOracle(t *testing.T) {
	want := map[string]string{"-1": DirectionUpgrade, "0": DirectionNone, "1": DirectionDowngrade}
	for _, eco := range []string{"deb", "apk", "alpm", "rpm", "gem", "maven"} {
		f, err := os.Open(filepath.Join("testdata", "version-oracle", eco+".tsv"))
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		n, unknown := 0, 0
		for sc.Scan() {
			p := strings.Split(sc.Text(), "\t")
			if len(p) != 3 {
				t.Fatalf("%s: bad line %q", eco, sc.Text())
			}
			n++
			dir, _ := ClassifyVersionChange(eco, p[0], p[1])
			switch {
			case dir == DirectionUnknown:
				if p[2] != "ERR" {
					unknown++ // the tool ordered it, we did not
				}
			case p[2] == "ERR" || dir != want[p[2]]:
				t.Errorf("%s %q -> %q: %s, tool says %s", eco, p[0], p[1], dir, p[2])
			}
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		// only invalid deb versions may be unknown
		if limit := map[string]int{"deb": 62}[eco]; unknown > limit {
			t.Errorf("%s: %d of %d pairs unknown, want <= %d", eco, unknown, n, limit)
		}
	}
}
