package main

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/rezmoss/sbomlyze/internal/cli"
	"github.com/rezmoss/sbomlyze/internal/policy"
)

const repo = "../../.."

// every policy field needs a doc tag: it is the website's description
func TestPolicyFieldsDocumented(t *testing.T) {
	typ := reflect.TypeOf(policy.Policy{})
	for i := 0; i < typ.NumField(); i++ {
		if f := typ.Field(i); f.Tag.Get("doc") == "" {
			t.Errorf("policy.Policy.%s has no doc tag", f.Name)
		}
	}
	readme, err := os.ReadFile(filepath.Join(repo, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range policyDocs() {
		if !strings.Contains(string(readme), "`"+r.Key+"`") {
			t.Errorf("README policy table lacks %s", r.Key)
		}
	}
}

// every flag the parser handles must be in --help and on the site
func TestCLIFlagsDocumented(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repo, "internal", "cli", "options.go"))
	if err != nil {
		t.Fatal(err)
	}
	var docs strings.Builder
	for _, o := range cli.OptionDocs {
		docs.WriteString(" " + o.Flag + " ")
	}
	for _, m := range regexp.MustCompile(`"(--?[a-z][a-z-]*)"`).FindAllStringSubmatch(string(src), -1) {
		flag := m[1]
		if flag == "-f" { // --format alias
			continue
		}
		if !regexp.MustCompile(`[ ,]` + regexp.QuoteMeta(flag) + `[ ,]`).MatchString(docs.String()) {
			t.Errorf("flag %s is parsed but not in cli.OptionDocs", flag)
		}
	}
}

func TestGenerate(t *testing.T) {
	site := t.TempDir()
	if err := os.MkdirAll(filepath.Join(site, "content"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := run(repo, site, "v9.9.9", "abc", 3); err != nil {
		t.Fatal(err)
	}
	act, err := actionDocs(filepath.Join(repo, "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"sbom-path", "fail-on", "report-sarif", "integrity-drift-count"} {
		found := false
		for _, f := range append(act["inputs"], act["outputs"]...) {
			found = found || f.Name == want
		}
		if !found {
			t.Errorf("action.yml field %s missing", want)
		}
	}
	n, err := whatsNew(filepath.Join(repo, "CHANGELOG.md"))
	if err != nil || n.Version == "" || len(n.Sections) == 0 {
		t.Errorf("whatsNew = %+v, %v", n, err)
	}
	for _, f := range []string{"data/gen/release.json", "data/gen/versions.json", "content/changelog.md", "content/json-reference.md"} {
		if _, err := os.Stat(filepath.Join(site, f)); err != nil {
			t.Error(err)
		}
	}
	if c := complianceDocs(); len(c) != 3 || len(c[0].Checks) == 0 {
		t.Errorf("compliance = %+v", c)
	}
}
