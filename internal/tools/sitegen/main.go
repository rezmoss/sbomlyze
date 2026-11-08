// Command sitegen writes the website's reference data from the code.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/rezmoss/sbomlyze/internal/analysis"
	"github.com/rezmoss/sbomlyze/internal/cli"
	"github.com/rezmoss/sbomlyze/internal/compliance"
	"github.com/rezmoss/sbomlyze/internal/output"
	"github.com/rezmoss/sbomlyze/internal/policy"
	"github.com/rezmoss/sbomlyze/internal/sbom"
)

func main() {
	repo := flag.String("repo", ".", "repo root (source of truth)")
	site := flag.String("site", "site", "Hugo site dir to write into")
	tag := flag.String("tag", "", "release tag, e.g. v0.7.1")
	sha := flag.String("sha", "", "commit SHA of the tag")
	stars := flag.Int("stars", 0, "GitHub star count (0 hides it)")
	flag.Parse()
	if err := run(*repo, *site, *tag, *sha, *stars); err != nil {
		fmt.Fprintln(os.Stderr, "sitegen:", err)
		os.Exit(1)
	}
}

func run(repo, site, tag, sha string, stars int) error {
	gen := filepath.Join(site, "data", "gen")
	if err := os.MkdirAll(gen, 0o755); err != nil {
		return err
	}
	act, err := actionDocs(filepath.Join(repo, "action.yml"))
	if err != nil {
		return err
	}
	versions, err := versionDocs(filepath.Join(repo, "internal", "analysis", "testdata", "version-oracle"))
	if err != nil {
		return err
	}
	news, err := whatsNew(filepath.Join(repo, "CHANGELOG.md"))
	if err != nil {
		return err
	}
	files := map[string]any{
		"release.json":    map[string]any{"tag": tag, "version": strings.TrimPrefix(tag, "v"), "sha": sha, "stars": stars, "generated": time.Now().UTC().Format("2006-01-02")},
		"action.json":     act,
		"cli.json":        map[string]any{"options": cli.OptionDocs, "formats": cli.OutputFormats},
		"policy.json":     policyDocs(),
		"sarif.json":      sarifDocs(),
		"compliance.json": complianceDocs(),
		"versions.json":   versions,
		"whatsnew.json":   news,
	}
	for name, v := range files {
		if err := writeJSON(filepath.Join(gen, name), v); err != nil {
			return err
		}
	}
	pages := []struct{ src, dst, title, desc string }{
		{"CHANGELOG.md", "changelog.md", "Changelog", "Every sbomlyze release and what changed."},
		{filepath.Join("docs", "diff-json-contract.md"), "json-reference.md", "JSON reference", "The diff JSON contract: every field sbomlyze --json prints."},
	}
	for _, p := range pages {
		if err := markdownPage(filepath.Join(repo, p.src), filepath.Join(site, "content", p.dst), p.title, p.desc); err != nil {
			return err
		}
	}
	return nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

type actionField struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
	Default     string `json:"default,omitempty"`
}

// actionDocs reads inputs/outputs from action.yml, in file order.
func actionDocs(path string) (map[string][]actionField, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	out := map[string][]actionField{"inputs": nil, "outputs": nil}
	if len(doc.Content) == 0 {
		return nil, fmt.Errorf("%s: empty", path)
	}
	top := doc.Content[0]
	for i := 0; i+1 < len(top.Content); i += 2 {
		section := top.Content[i].Value
		if section != "inputs" && section != "outputs" {
			continue
		}
		m := top.Content[i+1]
		for j := 0; j+1 < len(m.Content); j += 2 {
			var f struct {
				Description string `yaml:"description"`
				Required    bool   `yaml:"required"`
				Default     string `yaml:"default"`
			}
			if err := m.Content[j+1].Decode(&f); err != nil {
				return nil, err
			}
			out[section] = append(out[section], actionField{m.Content[j].Value, f.Description, f.Required, f.Default})
		}
	}
	if len(out["inputs"]) == 0 || len(out["outputs"]) == 0 {
		return nil, fmt.Errorf("%s: no inputs or outputs", path)
	}
	return out, nil
}

type policyRule struct {
	Key  string `json:"key"`
	Type string `json:"type"`
	Doc  string `json:"doc"`
}

func policyDocs() []policyRule {
	var out []policyRule
	t := reflect.TypeOf(policy.Policy{})
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		key, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		typ := f.Type.Kind().String()
		if f.Type.Kind() == reflect.Slice {
			typ = "[]" + f.Type.Elem().Kind().String()
		}
		out = append(out, policyRule{key, typ, f.Tag.Get("doc")})
	}
	return out
}

type sarifRule struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Level string `json:"level"`
	Desc  string `json:"desc"`
}

func sarifDocs() []sarifRule {
	var out []sarifRule
	for _, r := range output.SARIFRules() {
		out = append(out, sarifRule{r.ID, r.Name, r.DefaultConfig.Level, r.ShortDescription.Text})
	}
	return out
}

type complianceFramework struct {
	Standard string                   `json:"standard"`
	Checks   []compliance.CheckResult `json:"checks"`
}

// complianceDocs lists each framework's checks (scores dropped).
func complianceDocs() []complianceFramework {
	// empty SBOMs are not scored; one placeholder lists every check
	r := compliance.Evaluate([]sbom.Component{{Name: "placeholder"}}, sbom.SBOMInfo{})
	var out []complianceFramework
	for _, f := range []*compliance.FrameworkResult{r.NTIA, r.CISA, r.BSI} {
		if f == nil {
			continue
		}
		checks := make([]compliance.CheckResult, len(f.Checks))
		for i, c := range f.Checks {
			checks[i] = compliance.CheckResult{ID: c.ID, Name: c.Name, Description: c.Description}
		}
		out = append(out, complianceFramework{string(f.Standard), checks})
	}
	return out
}

type versionDoc struct {
	analysis.VersionOrdering
	OraclePairs int `json:"oracle_pairs,omitempty"`
}

// versionDocs adds the oracle-tested pair count to each ordering.
func versionDocs(oracleDir string) ([]versionDoc, error) {
	var out []versionDoc
	for _, o := range analysis.VersionOrderings() {
		d := versionDoc{VersionOrdering: o}
		if o.Oracle != "" {
			n, err := countLines(filepath.Join(oracleDir, o.Oracle+".tsv"))
			if err != nil {
				return nil, err
			}
			d.OraclePairs = n
		}
		out = append(out, d)
	}
	return out, nil
}

func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }() // read-only
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			n++
		}
	}
	return n, sc.Err()
}

type newsSection struct {
	Title string   `json:"title"`
	Items []string `json:"items"`
}

type news struct {
	Version  string        `json:"version"`
	Date     string        `json:"date"`
	Sections []newsSection `json:"sections"`
}

var (
	releaseRe = regexp.MustCompile(`^## \[?([0-9][^\]\s]*)\]?(?:\([^)]*\))?\s*(?:\(([0-9-]+)\))?`)
	linkRe    = regexp.MustCompile(`\s*\(\[[^\]]*\]\([^)]*\)\)`)
	mdLinkRe  = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`)
)

// whatsNew parses the newest release section of CHANGELOG.md.
func whatsNew(path string) (news, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return news{}, err
	}
	var n news
	var cur *newsSection
	for _, line := range strings.Split(string(b), "\n") {
		if m := releaseRe.FindStringSubmatch(line); m != nil {
			if n.Version != "" {
				break
			}
			n.Version, n.Date = m[1], m[2]
			continue
		}
		if n.Version == "" {
			continue
		}
		if t, ok := strings.CutPrefix(line, "### "); ok {
			n.Sections = append(n.Sections, newsSection{Title: strings.TrimSpace(t)})
			cur = &n.Sections[len(n.Sections)-1]
			continue
		}
		if item, ok := strings.CutPrefix(line, "* "); ok && cur != nil {
			item = mdLinkRe.ReplaceAllString(linkRe.ReplaceAllString(item, ""), "$1")
			cur.Items = append(cur.Items, strings.TrimSpace(item))
		}
	}
	if n.Version == "" {
		return n, fmt.Errorf("%s: no release section", path)
	}
	return n, nil
}

// markdownPage copies a repo doc into a Hugo page, dropping its H1.
func markdownPage(src, dst, title, desc string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	body := string(b)
	if first, rest, ok := strings.Cut(body, "\n"); ok && strings.HasPrefix(first, "# ") {
		body = rest
	}
	front := fmt.Sprintf("---\ntitle: %q\ndescription: %q\nlayout: doc\n---\n", title, desc)
	return os.WriteFile(dst, []byte(front+body), 0o644)
}
