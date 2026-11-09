// Command showcase runs the website examples against frozen input SBOMs.
// It writes outputs and page data for Hugo, and fails on any broken check.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

type manifest struct {
	InputsDir string    `yaml:"inputs_dir" json:"inputs_dir"` // repo path of the frozen SBOMs
	Repo      string    `yaml:"repo" json:"repo"`
	Examples  []example `yaml:"examples" json:"examples"`
}

type link struct {
	Label string `yaml:"label" json:"label"`
	URL   string `yaml:"url" json:"url"`
}

type input struct {
	Name   string `yaml:"name" json:"name"`
	Label  string `yaml:"label" json:"label"`
	Target string `yaml:"target" json:"target"`
	Note   string `yaml:"note" json:"note,omitempty"`
	// filled in
	Files []inputFile `yaml:"-" json:"files"`
}

type inputFile struct {
	Format  string `json:"format"`
	File    string `json:"file"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	Command string `json:"command"`
}

type run struct {
	ID      string   `yaml:"id" json:"id"`
	Title   string   `yaml:"title" json:"title"`
	Args    []string `yaml:"args" json:"args"`
	Formats []string `yaml:"formats" json:"-"`
	Exit    int      `yaml:"exit" json:"exit"`
	// filled in
	Command string    `yaml:"-" json:"command"`
	Text    string    `yaml:"-" json:"text"`
	Summary string    `yaml:"-" json:"summary"` // Key Findings + policy blocks
	Outputs []outFile `yaml:"-" json:"outputs"`
	Changed string    `yaml:"-" json:"changed_since,omitempty"` // diff vs previous release
}

type outFile struct {
	Format string `json:"format"`
	Path   string `json:"path"`
	Size   int    `json:"size"`
}

type check struct {
	Run      string `yaml:"run" json:"run"`
	Path     string `yaml:"path" json:"path,omitempty"`
	Equals   any    `yaml:"equals" json:"equals,omitempty"`
	Count    *int   `yaml:"count" json:"count,omitempty"`
	Contains string `yaml:"contains" json:"contains,omitempty"`
	// ground truth from evidence files: [before, after]
	DpkgPairs  *[2]string `yaml:"dpkg_pairs" json:"dpkg_pairs,omitempty"`
	CargoEdges *[2]string `yaml:"cargo_edges" json:"cargo_edges,omitempty"`
}

type example struct {
	ID        string            `yaml:"id" json:"id"`
	Title     string            `yaml:"title" json:"title"`
	Finding   string            `yaml:"finding" json:"finding"`
	Tags      []string          `yaml:"tags" json:"tags"`
	Features  []string          `yaml:"features" json:"features"`
	Story     string            `yaml:"story" json:"story"`
	NotProven string            `yaml:"not_proven" json:"not_proven"`
	Sources   []link            `yaml:"sources" json:"sources"`
	Inputs    []input           `yaml:"inputs" json:"inputs"`
	Policies  map[string]any    `yaml:"policies" json:"-"`
	Runs      []run             `yaml:"runs" json:"runs"`
	Checks    []check           `yaml:"checks" json:"checks"`
	Media     []link            `yaml:"media" json:"media,omitempty"`       // url = file in examples/media/
	Evidence  []link            `yaml:"evidence" json:"evidence,omitempty"` // url = file in the inputs release
	PolicyOut map[string]string `yaml:"-" json:"policies,omitempty"`        // name -> path
}

var formatExt = map[string]string{
	"text": "txt", "json": "json", "markdown": "md", "html": "html",
	"sarif": "sarif.json", "junit": "junit.xml", "patch": "patch.json",
}

var sbomFormats = []struct{ ext, flag string }{
	{"syft", "syft-json"}, {"cdx", "cyclonedx-json"}, {"spdx", "spdx-json"},
}

func main() {
	man := flag.String("manifest", "showcase/examples.yaml", "examples manifest")
	inputs := flag.String("inputs", "", "dir with the input SBOMs and SHA256SUMS")
	bin := flag.String("bin", "", "sbomlyze binary to run")
	site := flag.String("site", "", "Hugo site dir to write into (empty = check only)")
	tag := flag.String("tag", "", "release tag shown on the pages")
	prev := flag.String("prev", "", "previous release's examples dir, for changed_since")
	archives := flag.String("archives", "", "comma-separated earlier tags with archived outputs")
	flag.Parse()
	if *inputs == "" || *bin == "" {
		fmt.Fprintln(os.Stderr, "showcase: -inputs and -bin are required")
		os.Exit(2)
	}
	if err := runAll(*man, *inputs, *bin, *site, *tag, *prev, *archives); err != nil {
		fmt.Fprintln(os.Stderr, "showcase:", err)
		os.Exit(1)
	}
}

func runAll(manPath, inputs, bin, site, tag, prev, archives string) error {
	b, err := os.ReadFile(manPath)
	if err != nil {
		return err
	}
	var m manifest
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return fmt.Errorf("%s: %w", manPath, err)
	}
	sums, err := readSums(inputs)
	if err != nil {
		return err
	}
	bin, err = filepath.Abs(bin)
	if err != nil {
		return err
	}
	var failed []string
	for i := range m.Examples {
		ex := &m.Examples[i]
		if err := ex.fillInputs(m, inputs, sums, ref(tag)); err != nil {
			return fmt.Errorf("%s: %w", ex.ID, err)
		}
		outs, err := ex.execute(bin, inputs)
		if err != nil {
			return fmt.Errorf("%s: %w", ex.ID, err)
		}
		for _, c := range ex.Checks {
			if err := c.eval(outs, inputs); err != nil {
				failed = append(failed, fmt.Sprintf("%s/%s: %v", ex.ID, c.Run, err))
			}
		}
		if site != "" {
			if err := ex.write(site, tag, prev, outs); err != nil {
				return fmt.Errorf("%s: %w", ex.ID, err)
			}
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d check(s) failed:\n  %s", len(failed), strings.Join(failed, "\n  "))
	}
	if site == "" {
		fmt.Printf("showcase: %d examples, all checks passed\n", len(m.Examples))
		return nil
	}
	var arch []string
	for _, t := range strings.Split(archives, ",") {
		if t = strings.TrimSpace(t); t != "" && t != tag {
			arch = append(arch, t)
		}
	}
	slices.SortFunc(arch, func(a, b string) int { return strings.Compare(b, a) })
	data := map[string]any{
		"tag": tag, "generated": time.Now().UTC().Format("2006-01-02"),
		"inputs_dir": m.InputsDir, "inputs_url": treeURL(m, ref(tag)), "repo": m.Repo, "examples": m.Examples, "archives": arch,
	}
	if err := writeJSON(filepath.Join(site, "data", "gen", "showcase.json"), data); err != nil {
		return err
	}
	if tag != "" {
		if err := writeArchiveIndex(site, tag, m); err != nil {
			return err
		}
	}
	return writePages(site, m)
}

func readSums(dir string) (map[string]string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return nil, err
	}
	sums := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 {
			sums[strings.TrimPrefix(f[1], "*")] = f[0]
		}
	}
	return sums, nil
}

// fillInputs verifies each input file against SHA256SUMS
// ref: git ref the input links point at
func ref(tag string) string {
	if tag == "" {
		return "main"
	}
	return tag
}

func rawURL(m manifest, ref, file string) string {
	return fmt.Sprintf("https://github.com/%s/raw/%s/%s/%s", m.Repo, ref, m.InputsDir, file)
}

func treeURL(m manifest, ref string) string {
	return fmt.Sprintf("https://github.com/%s/tree/%s/%s", m.Repo, ref, m.InputsDir)
}

func (ex *example) fillInputs(m manifest, dir string, sums map[string]string, ref string) error {
	for i, e := range ex.Evidence {
		if _, ok := sums[e.URL]; !ok {
			return fmt.Errorf("evidence %s not in SHA256SUMS", e.URL)
		}
		if err := verifySum(dir, e.URL, sums); err != nil {
			return err
		}
		ex.Evidence[i].URL = rawURL(m, ref, e.URL)
	}
	for i := range ex.Inputs {
		in := &ex.Inputs[i]
		for _, f := range sbomFormats {
			name := in.Name + "." + f.ext + ".json"
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				return err
			}
			sum := sha256.Sum256(data)
			got := hex.EncodeToString(sum[:])
			if want := sums[name]; want != got {
				return fmt.Errorf("%s: sha256 %s, SHA256SUMS says %q", name, got, want)
			}
			in.Files = append(in.Files, inputFile{
				Format: f.ext, File: name, SHA256: got, Size: int64(len(data)),
				URL:     rawURL(m, ref, name),
				Command: fmt.Sprintf("syft scan %s -o %s=%s", in.Target, f.flag, name),
			})
		}
	}
	return nil
}

type result struct {
	exit  int
	out   map[string][]byte // format -> stdout
	jsonV any               // parsed json output, if any
}

// execute runs every run in each format; exit code must match
func (ex *example) execute(bin, dir string) (map[string]*result, error) {
	work, err := os.MkdirTemp("", "showcase-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(work) }() // temp dir
	ex.PolicyOut = map[string]string{}
	for name, p := range ex.Policies {
		b, err := json.MarshalIndent(p, "", "  ")
		if err != nil {
			return nil, err
		}
		file := "policy-" + name + ".json"
		if err := os.WriteFile(filepath.Join(work, file), append(b, '\n'), 0o644); err != nil {
			return nil, err
		}
		ex.PolicyOut[name] = file
	}
	outs := map[string]*result{}
	for i := range ex.Runs {
		r := &ex.Runs[i]
		formats := r.Formats
		if len(formats) == 0 {
			formats = []string{"text"}
		}
		needJSON := !slices.Contains(formats, "json") && slices.ContainsFunc(ex.Checks, func(c check) bool { return c.Run == r.ID && c.Path != "" })
		res := &result{out: map[string][]byte{}}
		for _, f := range append(slices.Clone(formats), map[bool]string{true: "json"}[needJSON]) {
			if f == "" {
				continue
			}
			args := resolveArgs(r.Args, dir, work)
			if f != "text" {
				args = append(args, "--format", f)
			}
			cmd := exec.Command(bin, append(args, "--no-pager")...)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "NO_COLOR=1", "TERM=dumb")
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			code := 0
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				code = ee.ExitCode()
			} else if err != nil {
				return nil, err
			}
			if code != r.Exit {
				return nil, fmt.Errorf("run %s (%s): exit %d, want %d: %s", r.ID, f, code, r.Exit, strings.TrimSpace(stderr.String()))
			}
			if stdout.Len() == 0 {
				return nil, fmt.Errorf("run %s (%s): empty output", r.ID, f)
			}
			res.exit = code
			res.out[f] = stdout.Bytes()
		}
		if j, ok := res.out["json"]; ok {
			if err := json.Unmarshal(j, &res.jsonV); err != nil {
				return nil, fmt.Errorf("run %s: json: %w", r.ID, err)
			}
		}
		r.Command = "sbomlyze " + strings.Join(r.Args, " ")
		r.Text = string(res.out["text"])
		r.Summary = summary(r.Text)
		outs[r.ID] = res
	}
	return outs, nil
}

// resolveArgs: policy files live in work, SBOMs in dir
func resolveArgs(args []string, dir, work string) []string {
	out := slices.Clone(args)
	for i, a := range out {
		if strings.HasPrefix(a, "policy-") && strings.HasSuffix(a, ".json") {
			out[i] = filepath.Join(work, a)
		}
	}
	return out
}

// write: outputs under static/examples/<id>/ and the tag archive
func (ex *example) write(site, tag, prev string, outs map[string]*result) error {
	dirs := []string{filepath.Join(site, "static", "examples", ex.ID)}
	if tag != "" {
		dirs = append(dirs, filepath.Join(site, "static", "examples", tag, ex.ID))
	}
	for _, d := range dirs {
		if err := os.RemoveAll(d); err != nil {
			return err
		}
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	for i := range ex.Runs {
		r := &ex.Runs[i]
		res := outs[r.ID]
		formats := r.Formats
		if len(formats) == 0 {
			formats = []string{"text"}
		}
		for _, f := range formats {
			name := r.ID + "." + formatExt[f]
			for _, d := range dirs {
				if err := os.WriteFile(filepath.Join(d, name), res.out[f], 0o644); err != nil {
					return err
				}
			}
			r.Outputs = append(r.Outputs, outFile{Format: f, Path: "examples/" + ex.ID + "/" + name, Size: len(res.out[f])})
		}
		if prev != "" {
			if old, err := os.ReadFile(filepath.Join(prev, ex.ID, r.ID+".txt")); err == nil && !bytes.Equal(old, res.out["text"]) {
				r.Changed = unifiedDiff(old, res.out["text"])
			}
		}
	}
	for name, file := range ex.PolicyOut {
		b, _ := json.MarshalIndent(ex.Policies[name], "", "  ") // marshalled in execute
		for _, d := range dirs {
			if err := os.WriteFile(filepath.Join(d, file), append(b, '\n'), 0o644); err != nil {
				return err
			}
		}
		ex.PolicyOut[name] = "examples/" + ex.ID + "/" + file
	}
	return nil
}

// unifiedDiff shells out to diff -u; empty if unavailable
func unifiedDiff(a, b []byte) string {
	dir, err := os.MkdirTemp("", "showcase-diff-")
	if err != nil {
		return ""
	}
	defer func() { _ = os.RemoveAll(dir) }() // temp dir
	pa, pb := filepath.Join(dir, "previous"), filepath.Join(dir, "current")
	if os.WriteFile(pa, a, 0o644) != nil || os.WriteFile(pb, b, 0o644) != nil {
		return ""
	}
	out, _ := exec.Command("diff", "-u", "--label", "previous release", "--label", "this release", pa, pb).Output() // exit 1 = differ
	return string(out)
}

// writePages: one Hugo page per example
func writePages(site string, m manifest) error {
	dir := filepath.Join(site, "content", "examples")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for i, ex := range m.Examples {
		front := fmt.Sprintf("---\ntitle: %q\ndescription: %q\nlayout: example\nexample: %q\nweight: %d\n---\n", ex.Title, ex.Finding, ex.ID, i+1)
		if err := os.WriteFile(filepath.Join(dir, ex.ID+".md"), []byte(front), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// eval: one check against a run's output
func (c check) eval(outs map[string]*result, dir string) error {
	res, ok := outs[c.Run]
	if !ok {
		return fmt.Errorf("no run %q", c.Run)
	}
	if c.DpkgPairs != nil {
		return checkDpkg(res.jsonV, dir, *c.DpkgPairs)
	}
	if c.CargoEdges != nil {
		return checkCargo(res.jsonV, dir, *c.CargoEdges)
	}
	if c.Contains != "" {
		if !bytes.Contains(res.out["text"], []byte(c.Contains)) {
			return fmt.Errorf("text output lacks %q", c.Contains)
		}
		return nil
	}
	got, err := lookup(res.jsonV, c.Path)
	if err != nil {
		return err
	}
	if c.Count != nil {
		n := 0
		if l, ok := got.([]any); ok {
			n = len(l)
		} else if got != nil {
			n = 1
		}
		if n != *c.Count {
			return fmt.Errorf("%s: count %d, want %d", c.Path, n, *c.Count)
		}
		return nil
	}
	if !equal(got, c.Equals) {
		return fmt.Errorf("%s = %s, want %s", c.Path, show(got), show(c.Equals))
	}
	return nil
}

var segRe = regexp.MustCompile(`^([^\[]+)(?:\[([^=\]]+)=([^\]]*)\])?$`)

// lookup: dotted path; key[field=value] filters a list
// keys may contain dots ("pkg:cargo/cc"): longest match wins
func lookup(v any, path string) (any, error) {
	parts := splitPath(path)
	cur := []any{v}
	multi := false
	for i := 0; i < len(parts); i++ {
		var next []any
		consumed := 1
		for _, x := range cur {
			obj, ok := x.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%s: %q is not an object", path, parts[i])
			}
			key, filter, n := matchKey(obj, parts[i:])
			consumed = n
			m := segRe.FindStringSubmatch(key + filter)
			if m == nil {
				return nil, fmt.Errorf("%s: bad segment %q", path, key+filter)
			}
			val, ok := obj[m[1]]
			if !ok {
				return nil, fmt.Errorf("%s: %q not found", path, m[1])
			}
			list, isList := val.([]any)
			if m[2] != "" && !isList {
				return nil, fmt.Errorf("%s: selector on non-list %q", path, m[1])
			}
			if isList {
				multi = true
				seen := false // selector field present on some element
				for _, el := range list {
					if m[2] == "" {
						next = append(next, el)
						continue
					}
					got, err := lookup(el, m[2])
					if err == nil {
						seen = true
						if fmt.Sprint(got) == m[3] {
							next = append(next, el)
						}
					}
				}
				// typo in a selector must not read as an empty match
				if m[2] != "" && len(list) > 0 && !seen {
					return nil, fmt.Errorf("%s: no element of %q has %q", path, m[1], m[2])
				}
				continue
			}
			next = append(next, val)
		}
		i += consumed - 1
		cur = next
	}
	if !multi {
		if len(cur) == 0 {
			return nil, fmt.Errorf("%s: not found", path)
		}
		return cur[0], nil
	}
	return cur, nil
}

// splitPath keeps [..] filters whole
func splitPath(p string) []string {
	var out []string
	depth, start := 0, 0
	for i, r := range p {
		switch r {
		case '[':
			depth++
		case ']':
			depth--
		case '.':
			if depth == 0 {
				out = append(out, p[start:i])
				start = i + 1
			}
		}
	}
	return append(out, p[start:])
}

// matchKey: longest run of parts that names a key in obj
func matchKey(obj map[string]any, parts []string) (key, filter string, n int) {
	for n = len(parts); n > 1; n-- {
		k := strings.Join(parts[:n], ".")
		// a filter can only end the key
		base, f, _ := strings.Cut(k, "[")
		if strings.Contains(strings.Join(parts[:n-1], "."), "[") {
			continue
		}
		if _, ok := obj[base]; ok {
			if f != "" {
				f = "[" + f
			}
			return base, f, n
		}
	}
	base, f, _ := strings.Cut(parts[0], "[")
	if f != "" {
		f = "[" + f
	}
	return base, f, 1
}

func equal(got, want any) bool {
	// one-element list vs scalar
	if l, ok := got.([]any); ok && len(l) == 1 {
		if _, wantList := want.([]any); !wantList {
			got = l[0]
		}
	}
	return show(got) == show(want)
}

func show(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// summary: Key Findings, a short Changed block, policy blocks
func summary(text string) string {
	var out, block []string
	keep := func() {
		// long Changed lists stay in the full output
		if len(block) > 0 && (!strings.HasPrefix(strings.TrimSpace(block[0]), "~ Changed") || len(block) <= 12) {
			out = append(append(out, block...), "")
		}
		block = nil
	}
	in := false
	var scores []string // compliance mode: framework + score
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasSuffix(t, " Compliance") || strings.HasPrefix(t, "Score: ") {
			scores = append(scores, t)
		}
		switch {
		case t == "Key Findings:" || strings.HasPrefix(t, "~ Changed (") || strings.HasPrefix(t, "❌ Policy Errors") || strings.HasPrefix(t, "⚠️ Policy Warnings"):
			keep()
			in = true
		case t == "":
			if in {
				keep()
			}
			in = false
			continue
		}
		if in {
			block = append(block, line)
		}
	}
	keep()
	if len(scores) > 1 {
		out = []string{}
		for i := 0; i+1 < len(scores); i += 2 {
			out = append(out, scores[i]+"   "+scores[i+1])
		}
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

// writeArchiveIndex: static page for /examples/<tag>/, kept on gh-pages
func writeArchiveIndex(site, tag string, m manifest) error {
	var b strings.Builder
	esc := html.EscapeString
	fmt.Fprintf(&b, "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>sbomlyze %s examples</title>\n", esc(tag))
	b.WriteString("<style>body{font:15px/1.6 system-ui,sans-serif;max-width:860px;margin:40px auto;padding:0 20px}code{font-family:ui-monospace,monospace}</style></head><body>\n")
	fmt.Fprintf(&b, "<p><a href=\"/examples/\">Latest examples</a></p>\n<h1>sbomlyze %s: example output</h1>\n", esc(tag))
	fmt.Fprintf(&b, "<p>Output of sbomlyze %s on the SBOMs in <a href=\"%s\">%s</a>.</p>\n", esc(tag), esc(treeURL(m, tag)), esc(m.InputsDir))
	for _, ex := range m.Examples {
		fmt.Fprintf(&b, "<h2>%s</h2>\n<p>%s</p>\n<ul>\n", esc(ex.Title), esc(ex.Finding))
		for _, r := range ex.Runs {
			fmt.Fprintf(&b, "<li>%s: <code>%s</code> (exit %d):", esc(r.Title), esc(r.Command), r.Exit)
			for _, o := range r.Outputs {
				fmt.Fprintf(&b, " <a href=\"%s/%s\">%s</a>", esc(ex.ID), esc(filepath.Base(o.Path)), esc(o.Format))
			}
			b.WriteString("</li>\n")
		}
		b.WriteString("</ul>\n")
	}
	b.WriteString("</body></html>\n")
	return os.WriteFile(filepath.Join(site, "static", "examples", tag, "index.html"), []byte(b.String()), 0o644)
}

func verifySum(dir, name string, sums map[string]string) error {
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != sums[name] {
		return fmt.Errorf("%s: sha256 %s, SHA256SUMS says %q", name, got, sums[name])
	}
	return nil
}

// dpkgList: "name version" lines from dpkg-query
func dpkgList(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && !strings.HasSuffix(f[0], ":") && f[0] != "debian_version" {
			out[f[0]] = f[1]
		}
	}
	return out, nil
}

// checkDpkg: deb changes in the diff equal the dpkg lists' changes
func checkDpkg(v any, dir string, files [2]string) error {
	before, err := dpkgList(filepath.Join(dir, files[0]))
	if err != nil {
		return err
	}
	after, err := dpkgList(filepath.Join(dir, files[1]))
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for name, bv := range before {
		av, ok := after[name]
		switch {
		case !ok:
			want["-"+name+" "+bv] = true
		case av != bv:
			want["~"+name+" "+bv+" "+av] = true
		}
	}
	for name, av := range after {
		if _, ok := before[name]; !ok {
			want["+"+name+" "+av] = true
		}
	}
	got := map[string]bool{}
	isDeb := func(c any) bool {
		p, _ := lookup(c, "purl")
		s, _ := p.(string)
		return strings.HasPrefix(s, "pkg:deb/")
	}
	str := func(c any, path string) string {
		x, _ := lookup(c, path)
		s, _ := x.(string)
		return s
	}
	for _, sec := range []struct{ key, sign string }{{"added", "+"}, {"removed", "-"}} {
		l, _ := lookup(v, "diff."+sec.key)
		list, _ := l.([]any)
		for _, c := range list {
			if isDeb(c) {
				got[sec.sign+str(c, "name")+" "+str(c, "version")] = true
			}
		}
	}
	l, _ := lookup(v, "diff.changed")
	list, _ := l.([]any)
	for _, c := range list {
		if b, _ := lookup(c, "before"); isDeb(b) && str(c, "drift.type") == "version" {
			got["~"+str(c, "name")+" "+str(c, "drift.version_from")+" "+str(c, "drift.version_to")] = true
		}
	}
	return compareSets("dpkg", want, got)
}

var cargoDepRe = regexp.MustCompile(`"([^" ]+)`)

// cargoEdges: package -> dependency names from Cargo.lock
func cargoEdges(path string) (map[string]bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	edges := map[string]bool{}
	var name string
	inDeps := false
	for _, line := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(line)
		switch {
		case t == "[[package]]":
			name, inDeps = "", false
		case strings.HasPrefix(t, "name = "):
			name = strings.Trim(strings.TrimPrefix(t, "name = "), `"`)
		case strings.HasPrefix(t, "dependencies = ["):
			inDeps = !strings.HasSuffix(t, "]")
			for _, m := range cargoDepRe.FindAllStringSubmatch(strings.TrimPrefix(t, "dependencies = ["), -1) {
				edges[crate(name)+" "+crate(m[1])] = true
			}
		case inDeps && t == "]":
			inDeps = false
		case inDeps:
			if m := cargoDepRe.FindStringSubmatch(t); m != nil {
				edges[crate(name)+" "+crate(m[1])] = true
			}
		}
	}
	return edges, nil
}

// crate: comparable crate name from a Cargo name or sbomlyze id
func crate(s string) string {
	if i := strings.LastIndexAny(s, "/:"); i >= 0 {
		s = s[i+1:]
	}
	return strings.ReplaceAll(strings.ToLower(s), "-", "_")
}

// checkCargo: dependency edge changes equal the Cargo.lock diff
func checkCargo(v any, dir string, files [2]string) error {
	before, err := cargoEdges(filepath.Join(dir, files[0]))
	if err != nil {
		return err
	}
	after, err := cargoEdges(filepath.Join(dir, files[1]))
	if err != nil {
		return err
	}
	want, got := map[string]bool{}, map[string]bool{}
	for e := range after {
		if !before[e] {
			want["+"+e] = true
		}
	}
	for e := range before {
		if !after[e] {
			want["-"+e] = true
		}
	}
	for _, sec := range []struct{ key, sign string }{{"added_deps", "+"}, {"removed_deps", "-"}} {
		m, _ := lookup(v, "diff.dependencies."+sec.key)
		deps, _ := m.(map[string]any)
		for from, tos := range deps {
			list, _ := tos.([]any)
			for _, to := range list {
				got[sec.sign+crate(from)+" "+crate(fmt.Sprint(to))] = true
			}
		}
	}
	return compareSets("Cargo.lock", want, got)
}

func compareSets(what string, want, got map[string]bool) error {
	var missing, extra []string
	for k := range want {
		if !got[k] {
			missing = append(missing, k)
		}
	}
	for k := range got {
		if !want[k] {
			extra = append(extra, k)
		}
	}
	if len(missing)+len(extra) == 0 {
		if len(want) == 0 {
			return fmt.Errorf("%s: no changes to compare", what)
		}
		return nil
	}
	slices.Sort(missing)
	slices.Sort(extra)
	return fmt.Errorf("%s mismatch: missing %v, extra %v", what, missing, extra)
}
