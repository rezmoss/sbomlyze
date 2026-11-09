package main

import (
	"encoding/json"
	"testing"
)

func TestLookup(t *testing.T) {
	var v any
	if err := json.Unmarshal([]byte(`{"diff":{
		"drift_summary":{"upgrades":40},
		"changed":[{"name":"openssl","drift":{"level":"revision","version_to":"3.0.17"}},{"name":"bash","drift":{"level":"patch"}}],
		"dependencies":{"added_deps":{"pkg:cargo/cc":["pkg:cargo/shlex"]}}}}`), &v); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		path string
		want any
	}{
		{"diff.drift_summary.upgrades", 40},
		{"diff.changed[name=openssl].drift.version_to", "3.0.17"},
		{"diff.changed[drift.level=patch].name", "bash"},
		{"diff.dependencies.added_deps.pkg:cargo/cc", []any{"pkg:cargo/shlex"}},
	}
	for _, c := range cases {
		got, err := lookup(v, c.path)
		if err != nil || !equal(got, c.want) {
			t.Errorf("%s = %v (%v), want %v", c.path, got, err, c.want)
		}
	}
	if _, err := lookup(v, "diff.nope"); err == nil {
		t.Error("missing key must fail")
	}
	n := 2
	if err := (check{Run: "r", Path: "diff.changed", Count: &n}).eval(map[string]*result{"r": {jsonV: v}}, ""); err != nil {
		t.Error(err)
	}
	n = 3
	if err := (check{Run: "r", Path: "diff.changed", Count: &n}).eval(map[string]*result{"r": {jsonV: v}}, ""); err == nil {
		t.Error("wrong count must fail")
	}
}

func TestSummary(t *testing.T) {
	text := "SBOM Comparison\nFile: a\n\nKey Findings:\n  x\n\n~ Changed (1):\n  ~ pkg [INTEGRITY]\n      hash: a -> b\n\n\n❌ Policy Errors (1):\n  [deny] pkg\n"
	want := "Key Findings:\n  x\n\n~ Changed (1):\n  ~ pkg [INTEGRITY]\n      hash: a -> b\n\n❌ Policy Errors (1):\n  [deny] pkg"
	if got := summary(text); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func TestLookupStrict(t *testing.T) {
	var v any
	_ = json.Unmarshal([]byte(`{"diff":{"summary":{"n":1},"changed":[{"name":"a","drift":{}},{"name":"b"}]}}`), &v)
	for _, p := range []string{"diff.summary[name=x]", "diff.changed.drift.level", "diff.nope.x", "diff.changed[nmae=a]"} {
		if _, err := lookup(v, p); err == nil {
			t.Errorf("%s must fail", p)
		}
	}
	// empty selection is a valid count of 0
	if got, err := lookup(v, "diff.changed[name=zzz]"); err != nil || len(got.([]any)) != 0 {
		t.Errorf("got %v %v", got, err)
	}
}

func TestCrate(t *testing.T) {
	for in, want := range map[string]string{"pkg:cargo/windows-sys": "windows_sys", "cpe:ignore_project:ignore": "ignore", "grep-cli 0.1.10": "grep_cli 0.1.10"} {
		if got := crate(in); got != want {
			t.Errorf("crate(%q) = %q", in, got)
		}
	}
}
