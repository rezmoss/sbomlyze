package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "update snapshot files")

var (
	goVersionRe = regexp.MustCompile(`go\d+\.\d+(\.\d+)?`)
	timestampRe = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z`)
)

func snapshotDir() string {
	dir, _ := os.Getwd()
	return filepath.Join(dir, "..", "..", "testdata", "snapshots")
}

func normalizeOutput(s string) string {
	// Replace absolute testdata paths with TESTDATA/
	tdPath := testdataPath("")
	s = strings.ReplaceAll(s, tdPath+"/", "TESTDATA/")
	s = strings.ReplaceAll(s, tdPath, "TESTDATA")

	// Replace Go version (e.g., go1.24.0 → goX.Y.Z)
	s = goVersionRe.ReplaceAllString(s, "goX.Y.Z")

	// Replace RFC3339 timestamps (e.g., 2026-02-09T20:52:34Z → TIMESTAMP)
	s = timestampRe.ReplaceAllString(s, "TIMESTAMP")

	return s
}

func compareOrUpdateSnapshot(t *testing.T, name, stdout, stderr string, exitCode int) {
	t.Helper()

	dir := snapshotDir()
	stdoutFile := filepath.Join(dir, name+".stdout")
	stderrFile := filepath.Join(dir, name+".stderr")
	exitcodeFile := filepath.Join(dir, name+".exitcode")

	stdout = normalizeOutput(stdout)
	stderr = normalizeOutput(stderr)
	exitCodeStr := strconv.Itoa(exitCode)

	if *update {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("failed to create snapshot dir: %v", err)
		}
		if err := os.WriteFile(stdoutFile, []byte(stdout), 0644); err != nil {
			t.Fatalf("failed to write %s: %v", stdoutFile, err)
		}
		if err := os.WriteFile(stderrFile, []byte(stderr), 0644); err != nil {
			t.Fatalf("failed to write %s: %v", stderrFile, err)
		}
		if err := os.WriteFile(exitcodeFile, []byte(exitCodeStr), 0644); err != nil {
			t.Fatalf("failed to write %s: %v", exitcodeFile, err)
		}
		return
	}

	compareSnapshot(t, "stdout", stdoutFile, stdout)
	compareSnapshot(t, "stderr", stderrFile, stderr)
	compareSnapshot(t, "exitcode", exitcodeFile, exitCodeStr)
}

func compareSnapshot(t *testing.T, label, file, actual string) {
	t.Helper()

	expected, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("snapshot file %s not found (run with -update to create): %v", file, err)
	}

	exp := string(expected)
	if exp == actual {
		return
	}

	expLines := strings.Split(exp, "\n")
	actLines := strings.Split(actual, "\n")

	maxLines := len(expLines)
	if len(actLines) > maxLines {
		maxLines = len(actLines)
	}

	var diff strings.Builder
	for i := 0; i < maxLines; i++ {
		var expLine, actLine string
		if i < len(expLines) {
			expLine = expLines[i]
		}
		if i < len(actLines) {
			actLine = actLines[i]
		}
		if expLine != actLine {
			fmt.Fprintf(&diff, "  line %d:\n    expected: %q\n    actual:   %q\n", i+1, expLine, actLine)
		}
	}

	t.Errorf("%s mismatch for %s:\n%s", label, filepath.Base(file), diff.String())
}

func TestSnapshot(t *testing.T) {
	td := testdataPath
	tests := []struct {
		name string
		args []string
	}{
		// Help/Version
		{"version_long", []string{"--version"}},
		{"version_short", []string{"-v"}},
		{"help_long", []string{"--help"}},
		{"no_args", nil},

		// Single File Stats — Text
		{"stats_cyclonedx_text", []string{td("cyclonedx-before.json")}},
		{"stats_spdx_text", []string{td("spdx-sample.json")}},
		{"stats_syft_text", []string{td("syft-sample.json")}},
		{"stats_empty_components_text", []string{td("cyclonedx-empty-components.json")}},
		{"stats_no_components_text", []string{td("cyclonedx-no-components.json")}},

		// Single File Stats — JSON
		{"stats_cyclonedx_json", []string{td("cyclonedx-before.json"), "--json"}},
		{"stats_spdx_json", []string{td("spdx-sample.json"), "--json"}},
		{"stats_syft_json", []string{td("syft-sample.json"), "--json"}},

		// Two File Diff — Text
		{"diff_text", []string{td("cyclonedx-before.json"), td("cyclonedx-after.json")}},
		{"diff_no_differences", []string{td("cyclonedx-before.json"), td("cyclonedx-before.json")}},
		{"diff_integrity_drift_text", []string{td("cyclonedx-before.json"), td("cyclonedx-integrity-drift.json")}},

		// Two File Diff — JSON
		{"diff_json", []string{td("cyclonedx-before.json"), td("cyclonedx-after.json"), "--json"}},
		{"diff_integrity_drift_json", []string{td("cyclonedx-before.json"), td("cyclonedx-integrity-drift.json"), "--json"}},

		// Output Formats
		{"format_sarif", []string{td("cyclonedx-before.json"), td("cyclonedx-after.json"), "--format", "sarif"}},
		{"format_junit", []string{td("cyclonedx-before.json"), td("cyclonedx-after.json"), "--format", "junit"}},
		{"format_markdown", []string{td("cyclonedx-before.json"), td("cyclonedx-after.json"), "--format", "markdown"}},
		{"format_patch", []string{td("cyclonedx-before.json"), td("cyclonedx-after.json"), "--format", "patch"}},

		// Policy
		{"policy_pass", []string{td("cyclonedx-before.json"), td("cyclonedx-after.json"), "--policy", td("test-policy.json")}},
		{"policy_violation_text", []string{td("cyclonedx-before.json"), td("cyclonedx-after.json"), "--policy", td("strict-test-policy.json")}},
		{"policy_violation_json", []string{td("cyclonedx-before.json"), td("cyclonedx-after.json"), "--policy", td("strict-test-policy.json"), "--json"}},
		{"policy_all_rules", []string{td("cyclonedx-before.json"), td("cyclonedx-after.json"), "--policy", td("policy-all-rules.json")}},

		// Strict/Tolerant
		{"strict_invalid_file", []string{td("invalid.json"), "--strict"}},
		{"tolerant_invalid_file", []string{td("invalid.json"), "--tolerant"}},

		// Error Cases
		{"nonexistent_file_strict", []string{"nonexistent.json", "--strict"}},
		{"invalid_policy_file", []string{td("cyclonedx-before.json"), td("cyclonedx-after.json"), "--policy", td("malformed.json")}},

		// Cross-format
		{"cross_format_diff", []string{td("cyclonedx-before.json"), td("spdx-sample.json"), "--json"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, exitCode := runCLI(tt.args...)
			compareOrUpdateSnapshot(t, tt.name, stdout, stderr, exitCode)
		})
	}
}
