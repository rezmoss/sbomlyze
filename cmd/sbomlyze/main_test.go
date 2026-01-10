package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var binaryPath string

func TestMain(m *testing.M) {
	// Build the binary before running tests
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	// Navigate to project root
	projectRoot := filepath.Join(dir, "..", "..")
	binaryPath = filepath.Join(projectRoot, "sbomlyze-test")

	// Build the binary
	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/sbomlyze")
	cmd.Dir = projectRoot
	if output, err := cmd.CombinedOutput(); err != nil {
		panic("Failed to build binary: " + string(output))
	}

	// Run tests
	code := m.Run()

	// Cleanup
	os.Remove(binaryPath)

	os.Exit(code)
}

func runCLI(args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(binaryPath, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	exitCode = 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	} else if err != nil {
		exitCode = 1
	}

	return outBuf.String(), errBuf.String(), exitCode
}

func testdataPath(filename string) string {
	dir, _ := os.Getwd()
	return filepath.Join(dir, "..", "..", "testdata", filename)
}

// ============================================
// Version and Help Tests
// ============================================

func TestVersionFlag(t *testing.T) {
	tests := []struct {
		name string
		flag string
	}{
		{"long flag", "--version"},
		{"short flag", "-v"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, _, exitCode := runCLI(tt.flag)

			if exitCode != 0 {
				t.Errorf("expected exit code 0, got %d", exitCode)
			}
			if !strings.Contains(stdout, "sbomlyze") {
				t.Errorf("expected version output to contain 'sbomlyze', got: %s", stdout)
			}
		})
	}
}

func TestHelpFlag(t *testing.T) {
	tests := []struct {
		name string
		flag string
	}{
		{"long flag", "--help"},
		{"short flag", "-h"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, stderr, exitCode := runCLI(tt.flag)

			if exitCode != 0 {
				t.Errorf("expected exit code 0, got %d", exitCode)
			}
			if !strings.Contains(stderr, "Usage:") {
				t.Errorf("expected help output to contain 'Usage:', got: %s", stderr)
			}
			if !strings.Contains(stderr, "--json") {
				t.Errorf("expected help to mention --json flag")
			}
			if !strings.Contains(stderr, "--policy") {
				t.Errorf("expected help to mention --policy flag")
			}
		})
	}
}

func TestNoArgsShowsHelp(t *testing.T) {
	_, stderr, exitCode := runCLI()

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for no args, got %d", exitCode)
	}
	if !strings.Contains(stderr, "Usage:") {
		t.Errorf("expected usage message in stderr")
	}
}

// ============================================
// Single File Mode (Stats) Tests
// ============================================

func TestStatsModeText(t *testing.T) {
	stdout, _, exitCode := runCLI(testdataPath("cyclonedx-before.json"))

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(stdout, "SBOM Statistics") {
		t.Errorf("expected stats output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "Total Components:") {
		t.Errorf("expected 'Total Components:' in output")
	}
}

func TestStatsModeJSON(t *testing.T) {
	stdout, _, exitCode := runCLI(testdataPath("cyclonedx-before.json"), "--json")

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	var result struct {
		Stats struct {
			TotalComponents int `json:"total_components"`
		} `json:"stats"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}
	if result.Stats.TotalComponents != 3 {
		t.Errorf("expected 3 components, got %d", result.Stats.TotalComponents)
	}
}

func TestStatsModeWithDifferentFormats(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		expected int
	}{
		{"CycloneDX", "cyclonedx-before.json", 3},
		{"SPDX", "spdx-sample.json", 2},
		{"Syft", "syft-sample.json", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, _, exitCode := runCLI(testdataPath(tt.file), "--json")

			if exitCode != 0 {
				t.Errorf("expected exit code 0, got %d", exitCode)
			}

			var result struct {
				Stats struct {
					TotalComponents int `json:"total_components"`
				} `json:"stats"`
			}
			if err := json.Unmarshal([]byte(stdout), &result); err != nil {
				t.Fatalf("failed to parse JSON: %v", err)
			}
			if result.Stats.TotalComponents != tt.expected {
				t.Errorf("expected %d components, got %d", tt.expected, result.Stats.TotalComponents)
			}
		})
	}
}

// ============================================
// Two File Mode (Diff) Tests
// ============================================

func TestDiffModeText(t *testing.T) {
	stdout, _, exitCode := runCLI(
		testdataPath("cyclonedx-before.json"),
		testdataPath("cyclonedx-after.json"),
	)

	// Exit code 1 because there are differences
	if exitCode != 1 {
		t.Errorf("expected exit code 1 (differences found), got %d", exitCode)
	}

	// Check for expected diff output
	if !strings.Contains(stdout, "Added") {
		t.Errorf("expected 'Added' in diff output")
	}
	if !strings.Contains(stdout, "Removed") {
		t.Errorf("expected 'Removed' in diff output")
	}
	if !strings.Contains(stdout, "Changed") {
		t.Errorf("expected 'Changed' in diff output")
	}
	if !strings.Contains(stdout, "new-package") {
		t.Errorf("expected 'new-package' to be shown as added")
	}
	if !strings.Contains(stdout, "old-package") {
		t.Errorf("expected 'old-package' to be shown as removed")
	}
}

func TestDiffModeJSON(t *testing.T) {
	stdout, _, exitCode := runCLI(
		testdataPath("cyclonedx-before.json"),
		testdataPath("cyclonedx-after.json"),
		"--json",
	)

	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}

	var result struct {
		Diff struct {
			Added   []interface{} `json:"added"`
			Removed []interface{} `json:"removed"`
			Changed []interface{} `json:"changed"`
		} `json:"diff"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if len(result.Diff.Added) != 1 {
		t.Errorf("expected 1 added, got %d", len(result.Diff.Added))
	}
	if len(result.Diff.Removed) != 1 {
		t.Errorf("expected 1 removed, got %d", len(result.Diff.Removed))
	}
	if len(result.Diff.Changed) != 1 {
		t.Errorf("expected 1 changed, got %d", len(result.Diff.Changed))
	}
}

func TestDiffNoDifferences(t *testing.T) {
	// Compare file with itself - no differences
	stdout, _, exitCode := runCLI(
		testdataPath("cyclonedx-before.json"),
		testdataPath("cyclonedx-before.json"),
	)

	if exitCode != 0 {
		t.Errorf("expected exit code 0 (no differences), got %d", exitCode)
	}
	if !strings.Contains(stdout, "No differences found") {
		t.Errorf("expected 'No differences found' message")
	}
}

// ============================================
// Output Format Tests
// ============================================

func TestFormatSARIF(t *testing.T) {
	stdout, _, _ := runCLI(
		testdataPath("cyclonedx-before.json"),
		testdataPath("cyclonedx-after.json"),
		"--format", "sarif",
	)

	var sarif struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name string `json:"name"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(stdout), &sarif); err != nil {
		t.Fatalf("failed to parse SARIF: %v", err)
	}
	if sarif.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", sarif.Version)
	}
	if len(sarif.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(sarif.Runs))
	}
	if sarif.Runs[0].Tool.Driver.Name != "sbomlyze" {
		t.Errorf("expected tool name 'sbomlyze', got %s", sarif.Runs[0].Tool.Driver.Name)
	}
}

func TestFormatJUnit(t *testing.T) {
	stdout, _, _ := runCLI(
		testdataPath("cyclonedx-before.json"),
		testdataPath("cyclonedx-after.json"),
		"--format", "junit",
	)

	// Check XML header
	if !strings.Contains(stdout, "<?xml") {
		t.Errorf("expected XML header in JUnit output")
	}

	// Parse XML
	var junit struct {
		XMLName xml.Name `xml:"testsuites"`
		Name    string   `xml:"name,attr"`
	}
	if err := xml.Unmarshal([]byte(stdout), &junit); err != nil {
		t.Fatalf("failed to parse JUnit XML: %v", err)
	}
	if junit.Name != "sbomlyze" {
		t.Errorf("expected testsuites name 'sbomlyze', got %s", junit.Name)
	}
}

func TestFormatMarkdown(t *testing.T) {
	stdout, _, _ := runCLI(
		testdataPath("cyclonedx-before.json"),
		testdataPath("cyclonedx-after.json"),
		"--format", "markdown",
	)

	if !strings.Contains(stdout, "## 📦 SBOM Diff Report") {
		t.Errorf("expected markdown header")
	}
	if !strings.Contains(stdout, "### Summary") {
		t.Errorf("expected Summary section")
	}
	if !strings.Contains(stdout, "<details>") {
		t.Errorf("expected collapsible details sections")
	}
}

func TestFormatPatch(t *testing.T) {
	stdout, _, _ := runCLI(
		testdataPath("cyclonedx-before.json"),
		testdataPath("cyclonedx-after.json"),
		"--format", "patch",
	)

	var patch []struct {
		Op   string `json:"op"`
		Path string `json:"path"`
	}
	if err := json.Unmarshal([]byte(stdout), &patch); err != nil {
		t.Fatalf("failed to parse JSON Patch: %v", err)
	}
	if len(patch) == 0 {
		t.Errorf("expected non-empty patch operations")
	}

	// Check for expected operations
	hasAdd := false
	hasRemove := false
	for _, op := range patch {
		if op.Op == "add" {
			hasAdd = true
		}
		if op.Op == "remove" {
			hasRemove = true
		}
	}
	if !hasAdd {
		t.Errorf("expected 'add' operation in patch")
	}
	if !hasRemove {
		t.Errorf("expected 'remove' operation in patch")
	}
}

// ============================================
// Policy Tests
// ============================================

func TestPolicyPass(t *testing.T) {
	_, _, exitCode := runCLI(
		testdataPath("cyclonedx-before.json"),
		testdataPath("cyclonedx-after.json"),
		"--policy", testdataPath("test-policy.json"),
	)

	// Policy allows up to 5 added/removed, we have 1 each, so should pass
	// But exit code 1 because there are differences
	if exitCode != 1 {
		t.Errorf("expected exit code 1 (differences exist), got %d", exitCode)
	}
}

func TestPolicyViolation(t *testing.T) {
	stdout, _, exitCode := runCLI(
		testdataPath("cyclonedx-before.json"),
		testdataPath("cyclonedx-after.json"),
		"--policy", testdataPath("strict-test-policy.json"),
	)

	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	// The strict policy denies Apache-2.0 which new-package has
	if !strings.Contains(stdout, "Policy Errors") {
		t.Errorf("expected 'Policy Errors' in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "deny_licenses") {
		t.Errorf("expected 'deny_licenses' violation in output")
	}
}

func TestPolicyWithJSON(t *testing.T) {
	stdout, _, exitCode := runCLI(
		testdataPath("cyclonedx-before.json"),
		testdataPath("cyclonedx-after.json"),
		"--policy", testdataPath("strict-test-policy.json"),
		"--json",
	)

	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}

	var result struct {
		Violations []struct {
			Rule     string `json:"rule"`
			Severity string `json:"severity"`
			Message  string `json:"message"`
		} `json:"violations"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("failed to parse JSON: %v\nOutput was: %s", err, stdout)
	}
	if len(result.Violations) == 0 {
		t.Errorf("expected policy violations in output, got: %s", stdout)
	}
	if result.Violations[0].Rule != "deny_licenses" {
		t.Errorf("expected deny_licenses rule, got %s", result.Violations[0].Rule)
	}
}

// ============================================
// Strict/Tolerant Mode Tests
// ============================================

func TestStrictModeWithInvalidFile(t *testing.T) {
	_, stderr, exitCode := runCLI(
		testdataPath("invalid.json"),
		"--strict",
	)

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for invalid file in strict mode, got %d", exitCode)
	}
	if !strings.Contains(stderr, "Error") {
		t.Errorf("expected error message in stderr")
	}
}

func TestTolerantModeWithInvalidFile(t *testing.T) {
	stdout, _, exitCode := runCLI(
		testdataPath("invalid.json"),
		"--tolerant",
	)

	// In tolerant mode, it should continue and show stats (with 0 components)
	if exitCode != 0 {
		t.Errorf("expected exit code 0 in tolerant mode, got %d", exitCode)
	}
	if !strings.Contains(stdout, "Total Components: 0") {
		t.Errorf("expected 0 components for invalid file in tolerant mode")
	}
}

func TestTolerantModeShowsWarnings(t *testing.T) {
	stdout, _, _ := runCLI(
		testdataPath("invalid.json"),
		"--tolerant",
	)

	if !strings.Contains(stdout, "Parse Warnings") {
		t.Errorf("expected parse warnings in tolerant mode output")
	}
}

// ============================================
// Drift Detection Tests
// ============================================

func TestIntegrityDriftDetection(t *testing.T) {
	stdout, _, _ := runCLI(
		testdataPath("cyclonedx-before.json"),
		testdataPath("cyclonedx-integrity-drift.json"),
		"--json",
	)

	var result struct {
		Diff struct {
			DriftSummary struct {
				IntegrityDrift int `json:"integrity_drift"`
			} `json:"drift_summary"`
		} `json:"diff"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if result.Diff.DriftSummary.IntegrityDrift != 1 {
		t.Errorf("expected 1 integrity drift, got %d", result.Diff.DriftSummary.IntegrityDrift)
	}
}

func TestVersionDriftDetection(t *testing.T) {
	stdout, _, _ := runCLI(
		testdataPath("cyclonedx-before.json"),
		testdataPath("cyclonedx-after.json"),
		"--json",
	)

	var result struct {
		Diff struct {
			Changed []struct {
				Drift struct {
					Type string `json:"type"`
				} `json:"drift"`
			} `json:"changed"`
		} `json:"diff"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if len(result.Diff.Changed) == 0 {
		t.Fatalf("expected changed components")
	}
	if result.Diff.Changed[0].Drift.Type != "version" {
		t.Errorf("expected version drift type, got %s", result.Diff.Changed[0].Drift.Type)
	}
}

// ============================================
// Error Handling Tests
// ============================================

func TestNonExistentFile(t *testing.T) {
	// Use --strict to ensure nonexistent file causes failure
	// In default tolerant mode, it returns 0 with warnings
	_, stderr, exitCode := runCLI("nonexistent.json", "--strict")

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for nonexistent file, got %d", exitCode)
	}
	if !strings.Contains(stderr, "Error") && !strings.Contains(stderr, "error") {
		t.Errorf("expected error message for nonexistent file, got stderr: %s", stderr)
	}
}

func TestInvalidPolicyFile(t *testing.T) {
	// Use malformed.json which has invalid JSON syntax
	// invalid.json is valid JSON (just not a policy), so it would parse as empty policy
	_, stderr, exitCode := runCLI(
		testdataPath("cyclonedx-before.json"),
		testdataPath("cyclonedx-after.json"),
		"--policy", testdataPath("malformed.json"),
	)

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for invalid policy, got %d", exitCode)
	}
	if !strings.Contains(stderr, "Error") && !strings.Contains(stderr, "error") {
		t.Errorf("expected error message for invalid policy, got stderr: %s", stderr)
	}
}

func TestNonExistentPolicyFile(t *testing.T) {
	_, stderr, exitCode := runCLI(
		testdataPath("cyclonedx-before.json"),
		testdataPath("cyclonedx-after.json"),
		"--policy", "nonexistent-policy.json",
	)

	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if !strings.Contains(stderr, "Error") {
		t.Errorf("expected error message for nonexistent policy file")
	}
}

// ============================================
// Format Flag Shortcuts
// ============================================

func TestFormatFlagShortcut(t *testing.T) {
	// Test -f shortcut for --format
	stdout, _, _ := runCLI(
		testdataPath("cyclonedx-before.json"),
		testdataPath("cyclonedx-after.json"),
		"-f", "markdown",
	)

	if !strings.Contains(stdout, "## 📦 SBOM Diff Report") {
		t.Errorf("expected markdown output with -f shortcut")
	}
}

func TestMarkdownFormatAlias(t *testing.T) {
	// Test "md" alias for "markdown"
	stdout, _, _ := runCLI(
		testdataPath("cyclonedx-before.json"),
		testdataPath("cyclonedx-after.json"),
		"--format", "md",
	)

	if !strings.Contains(stdout, "## 📦 SBOM Diff Report") {
		t.Errorf("expected markdown output with 'md' alias")
	}
}
