package output

import (
	"encoding/xml"
	"fmt"

	"github.com/rezmoss/sbomlyze/internal/analysis"
	"github.com/rezmoss/sbomlyze/internal/policy"
)

// JUnit types for CI Test UI

type JUnitTestSuites struct {
	XMLName   xml.Name         `xml:"testsuites"`
	Name      string           `xml:"name,attr"`
	Tests     int              `xml:"tests,attr"`
	Failures  int              `xml:"failures,attr"`
	Errors    int              `xml:"errors,attr"`
	Time      float64          `xml:"time,attr"`
	TestSuite []JUnitTestSuite `xml:"testsuite"`
}

type JUnitTestSuite struct {
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Errors    int             `xml:"errors,attr"`
	Time      float64         `xml:"time,attr"`
	TestCases []JUnitTestCase `xml:"testcase"`
}

type JUnitTestCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Time      float64       `xml:"time,attr"`
	Failure   *JUnitFailure `xml:"failure,omitempty"`
	Skipped   *JUnitSkipped `xml:"skipped,omitempty"`
}

type JUnitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

type JUnitSkipped struct {
	Message string `xml:"message,attr,omitempty"`
}

// GenerateJUnit creates a JUnit test report from diff results and policy violations
func GenerateJUnit(result analysis.DiffResult, violations []policy.Violation) JUnitTestSuites {
	var testCases []JUnitTestCase
	failures := 0
	errors := 0

	// Test: No integrity drift
	integrityDrift := 0
	if result.DriftSummary != nil {
		integrityDrift = result.DriftSummary.IntegrityDrift
	}
	tc := JUnitTestCase{
		Name:      "No Integrity Drift",
		ClassName: "sbomlyze.security",
		Time:      0.001,
	}
	if integrityDrift > 0 {
		tc.Failure = &JUnitFailure{
			Message: fmt.Sprintf("%d components have hash changes without version changes", integrityDrift),
			Type:    "IntegrityDrift",
		}
		failures++
	}
	testCases = append(testCases, tc)

	// Test: No deep dependencies
	deepDeps := 0
	if result.Dependencies != nil && result.Dependencies.DepthSummary != nil {
		deepDeps = result.Dependencies.DepthSummary.Depth3Plus
	}
	tc = JUnitTestCase{
		Name:      "No Deep Transitive Dependencies",
		ClassName: "sbomlyze.dependencies",
		Time:      0.001,
	}
	if deepDeps > 0 {
		tc.Failure = &JUnitFailure{
			Message: fmt.Sprintf("%d new dependencies at depth 3+", deepDeps),
			Type:    "DeepDependency",
		}
		failures++
	}
	testCases = append(testCases, tc)

	// Test: Policy compliance
	for _, v := range violations {
		tc := JUnitTestCase{
			Name:      fmt.Sprintf("Policy: %s", v.Rule),
			ClassName: "sbomlyze.policy",
			Time:      0.001,
		}
		if v.Severity == policy.SeverityError {
			tc.Failure = &JUnitFailure{
				Message: v.Message,
				Type:    "PolicyViolation",
			}
			failures++
		}
		testCases = append(testCases, tc)
	}

	// Test: Component changes summary
	tc = JUnitTestCase{
		Name:      "SBOM Diff Summary",
		ClassName: "sbomlyze.diff",
		Time:      0.001,
	}
	// This is informational, not a failure
	testCases = append(testCases, tc)

	return JUnitTestSuites{
		Name:     "sbomlyze",
		Tests:    len(testCases),
		Failures: failures,
		Errors:   errors,
		Time:     0.01,
		TestSuite: []JUnitTestSuite{{
			Name:      "SBOM Analysis",
			Tests:     len(testCases),
			Failures:  failures,
			Errors:    errors,
			Time:      0.01,
			TestCases: testCases,
		}},
	}
}
