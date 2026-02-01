package cli

import (
	"fmt"
	"os"
)

// PrintUsage displays the help message
func PrintUsage() {
	fmt.Fprintf(os.Stderr, "sbomlyze - A fast, reliable SBOM diff and analysis tool\n\n")
	fmt.Fprintf(os.Stderr, "Usage: sbomlyze <sbom1> [sbom2] [options]\n\n")
	fmt.Fprintf(os.Stderr, "Modes:\n")
	fmt.Fprintf(os.Stderr, "  Single file:  sbomlyze <sbom> [--json]        - Show statistics\n")
	fmt.Fprintf(os.Stderr, "  Interactive:  sbomlyze <sbom> -i              - Interactive explorer\n")
	fmt.Fprintf(os.Stderr, "  Web server:   sbomlyze -web [--port 8080]     - Web UI explorer\n")
	fmt.Fprintf(os.Stderr, "  Two files:    sbomlyze <sbom1> <sbom2> [...]  - Show diff\n\n")
	fmt.Fprintf(os.Stderr, "Options:\n")
	fmt.Fprintf(os.Stderr, "  -i, --interactive   Interactive TUI explorer\n")
	fmt.Fprintf(os.Stderr, "  -web, --web         Start web UI server\n")
	fmt.Fprintf(os.Stderr, "  --port <port>       Web server port (default 8080)\n")
	fmt.Fprintf(os.Stderr, "  --json              Output in JSON format (shortcut for --format json)\n")
	fmt.Fprintf(os.Stderr, "  --format <format>   Output format: text, json, sarif, junit, markdown, patch\n")
	fmt.Fprintf(os.Stderr, "  --policy <file>     Policy file for CI checks\n")
	fmt.Fprintf(os.Stderr, "  --strict            Fail on parse warnings\n")
	fmt.Fprintf(os.Stderr, "  --tolerant          Continue on parse warnings (default)\n")
	fmt.Fprintf(os.Stderr, "  --version, -v       Show version information\n")
	fmt.Fprintf(os.Stderr, "  --help, -h          Show this help message\n\n")
	fmt.Fprintf(os.Stderr, "Output Formats:\n")
	fmt.Fprintf(os.Stderr, "  text      Human-readable text (default)\n")
	fmt.Fprintf(os.Stderr, "  json      JSON for programmatic consumption\n")
	fmt.Fprintf(os.Stderr, "  sarif     SARIF for GitHub Code Scanning\n")
	fmt.Fprintf(os.Stderr, "  junit     JUnit XML for CI test results\n")
	fmt.Fprintf(os.Stderr, "  markdown  Markdown for PR comments\n")
	fmt.Fprintf(os.Stderr, "  patch     JSON Patch (RFC 6902) for automation\n\n")
	fmt.Fprintf(os.Stderr, "Interactive Mode Keys:\n")
	fmt.Fprintf(os.Stderr, "  ↑/↓, j/k    Navigate components\n")
	fmt.Fprintf(os.Stderr, "  Enter       View component details\n")
	fmt.Fprintf(os.Stderr, "  j           View raw SBOM JSON (all original fields)\n")
	fmt.Fprintf(os.Stderr, "  d           Back to detail view (in JSON view)\n")
	fmt.Fprintf(os.Stderr, "  /           Search by name, PURL, license\n")
	fmt.Fprintf(os.Stderr, "  t           Filter by package type\n")
	fmt.Fprintf(os.Stderr, "  c           Clear all filters\n")
	fmt.Fprintf(os.Stderr, "  Esc         Go back\n")
	fmt.Fprintf(os.Stderr, "  q           Quit\n\n")
	fmt.Fprintf(os.Stderr, "Examples:\n")
	fmt.Fprintf(os.Stderr, "  sbomlyze image.json                        # Show SBOM statistics\n")
	fmt.Fprintf(os.Stderr, "  sbomlyze image.json -i                     # Interactive explorer\n")
	fmt.Fprintf(os.Stderr, "  sbomlyze -web                              # Start web UI at localhost:8080\n")
	fmt.Fprintf(os.Stderr, "  sbomlyze -web --port 3000                  # Start web UI at localhost:3000\n")
	fmt.Fprintf(os.Stderr, "  sbomlyze before.json after.json            # Compare two SBOMs\n")
	fmt.Fprintf(os.Stderr, "  sbomlyze a.json b.json --policy p.json     # Apply policy checks\n")
	fmt.Fprintf(os.Stderr, "  sbomlyze a.json b.json --format sarif      # SARIF for GitHub\n")
	fmt.Fprintf(os.Stderr, "  sbomlyze a.json b.json --format markdown   # Markdown for PR\n\n")
	fmt.Fprintf(os.Stderr, "Documentation: https://github.com/rezmoss/sbomlyze\n")
}

// PrintWarnings displays parse warnings
func PrintWarnings(warnings []ParseWarning) {
	if len(warnings) > 0 {
		fmt.Printf("\n⚠️  Parse Warnings (%d):\n", len(warnings))
		for _, w := range warnings {
			if w.Field != "" {
				fmt.Printf("  [%s] %s (field: %s)\n", w.File, w.Message, w.Field)
			} else {
				fmt.Printf("  [%s] %s\n", w.File, w.Message)
			}
		}
		fmt.Println()
	}
}
