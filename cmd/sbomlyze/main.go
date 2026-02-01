package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"

	"github.com/rezmoss/sbomlyze/internal/analysis"
	"github.com/rezmoss/sbomlyze/internal/cli"
	"github.com/rezmoss/sbomlyze/internal/output"
	"github.com/rezmoss/sbomlyze/internal/policy"
	"github.com/rezmoss/sbomlyze/internal/sbom"
	"github.com/rezmoss/sbomlyze/internal/tui"
	"github.com/rezmoss/sbomlyze/internal/version"
	"github.com/rezmoss/sbomlyze/internal/web"
)

func main() {
	// Handle --version and --help early
	for _, arg := range os.Args[1:] {
		if arg == "--version" || arg == "-v" {
			fmt.Println(version.Info())
			os.Exit(0)
		}
		if arg == "--help" || arg == "-h" {
			cli.PrintUsage()
			os.Exit(0)
		}
	}

	if len(os.Args) < 2 {
		cli.PrintUsage()
		os.Exit(1)
	}

	opts := cli.ParseArgs(os.Args)

	// Web server mode
	if opts.WebServer {
		port := opts.WebPort
		if port == 0 {
			port = 8080
		}
		fmt.Printf("Starting sbomlyze web server at http://localhost:%d\n", port)
		if err := web.Serve(port); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if len(opts.Files) == 0 {
		fmt.Fprintf(os.Stderr, "Error: no input files specified\n")
		os.Exit(1)
	}

	parseOpts := cli.ParseOptions{Strict: opts.Strict}

	// Single file mode - stats or interactive
	if len(opts.Files) == 1 {
		// For interactive mode, we need SBOM info as well
		var comps []sbom.Component
		var sbomInfo sbom.SBOMInfo
		var err error

		if opts.Interactive {
			comps, sbomInfo, err = parseFileWithOptionsAndInfo(opts.Files[0], &parseOpts)
		} else {
			comps, err = parseFileWithOptions(opts.Files[0], &parseOpts)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing %s: %v\n", opts.Files[0], err)
			os.Exit(1)
		}

		// Normalize components
		comps = sbom.NormalizeComponents(comps)

		stats := analysis.ComputeStats(comps)

		// Interactive mode
		if opts.Interactive {
			if err := tui.Run(comps, stats, sbomInfo); err != nil {
				fmt.Fprintf(os.Stderr, "Error running interactive mode: %v\n", err)
				os.Exit(1)
			}
			return
		}

		if opts.JSONOutput {
			output := struct {
				Stats    analysis.Stats     `json:"stats"`
				Warnings []cli.ParseWarning `json:"warnings,omitempty"`
			}{
				Stats:    stats,
				Warnings: parseOpts.Warnings,
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(output); err != nil {
				fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
				os.Exit(1)
			}
		} else {
			analysis.PrintStats(stats)
			cli.PrintWarnings(parseOpts.Warnings)
		}
		return
	}

	// Two file mode - diff
	file1, file2 := opts.Files[0], opts.Files[1]

	comps1, err := parseFileWithOptions(file1, &parseOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing %s: %v\n", file1, err)
		os.Exit(1)
	}

	comps2, err := parseFileWithOptions(file2, &parseOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing %s: %v\n", file2, err)
		os.Exit(1)
	}

	// Normalize components
	comps1 = sbom.NormalizeComponents(comps1)
	comps2 = sbom.NormalizeComponents(comps2)

	result := analysis.DiffComponents(comps1, comps2)

	// Policy evaluation
	var violations []policy.Violation
	if opts.PolicyFile != "" {
		policyData, err := os.ReadFile(opts.PolicyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading policy file: %v\n", err)
			os.Exit(1)
		}
		pol, err := policy.Load(policyData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing policy: %v\n", err)
			os.Exit(1)
		}
		violations = policy.Evaluate(pol, result)
	}

	// Determine output format
	sbomFile := ""
	if len(opts.Files) > 1 {
		sbomFile = opts.Files[1]
	}

	switch opts.Format {
	case "json":
		out := struct {
			Diff       analysis.DiffResult `json:"diff"`
			Violations []policy.Violation  `json:"violations,omitempty"`
			Warnings   []cli.ParseWarning  `json:"warnings,omitempty"`
		}{
			Diff:       result,
			Violations: violations,
			Warnings:   parseOpts.Warnings,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
			os.Exit(1)
		}

	case "sarif":
		sarif := output.GenerateSARIF(result, violations, sbomFile)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(sarif); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding SARIF: %v\n", err)
			os.Exit(1)
		}

	case "junit":
		junit := output.GenerateJUnit(result, violations)
		out, err := xml.MarshalIndent(junit, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JUnit: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(xml.Header + string(out))

	case "markdown", "md":
		fmt.Println(output.GenerateMarkdown(result, violations))

	case "patch":
		patch := output.GenerateJSONPatch(result)
		out, err := json.MarshalIndent(patch, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON Patch: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(out))

	default: // text
		output.PrintTextDiff(result)
		output.PrintViolations(violations)
		cli.PrintWarnings(parseOpts.Warnings)
	}

	// Exit with error if there are differences OR policy errors (not warnings)
	hasDiff := len(result.Added) > 0 || len(result.Removed) > 0 || len(result.Changed) > 0
	hasPolicyErrors := policy.HasErrors(violations)
	if hasDiff || hasPolicyErrors {
		os.Exit(1)
	}
}

func parseFileWithOptions(path string, opts *cli.ParseOptions) ([]sbom.Component, error) {
	comps, err := sbom.ParseFile(path)
	if err != nil {
		if opts.Strict {
			return nil, err
		}
		// In tolerant mode, add warning and return empty
		opts.AddWarning(path, err.Error(), "")
		return []sbom.Component{}, nil
	}
	return comps, nil
}

func parseFileWithOptionsAndInfo(path string, opts *cli.ParseOptions) ([]sbom.Component, sbom.SBOMInfo, error) {
	comps, info, err := sbom.ParseFileWithInfo(path)
	if err != nil {
		if opts.Strict {
			return nil, sbom.SBOMInfo{}, err
		}
		// In tolerant mode, add warning and return empty
		opts.AddWarning(path, err.Error(), "")
		return []sbom.Component{}, sbom.SBOMInfo{}, nil
	}
	return comps, info, nil
}
