package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"

	"github.com/rezmoss/sbomlyze/internal/analysis"
	"github.com/rezmoss/sbomlyze/internal/cli"
	"github.com/rezmoss/sbomlyze/internal/convert"
	"github.com/rezmoss/sbomlyze/internal/output"
	"github.com/rezmoss/sbomlyze/internal/pager"
	"github.com/rezmoss/sbomlyze/internal/policy"
	"github.com/rezmoss/sbomlyze/internal/progress"
	"github.com/rezmoss/sbomlyze/internal/sbom"
	"github.com/rezmoss/sbomlyze/internal/tui"
	"github.com/rezmoss/sbomlyze/internal/version"
	"github.com/rezmoss/sbomlyze/internal/web"
)

func main() {
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

	if opts.WebServer {
		port := opts.WebPort
		if port == 0 {
			port = 8080
		}
		fmt.Printf("Starting sbomlyze web server at http://localhost:%d\n", port)
		if err := web.Serve(port); err != nil {
			fmt.Fprintf(os.Stderr, "err: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if opts.Convert {
		if len(opts.Files) == 0 {
			fmt.Fprintf(os.Stderr, "err: no input for convert\n")
			os.Exit(1)
		}
		if opts.TargetFormat == "" {
			fmt.Fprintf(os.Stderr, "err: --to flag required\n")
			os.Exit(1)
		}
		targetFmt, err := convert.ParseFormat(opts.TargetFormat)
		if err != nil {
			fmt.Fprintf(os.Stderr, "err: %v\n", err)
			os.Exit(1)
		}
		comps, info, err := sbom.ParseFileWithInfo(opts.Files[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "err: parse %s: %v\n", opts.Files[0], err)
			os.Exit(1)
		}
		comps = sbom.NormalizeComponents(comps)

		var w *os.File
		if opts.OutputFile != "" {
			w, err = os.Create(opts.OutputFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "err: create output: %v\n", err)
				os.Exit(1)
			}
			defer func() { _ = w.Close() }()
		} else {
			w = os.Stdout
		}
		if err := convert.Convert(w, comps, info, targetFmt); err != nil {
			fmt.Fprintf(os.Stderr, "err: convert: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if len(opts.Files) == 0 {
		fmt.Fprintf(os.Stderr, "err: no input files\n")
		os.Exit(1)
	}

	parseOpts := cli.ParseOptions{Strict: opts.Strict}

	if len(opts.Files) == 1 {
		spin := progress.New(opts.JSONOutput || opts.Interactive)

		spin.Start("Parsing...")
		comps, sbomInfo, err := parseFileWithOptionsAndInfo(opts.Files[0], &parseOpts)
		if err != nil {
			spin.Stop()
			fmt.Fprintf(os.Stderr, "err: parse %s: %v\n", opts.Files[0], err)
			os.Exit(1)
		}
		spin.Done(fmt.Sprintf("Parsed %d components", len(comps)))

		spin.Start("Analyzing...")
		comps = sbom.NormalizeComponents(comps)
		stats := analysis.ComputeStats(comps)
		findings := analysis.ComputeSingleFindings(stats, sbomInfo, comps)
		spin.Done("Done")

		if opts.Interactive {
			if err := tui.Run(comps, stats, sbomInfo); err != nil {
				fmt.Fprintf(os.Stderr, "err: interactive mode: %v\n", err)
				os.Exit(1)
			}
			return
		}

		p := pager.Start(opts.NoPager)
		defer p.Stop()

		if opts.JSONOutput {
			out := struct {
				Info     sbom.SBOMInfo      `json:"info"`
				Findings analysis.KeyFindings `json:"findings"`
				Stats    analysis.Stats     `json:"stats"`
				Warnings []cli.ParseWarning `json:"warnings,omitempty"`
			}{
				Info:     sbomInfo,
				Findings: findings,
				Stats:    stats,
				Warnings: parseOpts.Warnings,
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(out); err != nil {
				p.Stop()
				fmt.Fprintf(os.Stderr, "err: encode JSON: %v\n", err)
				os.Exit(1)
			}
		} else {
			output.PrintSingleScanContext(sbomInfo)
			output.PrintKeyFindings(findings)
			analysis.PrintStats(stats)
			cli.PrintWarnings(parseOpts.Warnings)
		}
		return
	}

	file1, file2 := opts.Files[0], opts.Files[1]
	spin := progress.New(opts.Format != "" && opts.Format != "text")

	spin.Start("Parsing first...")
	comps1, info1, err := parseFileWithOptionsAndInfo(file1, &parseOpts)
	if err != nil {
		spin.Stop()
		fmt.Fprintf(os.Stderr, "err: parse %s: %v\n", file1, err)
		os.Exit(1)
	}
	spin.Done(fmt.Sprintf("Parsed %d components", len(comps1)))

	spin.Start("Parsing second...")
	comps2, info2, err := parseFileWithOptionsAndInfo(file2, &parseOpts)
	if err != nil {
		spin.Stop()
		fmt.Fprintf(os.Stderr, "err: parse %s: %v\n", file2, err)
		os.Exit(1)
	}
	spin.Done(fmt.Sprintf("Parsed %d components", len(comps2)))

	spin.Start("Comparing...")
	comps1 = sbom.NormalizeComponents(comps1)
	comps2 = sbom.NormalizeComponents(comps2)

	overview := analysis.ComputeDiffOverview(file1, file2, comps1, comps2, info1, info2)
	result := analysis.DiffComponents(comps1, comps2)
	analysis.ComputePackageSamples(&result)
	findings := analysis.ComputeKeyFindings(result, overview)
	spin.Done("Done")

	var violations []policy.Violation
	if opts.PolicyFile != "" {
		policyData, err := os.ReadFile(opts.PolicyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "err: read policy: %v\n", err)
			os.Exit(1)
		}
		pol, err := policy.Load(policyData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "err: parse policy: %v\n", err)
			os.Exit(1)
		}
		violations = policy.Evaluate(pol, result)
	}

	sbomFile := ""
	if len(opts.Files) > 1 {
		sbomFile = opts.Files[1]
	}

	p := pager.Start(opts.NoPager)

	switch opts.Format {
	case "json":
		out := struct {
			Overview   analysis.DiffOverview `json:"overview"`
			Findings   analysis.KeyFindings  `json:"findings"`
			Diff       analysis.DiffResult   `json:"diff"`
			Violations []policy.Violation    `json:"violations,omitempty"`
			Warnings   []cli.ParseWarning    `json:"warnings,omitempty"`
		}{
			Overview:   overview,
			Findings:   findings,
			Diff:       result,
			Violations: violations,
			Warnings:   parseOpts.Warnings,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			p.Stop()
			fmt.Fprintf(os.Stderr, "err: encode JSON: %v\n", err)
			os.Exit(1)
		}

	case "sarif":
		sarif := output.GenerateSARIF(result, violations, sbomFile)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(sarif); err != nil {
			p.Stop()
			fmt.Fprintf(os.Stderr, "err: encode SARIF: %v\n", err)
			os.Exit(1)
		}

	case "junit":
		junit := output.GenerateJUnit(result, violations)
		out, err := xml.MarshalIndent(junit, "", "  ")
		if err != nil {
			p.Stop()
			fmt.Fprintf(os.Stderr, "err: encode JUnit: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(xml.Header + string(out))

	case "markdown", "md":
		fmt.Println(output.GenerateMarkdownWithOverview(result, violations, overview, findings))

	case "patch":
		patch := output.GenerateJSONPatch(result)
		out, err := json.MarshalIndent(patch, "", "  ")
		if err != nil {
			p.Stop()
			fmt.Fprintf(os.Stderr, "err: encode patch: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(out))

	default: // text
		output.PrintDiffOverview(overview)
		output.PrintScanContext(overview)
		output.PrintKeyFindings(findings)
		output.PrintPackageSamples(result.AddedByType, result.RemovedByType)
		output.PrintTextDiff(result)
		output.PrintViolations(violations)
		cli.PrintWarnings(parseOpts.Warnings)
	}

	p.Stop()

	hasDiff := len(result.Added) > 0 || len(result.Removed) > 0 || len(result.Changed) > 0
	hasPolicyErrors := policy.HasErrors(violations)
	if hasDiff || hasPolicyErrors {
		os.Exit(1)
	}
}

func parseFileWithOptionsAndInfo(path string, opts *cli.ParseOptions) ([]sbom.Component, sbom.SBOMInfo, error) {
	comps, info, err := sbom.ParseFileWithInfo(path)
	if err != nil {
		if opts.Strict {
			return nil, sbom.SBOMInfo{}, err
		}
		opts.AddWarning(path, err.Error(), "")
		return []sbom.Component{}, sbom.SBOMInfo{}, nil
	}
	return comps, info, nil
}
