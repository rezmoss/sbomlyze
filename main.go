package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx"
)

type Component struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	PURL         string            `json:"purl,omitempty"`
	Licenses     []string          `json:"licenses,omitempty"`
	CPEs         []string          `json:"cpes,omitempty"`
	Hashes       map[string]string `json:"hashes,omitempty"`
	Dependencies []string          `json:"dependencies,omitempty"`
	BOMRef       string            `json:"bom-ref,omitempty"`
	SPDXID       string            `json:"spdxid,omitempty"`
	Namespace    string            `json:"namespace,omitempty"`
	Supplier     string            `json:"supplier,omitempty"`
}

type DiffResult struct {
	Added        []Component        `json:"added,omitempty"`
	Removed      []Component        `json:"removed,omitempty"`
	Changed      []ChangedComponent `json:"changed,omitempty"`
	Duplicates   *DuplicateReport   `json:"duplicates,omitempty"`
	Dependencies *DependencyDiff    `json:"dependencies,omitempty"`
	DriftSummary *DriftSummary      `json:"drift_summary,omitempty"`
}

type ChangedComponent struct {
	ID      string     `json:"id"`
	Name    string     `json:"name"`
	Before  Component  `json:"before"`
	After   Component  `json:"after"`
	Changes []string   `json:"changes"`
	Drift   *DriftInfo `json:"drift,omitempty"`
}

func main() {
	// Handle --version and --help early
	for _, arg := range os.Args[1:] {
		if arg == "--version" || arg == "-v" {
			fmt.Println(VersionInfo())
			os.Exit(0)
		}
		if arg == "--help" || arg == "-h" {
			printUsage()
			os.Exit(0)
		}
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	opts := parseArgs(os.Args)

	if len(opts.Files) == 0 {
		fmt.Fprintf(os.Stderr, "Error: no input files specified\n")
		os.Exit(1)
	}

	parseOpts := ParseOptions{Strict: opts.Strict}

	// Single file mode - stats
	if len(opts.Files) == 1 {
		comps, err := parseFileWithOptions(opts.Files[0], &parseOpts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing %s: %v\n", opts.Files[0], err)
			os.Exit(1)
		}

		// Normalize components
		comps = normalizeComponents(comps)

		stats := computeStats(comps)

		if opts.JSONOutput {
			output := struct {
				Stats    SBOMStats      `json:"stats"`
				Warnings []ParseWarning `json:"warnings,omitempty"`
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
			printStats(stats)
			printWarnings(parseOpts.Warnings)
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
	comps1 = normalizeComponents(comps1)
	comps2 = normalizeComponents(comps2)

	result := diffComponents(comps1, comps2)

	// Policy evaluation
	var violations []PolicyViolation
	if opts.PolicyFile != "" {
		policyData, err := os.ReadFile(opts.PolicyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading policy file: %v\n", err)
			os.Exit(1)
		}
		policy, err := loadPolicyFromJSON(policyData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing policy: %v\n", err)
			os.Exit(1)
		}
		violations = evaluatePolicy(policy, result)
	}

	if opts.JSONOutput {
		output := struct {
			Diff       DiffResult        `json:"diff"`
			Violations []PolicyViolation `json:"violations,omitempty"`
			Warnings   []ParseWarning    `json:"warnings,omitempty"`
		}{
			Diff:       result,
			Violations: violations,
			Warnings:   parseOpts.Warnings,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(output); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
			os.Exit(1)
		}
	} else {
		printTextDiff(result)
		if len(violations) > 0 {
			// Separate errors and warnings
			var errors, warnings []PolicyViolation
			for _, v := range violations {
				if v.Severity == SeverityWarning {
					warnings = append(warnings, v)
				} else {
					errors = append(errors, v)
				}
			}

			if len(errors) > 0 {
				fmt.Printf("\n❌ Policy Errors (%d):\n", len(errors))
				for _, v := range errors {
					fmt.Printf("  [%s] %s\n", v.Rule, v.Message)
				}
			}
			if len(warnings) > 0 {
				fmt.Printf("\n⚠️  Policy Warnings (%d):\n", len(warnings))
				for _, v := range warnings {
					fmt.Printf("  [%s] %s\n", v.Rule, v.Message)
				}
			}
			fmt.Println()
		}
		printWarnings(parseOpts.Warnings)
	}

	// Exit with error if there are differences OR policy errors (not warnings)
	hasDiff := len(result.Added) > 0 || len(result.Removed) > 0 || len(result.Changed) > 0
	hasPolicyErrors := HasErrors(violations)
	if hasDiff || hasPolicyErrors {
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "sbomlyze - A fast, reliable SBOM diff and analysis tool\n\n")
	fmt.Fprintf(os.Stderr, "Usage: sbomlyze <sbom1> [sbom2] [options]\n\n")
	fmt.Fprintf(os.Stderr, "Modes:\n")
	fmt.Fprintf(os.Stderr, "  Single file:  sbomlyze <sbom> [--json]        - Show statistics\n")
	fmt.Fprintf(os.Stderr, "  Two files:    sbomlyze <sbom1> <sbom2> [...]  - Show diff\n\n")
	fmt.Fprintf(os.Stderr, "Options:\n")
	fmt.Fprintf(os.Stderr, "  --json           Output in JSON format\n")
	fmt.Fprintf(os.Stderr, "  --policy <file>  Policy file for CI checks\n")
	fmt.Fprintf(os.Stderr, "  --strict         Fail on parse warnings\n")
	fmt.Fprintf(os.Stderr, "  --tolerant       Continue on parse warnings (default)\n")
	fmt.Fprintf(os.Stderr, "  --version, -v    Show version information\n")
	fmt.Fprintf(os.Stderr, "  --help, -h       Show this help message\n\n")
	fmt.Fprintf(os.Stderr, "Examples:\n")
	fmt.Fprintf(os.Stderr, "  sbomlyze image.json                    # Show SBOM statistics\n")
	fmt.Fprintf(os.Stderr, "  sbomlyze before.json after.json        # Compare two SBOMs\n")
	fmt.Fprintf(os.Stderr, "  sbomlyze a.json b.json --policy p.json # Apply policy checks\n")
	fmt.Fprintf(os.Stderr, "  sbomlyze a.json b.json --json          # Output as JSON\n\n")
	fmt.Fprintf(os.Stderr, "Documentation: https://github.com/rezmoss/sbomlyze\n")
}

func printWarnings(warnings []ParseWarning) {
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

func parseFileWithOptions(path string, opts *ParseOptions) ([]Component, error) {
	comps, err := parseFile(path)
	if err != nil {
		if opts.Strict {
			return nil, err
		}
		// In tolerant mode, add warning and return empty
		opts.AddWarning(path, err.Error(), "")
		return []Component{}, nil
	}
	return comps, nil
}

func normalizePURL(purl string) string {
	if purl == "" {
		return ""
	}
	if idx := strings.Index(purl, "#"); idx != -1 {
		purl = purl[:idx]
	}
	if idx := strings.Index(purl, "?"); idx != -1 {
		purl = purl[:idx]
	}
	if idx := strings.LastIndex(purl, "@"); idx != -1 {
		purl = purl[:idx]
	}
	return purl
}

func extractPURLVersion(purl string) string {
	if purl == "" {
		return ""
	}
	if idx := strings.Index(purl, "#"); idx != -1 {
		purl = purl[:idx]
	}
	if idx := strings.Index(purl, "?"); idx != -1 {
		purl = purl[:idx]
	}
	if idx := strings.LastIndex(purl, "@"); idx != -1 {
		ver := purl[idx+1:]
		if decoded, err := url.QueryUnescape(ver); err == nil {
			return decoded
		}
		return ver
	}
	return ""
}

func parseFile(path string) ([]Component, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if isCycloneDX(data) {
		return parseCycloneDX(data)
	}
	if isSPDX(data) {
		return parseSPDX(path)
	}
	if isSyft(data) {
		return parseSyft(data)
	}
	return nil, fmt.Errorf("unknown SBOM format")
}

func isSyft(data []byte) bool {
	return strings.Contains(string(data), "\"artifacts\"")
}

func isCycloneDX(data []byte) bool {
	return strings.Contains(string(data), "\"bomFormat\"") ||
		(strings.Contains(string(data), "\"$schema\"") && strings.Contains(string(data), "cyclonedx"))
}

func isSPDX(data []byte) bool {
	return strings.Contains(string(data), "\"spdxVersion\"") || strings.Contains(string(data), "\"SPDXID\"")
}

func parseSyft(data []byte) ([]Component, error) {
	var doc struct {
		Artifacts []struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			PURL     string `json:"purl"`
			Licenses []struct {
				Value string `json:"value"`
			} `json:"licenses"`
			CPEs []struct {
				CPE string `json:"cpe"`
			} `json:"cpes"`
			Metadata struct {
				PullDependencies []string `json:"pullDependencies"`
			} `json:"metadata"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	var comps []Component
	for _, a := range doc.Artifacts {
		comp := Component{
			Name:         a.Name,
			Version:      a.Version,
			PURL:         a.PURL,
			Hashes:       make(map[string]string),
			Dependencies: a.Metadata.PullDependencies,
		}
		for _, lic := range a.Licenses {
			if lic.Value != "" {
				comp.Licenses = append(comp.Licenses, lic.Value)
			}
		}
		for _, cpe := range a.CPEs {
			if cpe.CPE != "" {
				comp.CPEs = append(comp.CPEs, cpe.CPE)
			}
		}
		// Compute ID using identity matcher
		comp.ID = computeComponentID(comp)
		comps = append(comps, comp)
	}
	return comps, nil
}

func parseCycloneDX(data []byte) ([]Component, error) {
	var bom cdx.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, err
	}

	var comps []Component
	if bom.Components == nil {
		return comps, nil
	}

	for _, c := range *bom.Components {
		comp := Component{
			Name:      c.Name,
			Version:   c.Version,
			Hashes:    make(map[string]string),
			BOMRef:    c.BOMRef,
			Namespace: c.Group,
		}
		if c.PackageURL != "" {
			comp.PURL = c.PackageURL
		}
		if c.CPE != "" {
			comp.CPEs = append(comp.CPEs, c.CPE)
		}
		if c.Licenses != nil {
			for _, lic := range *c.Licenses {
				if lic.License != nil && lic.License.ID != "" {
					comp.Licenses = append(comp.Licenses, lic.License.ID)
				}
			}
		}
		if c.Hashes != nil {
			for _, h := range *c.Hashes {
				comp.Hashes[string(h.Algorithm)] = h.Value
			}
		}
		// Extract supplier info
		if c.Supplier != nil && c.Supplier.Name != "" {
			comp.Supplier = c.Supplier.Name
		}
		// Compute ID using identity matcher
		comp.ID = computeComponentID(comp)
		comps = append(comps, comp)
	}
	return comps, nil
}

func parseSPDX(path string) ([]Component, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	doc, err := spdxjson.Read(f)
	if err != nil {
		return nil, err
	}

	var comps []Component
	for _, pkg := range doc.Packages {
		comp := Component{
			Name:    pkg.PackageName,
			Version: pkg.PackageVersion,
			Hashes:  make(map[string]string),
			SPDXID:  string(pkg.PackageSPDXIdentifier),
		}
		for _, ref := range pkg.PackageExternalReferences {
			if ref.RefType == spdx.PackageManagerPURL || ref.RefType == "purl" {
				comp.PURL = ref.Locator
			}
			// Extract CPEs from external references
			if ref.RefType == "cpe22Type" || ref.RefType == "cpe23Type" {
				comp.CPEs = append(comp.CPEs, ref.Locator)
			}
		}
		if pkg.PackageLicenseConcluded != "" {
			comp.Licenses = append(comp.Licenses, pkg.PackageLicenseConcluded)
		}
		for _, cs := range pkg.PackageChecksums {
			comp.Hashes[string(cs.Algorithm)] = cs.Value
		}
		// Compute ID using identity matcher
		comp.ID = computeComponentID(comp)
		comps = append(comps, comp)
	}
	return comps, nil
}

func diffComponents(before, after []Component) DiffResult {
	beforeDups := detectDuplicates(before)
	afterDups := detectDuplicates(after)

	beforeMap := make(map[string]Component)
	afterMap := make(map[string]Component)

	for _, c := range before {
		if _, exists := beforeMap[c.ID]; !exists {
			beforeMap[c.ID] = c
		}
	}
	for _, c := range after {
		if _, exists := afterMap[c.ID]; !exists {
			afterMap[c.ID] = c
		}
	}

	var result DiffResult

	for id, c := range afterMap {
		if _, exists := beforeMap[id]; !exists {
			result.Added = append(result.Added, c)
		}
	}

	for id, c := range beforeMap {
		if _, exists := afterMap[id]; !exists {
			result.Removed = append(result.Removed, c)
		}
	}

	for id, b := range beforeMap {
		if a, exists := afterMap[id]; exists {
			changes := compareComponents(b, a)
			if len(changes) > 0 {
				drift := classifyDrift(b, a)
				result.Changed = append(result.Changed, ChangedComponent{
					ID:      id,
					Name:    b.Name,
					Before:  b,
					After:   a,
					Changes: changes,
					Drift:   &drift,
				})
			}
		}
	}

	sort.Slice(result.Added, func(i, j int) bool { return result.Added[i].ID < result.Added[j].ID })
	sort.Slice(result.Removed, func(i, j int) bool { return result.Removed[i].ID < result.Removed[j].ID })
	sort.Slice(result.Changed, func(i, j int) bool { return result.Changed[i].ID < result.Changed[j].ID })

	// Compute drift summary
	if len(result.Changed) > 0 {
		summary := summarizeDrift(result.Changed)
		if summary.VersionDrift > 0 || summary.IntegrityDrift > 0 || summary.MetadataDrift > 0 {
			result.DriftSummary = &summary
		}
	}

	if len(beforeDups) > 0 || len(afterDups) > 0 {
		versionDiff := diffDuplicateVersions(beforeDups, afterDups)
		result.Duplicates = &DuplicateReport{
			Before: beforeDups,
			After:  afterDups,
		}
		if !versionDiff.IsEmpty() {
			result.Duplicates.VersionDiff = &versionDiff
		}
	}

	// Detect collisions in both SBOMs
	beforeCollisions := detectCollisions(before)
	afterCollisions := detectCollisions(after)
	if len(beforeCollisions) > 0 || len(afterCollisions) > 0 {
		if result.Duplicates == nil {
			result.Duplicates = &DuplicateReport{}
		}
		// Combine and deduplicate collisions
		allCollisions := append(beforeCollisions, afterCollisions...)
		seen := make(map[string]bool)
		for _, c := range allCollisions {
			key := c.ID + ":" + c.Reason
			if !seen[key] {
				result.Duplicates.Collisions = append(result.Duplicates.Collisions, c)
				seen[key] = true
			}
		}
	}

	// Dependency graph diff
	beforeGraph := buildDependencyGraph(before)
	afterGraph := buildDependencyGraph(after)
	depDiff := diffDependencyGraphs(beforeGraph, afterGraph)
	if !depDiff.IsEmpty() {
		result.Dependencies = &depDiff
	}

	return result
}

func compareComponents(b, a Component) []string {
	var changes []string
	if b.Version != a.Version {
		changes = append(changes, fmt.Sprintf("version: %s -> %s", b.Version, a.Version))
	}
	if !equalSlices(b.Licenses, a.Licenses) {
		changes = append(changes, fmt.Sprintf("licenses: %v -> %v", b.Licenses, a.Licenses))
	}
	for algo, hash := range b.Hashes {
		if newHash, exists := a.Hashes[algo]; exists && hash != newHash {
			changes = append(changes, fmt.Sprintf("hash[%s]: %s -> %s", algo, hash, newHash))
		}
	}
	return changes
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aCopy := make([]string, len(a))
	bCopy := make([]string, len(b))
	copy(aCopy, a)
	copy(bCopy, b)
	sort.Strings(aCopy)
	sort.Strings(bCopy)
	for i := range aCopy {
		if aCopy[i] != bCopy[i] {
			return false
		}
	}
	return true
}

func printTextDiff(result DiffResult) {
	if len(result.Added) == 0 && len(result.Removed) == 0 && len(result.Changed) == 0 && result.Duplicates == nil && result.Dependencies == nil {
		fmt.Println("No differences found")
		return
	}

	// Print drift summary first if there are changes
	if result.DriftSummary != nil {
		fmt.Println("\n📊 Drift Summary:")
		if result.DriftSummary.VersionDrift > 0 {
			fmt.Printf("  📦 Version drift:   %d components\n", result.DriftSummary.VersionDrift)
		}
		if result.DriftSummary.IntegrityDrift > 0 {
			fmt.Printf("  ⚠️  Integrity drift: %d components (hash changed without version change!)\n", result.DriftSummary.IntegrityDrift)
		}
		if result.DriftSummary.MetadataDrift > 0 {
			fmt.Printf("  📝 Metadata drift:  %d components\n", result.DriftSummary.MetadataDrift)
		}
	}

	if len(result.Added) > 0 {
		fmt.Printf("\n+ Added (%d):\n", len(result.Added))
		for _, c := range result.Added {
			fmt.Printf("  + %s %s\n", c.Name, c.Version)
		}
	}

	if len(result.Removed) > 0 {
		fmt.Printf("\n- Removed (%d):\n", len(result.Removed))
		for _, c := range result.Removed {
			fmt.Printf("  - %s %s\n", c.Name, c.Version)
		}
	}

	if len(result.Changed) > 0 {
		fmt.Printf("\n~ Changed (%d):\n", len(result.Changed))
		for _, c := range result.Changed {
			driftIndicator := ""
			if c.Drift != nil {
				switch c.Drift.Type {
				case DriftTypeIntegrity:
					driftIndicator = " ⚠️  [INTEGRITY]"
				case DriftTypeVersion:
					driftIndicator = ""
				case DriftTypeMetadata:
					driftIndicator = " [metadata]"
				}
			}
			fmt.Printf("  ~ %s%s\n", c.Name, driftIndicator)
			for _, ch := range c.Changes {
				fmt.Printf("      %s\n", ch)
			}
		}
	}

	if result.Duplicates != nil {
		if len(result.Duplicates.Before) > 0 {
			fmt.Printf("\n! Duplicates in first SBOM (%d):\n", len(result.Duplicates.Before))
			for _, d := range result.Duplicates.Before {
				fmt.Printf("  ! %s: %v\n", d.Name, d.Versions)
			}
		}
		if len(result.Duplicates.After) > 0 {
			fmt.Printf("\n! Duplicates in second SBOM (%d):\n", len(result.Duplicates.After))
			for _, d := range result.Duplicates.After {
				fmt.Printf("  ! %s: %v\n", d.Name, d.Versions)
			}
		}
		if result.Duplicates.VersionDiff != nil {
			vd := result.Duplicates.VersionDiff
			if len(vd.NewDuplicates) > 0 {
				fmt.Printf("\n++ New duplicate groups (%d):\n", len(vd.NewDuplicates))
				for _, d := range vd.NewDuplicates {
					fmt.Printf("  ++ %s: %v\n", d.Name, d.Versions)
				}
			}
			if len(vd.ResolvedDuplicates) > 0 {
				fmt.Printf("\n-- Resolved duplicate groups (%d):\n", len(vd.ResolvedDuplicates))
				for _, d := range vd.ResolvedDuplicates {
					fmt.Printf("  -- %s: %v\n", d.Name, d.Versions)
				}
			}
			if len(vd.VersionsAdded) > 0 {
				fmt.Printf("\n+v Versions added to duplicates:\n")
				for id, versions := range vd.VersionsAdded {
					fmt.Printf("  %s: +%v\n", id, versions)
				}
			}
			if len(vd.VersionsRemoved) > 0 {
				fmt.Printf("\n-v Versions removed from duplicates:\n")
				for id, versions := range vd.VersionsRemoved {
					fmt.Printf("  %s: -%v\n", id, versions)
				}
			}
		}
		if len(result.Duplicates.Collisions) > 0 {
			fmt.Printf("\n⚠️  Identity Collisions (%d):\n", len(result.Duplicates.Collisions))
			for _, c := range result.Duplicates.Collisions {
				fmt.Printf("  [%s] %s\n", c.Reason, c.ID)
				for _, comp := range c.Components {
					fmt.Printf("    - %s %s\n", comp.Name, comp.Version)
				}
			}
		}
	}

	if result.Dependencies != nil {
		if len(result.Dependencies.AddedDeps) > 0 {
			fmt.Printf("\n>> Added dependencies:\n")
			for comp, deps := range result.Dependencies.AddedDeps {
				fmt.Printf("  %s: +%v\n", comp, deps)
			}
		}
		if len(result.Dependencies.RemovedDeps) > 0 {
			fmt.Printf("\n<< Removed dependencies:\n")
			for comp, deps := range result.Dependencies.RemovedDeps {
				fmt.Printf("  %s: -%v\n", comp, deps)
			}
		}

		// Transitive dependency changes
		if len(result.Dependencies.TransitiveNew) > 0 {
			fmt.Printf("\n🔗 New transitive dependencies (%d):\n", len(result.Dependencies.TransitiveNew))
			for _, td := range result.Dependencies.TransitiveNew {
				fmt.Printf("  + %s (depth %d)\n", td.Target, td.Depth)
				if len(td.Via) > 0 {
					fmt.Printf("    via: %v\n", td.Via)
				}
			}
		}
		if len(result.Dependencies.TransitiveLost) > 0 {
			fmt.Printf("\n🔓 Removed transitive dependencies (%d):\n", len(result.Dependencies.TransitiveLost))
			for _, td := range result.Dependencies.TransitiveLost {
				fmt.Printf("  - %s (depth %d)\n", td.Target, td.Depth)
			}
		}

		// Depth summary
		if result.Dependencies.DepthSummary != nil {
			ds := result.Dependencies.DepthSummary
			if ds.Depth1 > 0 || ds.Depth2 > 0 || ds.Depth3Plus > 0 {
				fmt.Printf("\n📊 New deps by depth:\n")
				if ds.Depth1 > 0 {
					fmt.Printf("  Depth 1 (direct):     %d\n", ds.Depth1)
				}
				if ds.Depth2 > 0 {
					fmt.Printf("  Depth 2:              %d\n", ds.Depth2)
				}
				if ds.Depth3Plus > 0 {
					fmt.Printf("  Depth 3+ (risky):     %d ⚠️\n", ds.Depth3Plus)
				}
			}
		}
	}

	fmt.Println()
}
