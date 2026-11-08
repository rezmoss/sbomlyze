package cli

// OptionDoc documents one CLI option; feeds --help and the website.
type OptionDoc struct {
	Flag string `json:"flag"`
	Desc string `json:"desc"`
}

// FormatDoc documents one --format value.
type FormatDoc struct {
	Name    string `json:"name"`
	Summary string `json:"summary"`
	BestFor string `json:"best_for"`
}

// OptionDocs lists every CLI option, in --help order.
var OptionDocs = []OptionDoc{
	{"-i, --interactive", "Interactive TUI explorer"},
	{"-web, --web", "Start web UI server"},
	{"--port <port>", "Web server port (default 8080)"},
	{"--json", "Output in JSON format (shortcut for --format json)"},
	{"--format <format>", "Output format: text, json, sarif, junit, markdown, html, patch"},
	{"--compliance", "Score NTIA, CISA and BSI TR-03183 compliance"},
	{"--policy <file>", "Policy file for CI checks"},
	{"--strict", "Fail on parse warnings"},
	{"--tolerant", "Continue on parse warnings (default)"},
	{"--no-pager", "Disable automatic paging of output"},
	{"--to <format>", "Target format for convert: cyclonedx (cdx), spdx, syft"},
	{"-o, --output <file>", "Output file for convert (default: stdout)"},
	{"--version, -v", "Show version information"},
	{"--help, -h", "Show this help message"},
}

// OutputFormats lists every --format value.
var OutputFormats = []FormatDoc{
	{"text", "Human-readable text (default)", "Local inspection"},
	{"json", "JSON for programmatic consumption", "CI pipelines, scripting"},
	{"sarif", "SARIF for GitHub Code Scanning", "GitHub Code Scanning"},
	{"junit", "JUnit XML for CI test results", "CI test dashboards"},
	{"markdown", "Markdown for PR comments", "Pull request comments"},
	{"html", "Self-contained HTML for auditors and reports", "Auditors, sharable reports"},
	{"patch", "JSON Patch (RFC 6902) for automation", "Programmatic patching"},
}
