package tui

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/rezmoss/sbomlyze/internal/sbom"
)

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1)

	statusBarStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFDF5")).
			Background(lipgloss.Color("#6124DF")).
			Padding(0, 1)

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#626262"))

	selectedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4"))

	detailKeyStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7D56F4")).
			Bold(true)

	detailValueStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#FAFAFA"))

	warningStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF6B6B")).
			Bold(true)

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#69DB7C"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#626262"))

	// JSON syntax highlighting styles
	jsonKeyStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#82AAFF")).
			Bold(true)

	jsonStringStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#C3E88D"))

	jsonNumberStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F78C6C"))

	jsonBoolStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF5370"))

	jsonNullStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF5370")).
			Italic(true)

	jsonBracketStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#89DDFF"))

	jsonColonStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#89DDFF"))
)

func (m Model) View() string {
	if m.quitting {
		return ""
	}

	if !m.ready {
		return "Loading..."
	}

	var content string

	switch m.mode {
	case listView:
		content = m.renderListView()
	case detailView:
		content = m.renderDetailView()
	case jsonView:
		content = m.renderJSONView()
	case searchView, filterView:
		content = m.renderSearchView()
	case helpView:
		content = m.renderHelpView()
	}

	return content
}

func (m Model) renderListView() string {
	var status strings.Builder

	// Status bar
	status.WriteString(statusBarStyle.Render(
		fmt.Sprintf(" 📦 %d components", len(m.filteredComps)),
	))

	if m.searchQuery != "" {
		status.WriteString(" ")
		status.WriteString(statusBarStyle.Render(
			fmt.Sprintf(" 🔍 \"%s\"", m.searchQuery),
		))
	}

	if m.filterType != "" {
		status.WriteString(" ")
		status.WriteString(statusBarStyle.Render(
			fmt.Sprintf(" 📁 type:%s", m.filterType),
		))
	}

	help := helpStyle.Render(" / search • t filter type • enter details • c clear • ? help • q quit")

	// Build OS info line if available
	osInfo := m.renderOSInfo()

	if osInfo != "" {
		return fmt.Sprintf("%s\n%s\n%s\n%s",
			status.String(),
			m.list.View(),
			osInfo,
			help,
		)
	}

	return fmt.Sprintf("%s\n%s\n%s",
		status.String(),
		m.list.View(),
		help,
	)
}

// renderOSInfo renders the OS/source info line if available
func (m Model) renderOSInfo() string {
	var parts []string

	// OS name and version
	if m.sbomInfo.OSName != "" {
		osStr := m.sbomInfo.OSName
		if m.sbomInfo.OSVersion != "" {
			osStr += " " + m.sbomInfo.OSVersion
		}
		parts = append(parts, fmt.Sprintf("🐧 %s", osStr))
	}

	// Source type and name
	if m.sbomInfo.SourceType != "" || m.sbomInfo.SourceName != "" {
		var sourceStr string
		if m.sbomInfo.SourceType != "" {
			sourceStr = m.sbomInfo.SourceType
		}
		if m.sbomInfo.SourceName != "" {
			if sourceStr != "" {
				sourceStr += ": " + m.sbomInfo.SourceName
			} else {
				sourceStr = m.sbomInfo.SourceName
			}
		}
		if sourceStr != "" {
			parts = append(parts, fmt.Sprintf("📂 %s", sourceStr))
		}
	}

	if len(parts) == 0 {
		return ""
	}

	return dimStyle.Render(strings.Join(parts, "  •  "))
}

func (m Model) renderDetailView() string {
	title := titleStyle.Render(" 📄 Component Details ")
	help := helpStyle.Render(" ↑/↓ scroll • PgUp/PgDn/Ctrl+u/d half-page • j view JSON • esc back • q quit")

	return fmt.Sprintf("%s\n\n%s\n\n%s", title, m.viewport.View(), help)
}

func (m Model) renderJSONView() string {
	title := titleStyle.Render(" 🔧 Raw SBOM JSON ")
	compName := detailValueStyle.Render(m.selectedComp.Name)
	help := helpStyle.Render(" ↑/↓ scroll • PgUp/PgDn/Ctrl+u/d half-page • g/G top/bottom • d details • esc back")

	return fmt.Sprintf("%s %s\n\n%s\n\n%s", title, compName, m.viewport.View(), help)
}

func (m Model) renderSearchView() string {
	var title string
	if m.mode == searchView {
		title = titleStyle.Render(" 🔍 Search ")
	} else {
		title = titleStyle.Render(" 📁 Filter by Type ")
	}

	return fmt.Sprintf("%s\n\n%s\n\n%s",
		title,
		m.textInput.View(),
		helpStyle.Render(" enter confirm • esc cancel"),
	)
}

func (m Model) renderHelpView() string {
	title := titleStyle.Render(" ❓ Help ")
	return fmt.Sprintf("%s\n\n%s\n\n%s", title, m.viewport.View(), helpStyle.Render(" esc or ? to close"))
}

func (m Model) renderComponentDetail(c sbom.Component) string {
	var sb strings.Builder

	// Name and version
	sb.WriteString(detailKeyStyle.Render("Name: "))
	sb.WriteString(detailValueStyle.Render(c.Name))
	sb.WriteString("\n")

	sb.WriteString(detailKeyStyle.Render("Version: "))
	if c.Version != "" {
		sb.WriteString(detailValueStyle.Render(c.Version))
	} else {
		sb.WriteString(dimStyle.Render("(none)"))
	}
	sb.WriteString("\n")

	// PURL
	if c.PURL != "" {
		sb.WriteString(detailKeyStyle.Render("PURL: "))
		sb.WriteString(detailValueStyle.Render(c.PURL))
		sb.WriteString("\n")

		// Extract and show type
		pkgType := extractPkgType(c.PURL)
		if pkgType != "" {
			sb.WriteString(detailKeyStyle.Render("Type: "))
			sb.WriteString(detailValueStyle.Render(pkgType))
			sb.WriteString("\n")
		}
	}

	// ID
	sb.WriteString(detailKeyStyle.Render("ID: "))
	sb.WriteString(dimStyle.Render(c.ID))
	sb.WriteString("\n")

	// Namespace
	if c.Namespace != "" {
		sb.WriteString(detailKeyStyle.Render("Namespace: "))
		sb.WriteString(detailValueStyle.Render(c.Namespace))
		sb.WriteString("\n")
	}

	// Supplier
	if c.Supplier != "" {
		sb.WriteString(detailKeyStyle.Render("Supplier: "))
		sb.WriteString(detailValueStyle.Render(c.Supplier))
		sb.WriteString("\n")
	}

	sb.WriteString("\n")

	// Licenses
	sb.WriteString(detailKeyStyle.Render("Licenses: "))
	if len(c.Licenses) > 0 {
		sb.WriteString("\n")
		for _, lic := range c.Licenses {
			sb.WriteString("  • ")
			sb.WriteString(successStyle.Render(lic))
			sb.WriteString("\n")
		}
	} else {
		sb.WriteString(warningStyle.Render("⚠ No license"))
		sb.WriteString("\n")
	}

	// Hashes
	sb.WriteString("\n")
	sb.WriteString(detailKeyStyle.Render("Hashes: "))
	if len(c.Hashes) > 0 {
		sb.WriteString("\n")
		for algo, hash := range c.Hashes {
			sb.WriteString("  • ")
			sb.WriteString(fmt.Sprintf("%s: ", algo))
			if len(hash) > 16 {
				sb.WriteString(dimStyle.Render(hash[:16] + "..."))
			} else {
				sb.WriteString(dimStyle.Render(hash))
			}
			sb.WriteString("\n")
		}
	} else {
		sb.WriteString(warningStyle.Render("⚠ No hashes"))
		sb.WriteString("\n")
	}

	// CPEs
	if len(c.CPEs) > 0 {
		sb.WriteString("\n")
		sb.WriteString(detailKeyStyle.Render("CPEs: "))
		sb.WriteString("\n")
		for _, cpe := range c.CPEs {
			sb.WriteString("  • ")
			sb.WriteString(dimStyle.Render(cpe))
			sb.WriteString("\n")
		}
	}

	// Dependencies
	sb.WriteString("\n")
	sb.WriteString(detailKeyStyle.Render("Dependencies: "))
	if len(c.Dependencies) > 0 {
		sb.WriteString(fmt.Sprintf("(%d)\n", len(c.Dependencies)))
		for _, dep := range c.Dependencies {
			sb.WriteString("  → ")
			sb.WriteString(detailValueStyle.Render(dep))
			sb.WriteString("\n")
		}
	} else {
		sb.WriteString(dimStyle.Render("(none)"))
		sb.WriteString("\n")
	}

	// BOM-ref / SPDXID
	if c.BOMRef != "" {
		sb.WriteString("\n")
		sb.WriteString(detailKeyStyle.Render("BOM-ref: "))
		sb.WriteString(dimStyle.Render(c.BOMRef))
		sb.WriteString("\n")
	}
	if c.SPDXID != "" {
		sb.WriteString("\n")
		sb.WriteString(detailKeyStyle.Render("SPDX-ID: "))
		sb.WriteString(dimStyle.Render(c.SPDXID))
		sb.WriteString("\n")
	}

	sb.WriteString("\n")
	sb.WriteString(dimStyle.Render("Press 'j' to view original SBOM JSON (all fields)"))

	return sb.String()
}

// renderComponentJSON renders the component as syntax-highlighted JSON
// Uses the original raw JSON from the SBOM if available
func (m Model) renderComponentJSON(c sbom.Component) string {
	var jsonBytes []byte
	var err error

	// Use raw JSON if available (preserves all original fields)
	if len(c.RawJSON) > 0 {
		// Pretty print the raw JSON
		var raw interface{}
		if err = json.Unmarshal(c.RawJSON, &raw); err == nil {
			jsonBytes, err = json.MarshalIndent(raw, "", "  ")
		}
	}

	// Fallback to normalized component if no raw JSON
	if len(jsonBytes) == 0 || err != nil {
		jsonBytes, err = json.MarshalIndent(c, "", "  ")
		if err != nil {
			return warningStyle.Render("Error rendering JSON: " + err.Error())
		}
	}

	// Apply syntax highlighting
	return syntaxHighlightJSON(string(jsonBytes))
}

// syntaxHighlightJSON applies color syntax highlighting to JSON
func syntaxHighlightJSON(jsonStr string) string {
	var result strings.Builder
	inString := false
	inKey := false
	stringStart := 0
	i := 0

	runes := []rune(jsonStr)
	length := len(runes)

	for i < length {
		ch := runes[i]

		switch {
		case ch == '"' && (i == 0 || runes[i-1] != '\\'):
			if !inString {
				// Starting a string
				inString = true
				stringStart = i

				// Check if this is a key (look ahead for colon)
				inKey = false
				for j := i + 1; j < length; j++ {
					if runes[j] == '"' && runes[j-1] != '\\' {
						// End of string, check what comes next
						for k := j + 1; k < length; k++ {
							if runes[k] == ':' {
								inKey = true
								break
							} else if runes[k] != ' ' && runes[k] != '\t' && runes[k] != '\n' {
								break
							}
						}
						break
					}
				}
			} else {
				// Ending a string
				inString = false
				strContent := string(runes[stringStart : i+1])

				if inKey {
					result.WriteString(jsonKeyStyle.Render(strContent))
				} else {
					result.WriteString(jsonStringStyle.Render(strContent))
				}
				i++
				continue
			}

		case !inString && (ch == '{' || ch == '}' || ch == '[' || ch == ']'):
			result.WriteString(jsonBracketStyle.Render(string(ch)))
			i++
			continue

		case !inString && ch == ':':
			result.WriteString(jsonColonStyle.Render(": "))
			i++
			// Skip the space after colon if present
			if i < length && runes[i] == ' ' {
				i++
			}
			continue

		case !inString && ch == ',':
			result.WriteString(jsonColonStyle.Render(","))
			i++
			continue

		case !inString && (ch == 't' || ch == 'f'):
			// Check for true/false
			if i+4 <= length && string(runes[i:i+4]) == "true" {
				result.WriteString(jsonBoolStyle.Render("true"))
				i += 4
				continue
			}
			if i+5 <= length && string(runes[i:i+5]) == "false" {
				result.WriteString(jsonBoolStyle.Render("false"))
				i += 5
				continue
			}

		case !inString && ch == 'n':
			// Check for null
			if i+4 <= length && string(runes[i:i+4]) == "null" {
				result.WriteString(jsonNullStyle.Render("null"))
				i += 4
				continue
			}

		case !inString && (ch >= '0' && ch <= '9' || ch == '-'):
			// Parse number
			numStart := i
			for i < length && (runes[i] >= '0' && runes[i] <= '9' || runes[i] == '.' || runes[i] == '-' || runes[i] == 'e' || runes[i] == 'E' || runes[i] == '+') {
				i++
			}
			result.WriteString(jsonNumberStyle.Render(string(runes[numStart:i])))
			continue
		}

		if !inString {
			result.WriteRune(ch)
		}
		i++
	}

	return result.String()
}

func (m Model) renderHelp() string {
	var sb strings.Builder

	sb.WriteString(detailKeyStyle.Render("Navigation"))
	sb.WriteString("\n")
	sb.WriteString("  ↑/k           Move up\n")
	sb.WriteString("  ↓/j           Move down\n")
	sb.WriteString("  PgUp/Ctrl+u   Half page up\n")
	sb.WriteString("  PgDn/Ctrl+d   Half page down\n")
	sb.WriteString("  g/G           Go to top/bottom (in JSON view)\n")
	sb.WriteString("  enter         View component details\n")
	sb.WriteString("  esc           Go back\n")
	sb.WriteString("  q             Quit\n")
	sb.WriteString("\n")

	sb.WriteString(detailKeyStyle.Render("Views"))
	sb.WriteString("\n")
	sb.WriteString("  j           View original SBOM JSON (all fields from source)\n")
	sb.WriteString("  d           Switch back to detail view (in JSON view)\n")
	sb.WriteString("\n")

	sb.WriteString(detailKeyStyle.Render("Search & Filter"))
	sb.WriteString("\n")
	sb.WriteString("  /           Search all fields (deep search)\n")
	sb.WriteString("  t           Filter by package type (npm, apk, golang...)\n")
	sb.WriteString("  c           Clear all filters\n")
	sb.WriteString("\n")

	sb.WriteString(detailKeyStyle.Render("In List View"))
	sb.WriteString("\n")
	sb.WriteString("  Type to filter list in real-time\n")
	sb.WriteString("\n")

	sb.WriteString(detailKeyStyle.Render("Package Types"))
	sb.WriteString("\n")
	sb.WriteString("  npm       Node.js packages\n")
	sb.WriteString("  apk       Alpine packages\n")
	sb.WriteString("  golang    Go modules\n")
	sb.WriteString("  pypi      Python packages\n")
	sb.WriteString("  maven     Java/Maven artifacts\n")
	sb.WriteString("  cargo     Rust crates\n")
	sb.WriteString("  gem       Ruby gems\n")
	sb.WriteString("  nuget     .NET packages\n")
	sb.WriteString("  deb       Debian packages\n")
	sb.WriteString("  rpm       RPM packages\n")

	return sb.String()
}
