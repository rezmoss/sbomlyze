package tui

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/rezmoss/sbomlyze/internal/sbom"
)

// Color palette - modern, consistent theme
var (
	// Primary colors
	primaryColor   = lipgloss.Color("#7C3AED") // Vibrant purple
	secondaryColor = lipgloss.Color("#06B6D4") // Cyan
	accentColor    = lipgloss.Color("#F59E0B") // Amber

	// Semantic colors
	successColor = lipgloss.Color("#10B981") // Green
	warningColor = lipgloss.Color("#F59E0B") // Amber
	errorColor   = lipgloss.Color("#EF4444") // Red

	// Neutral colors
	bgColor      = lipgloss.Color("#1E1E2E") // Dark background
	surfaceColor = lipgloss.Color("#313244") // Slightly lighter
	textColor    = lipgloss.Color("#CDD6F4") // Light text
	dimColor     = lipgloss.Color("#6C7086") // Dim text
	brightColor  = lipgloss.Color("#F5F5F5") // Bright white
)

// Base styles
var (
	// Header styles
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(brightColor).
			Background(primaryColor).
			Padding(0, 2)

	headerInfoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A5B4FC")).
			Background(primaryColor)

	// Footer styles
	footerStyle = lipgloss.NewStyle().
			Foreground(dimColor).
			Background(surfaceColor).
			Padding(0, 1)

	footerKeyStyle = lipgloss.NewStyle().
			Foreground(secondaryColor).
			Background(surfaceColor).
			Bold(true)

	footerDescStyle = lipgloss.NewStyle().
			Foreground(dimColor).
			Background(surfaceColor)

	// Status bar styles
	statusBarStyle = lipgloss.NewStyle().
			Foreground(brightColor).
			Background(lipgloss.Color("#4C1D95")).
			Padding(0, 1).
			MarginRight(1)

	statusItemStyle = lipgloss.NewStyle().
			Foreground(textColor).
			Background(surfaceColor).
			Padding(0, 1)

	// Detail view styles
	sectionTitleStyle = lipgloss.NewStyle().
				Foreground(secondaryColor).
				Bold(true).
				MarginTop(1).
				MarginBottom(0)

	labelStyle = lipgloss.NewStyle().
			Foreground(primaryColor).
			Bold(true).
			Width(14)

	valueStyle = lipgloss.NewStyle().
			Foreground(textColor)

	tagStyle = lipgloss.NewStyle().
			Foreground(brightColor).
			Background(surfaceColor).
			Padding(0, 1).
			MarginRight(1)

	successTagStyle = lipgloss.NewStyle().
			Foreground(brightColor).
			Background(successColor).
			Padding(0, 1).
			MarginRight(1)

	warningTagStyle = lipgloss.NewStyle().
			Foreground(brightColor).
			Background(warningColor).
			Padding(0, 1)

	errorTagStyle = lipgloss.NewStyle().
			Foreground(brightColor).
			Background(errorColor).
			Padding(0, 1)

	dimStyle = lipgloss.NewStyle().
			Foreground(dimColor)

	// Modal/overlay styles
	modalStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(primaryColor).
			Padding(1, 2).
			Background(bgColor)

	// JSON syntax highlighting styles
	jsonKeyStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#89B4FA")).
			Bold(true)

	jsonStringStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A6E3A1"))

	jsonNumberStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FAB387"))

	jsonBoolStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F38BA8"))

	jsonNullStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F38BA8")).
			Italic(true)

	jsonBracketStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#89DCEB"))

	jsonColonStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#89DCEB"))

	// Help styles
	helpKeyStyle = lipgloss.NewStyle().
			Foreground(secondaryColor).
			Bold(true).
			Width(16)

	helpDescStyle = lipgloss.NewStyle().
			Foreground(textColor)

	helpSectionStyle = lipgloss.NewStyle().
				Foreground(primaryColor).
				Bold(true).
				MarginTop(1).
				MarginBottom(0).
				Underline(true)
)

func (m Model) View() string {
	if m.quitting {
		return ""
	}

	if !m.ready {
		return lipgloss.Place(
			m.width, m.height,
			lipgloss.Center, lipgloss.Center,
			lipgloss.NewStyle().Foreground(primaryColor).Bold(true).Render("Loading SBOMlyze..."),
		)
	}

	// Build the full-screen layout
	header := m.renderHeader()
	footer := m.renderFooter()
	content := m.renderContent()

	// Calculate content height
	headerHeight := lipgloss.Height(header)
	footerHeight := lipgloss.Height(footer)
	contentHeight := m.height - headerHeight - footerHeight

	// Ensure content fills available space
	contentArea := lipgloss.NewStyle().
		Height(contentHeight).
		Width(m.width).
		Render(content)

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		contentArea,
		footer,
	)
}

func (m Model) renderHeader() string {
	// App title
	title := headerStyle.Render(" SBOMLYZE ")

	// Mode indicator
	var modeText string
	switch m.mode {
	case listView:
		modeText = "EXPLORER"
	case detailView:
		modeText = "DETAILS"
	case jsonView:
		modeText = "JSON VIEW"
	case searchView:
		modeText = "SEARCH"
	case filterView:
		modeText = "FILTER"
	case helpView:
		modeText = "HELP"
	}
	mode := lipgloss.NewStyle().
		Foreground(accentColor).
		Background(primaryColor).
		Bold(true).
		Padding(0, 1).
		Render(modeText)

	// SBOM info
	var infoItems []string
	if m.sbomInfo.OSName != "" {
		osStr := m.sbomInfo.OSName
		if m.sbomInfo.OSVersion != "" {
			osStr += " " + m.sbomInfo.OSVersion
		}
		infoItems = append(infoItems, headerInfoStyle.Render(" "+osStr))
	}
	if m.sbomInfo.SourceName != "" {
		infoItems = append(infoItems, headerInfoStyle.Render(" "+m.sbomInfo.SourceName))
	}
	if m.sbomInfo.SourceType != "" && m.sbomInfo.SourceName == "" {
		infoItems = append(infoItems, headerInfoStyle.Render(" "+m.sbomInfo.SourceType))
	}

	// Component count - show filtered results when search/filter is active
	var countText string
	if m.searchQuery != "" || m.filterType != "" {
		// Show "X of Y" format when filtering
		resultCountStyle := lipgloss.NewStyle().
			Foreground(accentColor).
			Background(primaryColor).
			Bold(true).
			Padding(0, 1)
		countText = resultCountStyle.Render(fmt.Sprintf("%d of %d", len(m.filteredComps), len(m.components)))
	} else {
		countText = headerInfoStyle.Render(fmt.Sprintf(" %d pkgs", len(m.filteredComps)))
	}

	// Build header line
	leftSide := lipgloss.JoinHorizontal(lipgloss.Center, title, mode)
	rightSide := lipgloss.JoinHorizontal(lipgloss.Center, strings.Join(infoItems, " "), countText)

	// Calculate spacing
	leftWidth := lipgloss.Width(leftSide)
	rightWidth := lipgloss.Width(rightSide)
	spacerWidth := m.width - leftWidth - rightWidth
	if spacerWidth < 1 {
		spacerWidth = 1
	}

	spacer := lipgloss.NewStyle().
		Background(primaryColor).
		Width(spacerWidth).
		Render("")

	headerLine := lipgloss.JoinHorizontal(lipgloss.Center, leftSide, spacer, rightSide)

	// Status line for filters - show active filters with result count
	var statusLine string
	if m.searchQuery != "" || m.filterType != "" {
		var statusItems []string

		// Show result summary
		resultStyle := lipgloss.NewStyle().
			Foreground(brightColor).
			Background(lipgloss.Color("#059669")). // Green background
			Bold(true).
			Padding(0, 1)
		statusItems = append(statusItems, resultStyle.Render(fmt.Sprintf(" %d results", len(m.filteredComps))))

		if m.searchQuery != "" {
			statusItems = append(statusItems, statusBarStyle.Render(fmt.Sprintf(" \"%s\"", m.searchQuery)))
		}
		if m.filterType != "" {
			statusItems = append(statusItems, statusItemStyle.Render(fmt.Sprintf(" type:%s", m.filterType)))
		}
		statusLine = "\n" + strings.Join(statusItems, " ")
	}

	return headerLine + statusLine
}

func (m Model) renderFooter() string {
	var keys []string

	switch m.mode {
	case listView:
		keys = []string{
			footerKeyStyle.Render("/") + footerDescStyle.Render(" search"),
			footerKeyStyle.Render("t") + footerDescStyle.Render(" filter"),
			footerKeyStyle.Render("enter") + footerDescStyle.Render(" view"),
			footerKeyStyle.Render("c") + footerDescStyle.Render(" clear"),
			footerKeyStyle.Render("?") + footerDescStyle.Render(" help"),
			footerKeyStyle.Render("q") + footerDescStyle.Render(" quit"),
		}
	case detailView:
		keys = []string{
			footerKeyStyle.Render("j/k") + footerDescStyle.Render(" scroll"),
			footerKeyStyle.Render("j") + footerDescStyle.Render(" json"),
			footerKeyStyle.Render("esc") + footerDescStyle.Render(" back"),
			footerKeyStyle.Render("q") + footerDescStyle.Render(" quit"),
		}
	case jsonView:
		keys = []string{
			footerKeyStyle.Render("j/k") + footerDescStyle.Render(" scroll"),
			footerKeyStyle.Render("g/G") + footerDescStyle.Render(" top/bottom"),
			footerKeyStyle.Render("d") + footerDescStyle.Render(" details"),
			footerKeyStyle.Render("esc") + footerDescStyle.Render(" back"),
		}
	case searchView, filterView:
		keys = []string{
			footerKeyStyle.Render("enter") + footerDescStyle.Render(" confirm"),
			footerKeyStyle.Render("esc") + footerDescStyle.Render(" cancel"),
		}
	case helpView:
		keys = []string{
			footerKeyStyle.Render("esc") + footerDescStyle.Render(" close"),
			footerKeyStyle.Render("?") + footerDescStyle.Render(" close"),
		}
	}

	keysStr := strings.Join(keys, footerDescStyle.Render("  "))

	// Fill the footer to full width
	footerContent := footerStyle.Width(m.width).Render(keysStr)

	return footerContent
}

func (m Model) renderContent() string {
	switch m.mode {
	case listView:
		return m.renderListView()
	case detailView:
		return m.renderDetailView()
	case jsonView:
		return m.renderJSONView()
	case searchView, filterView:
		return m.renderSearchView()
	case helpView:
		return m.renderHelpView()
	}
	return ""
}

func (m Model) renderListView() string {
	return m.list.View()
}

func (m Model) renderDetailView() string {
	// Create a bordered content area
	titleBar := lipgloss.NewStyle().
		Foreground(secondaryColor).
		Bold(true).
		Render(fmt.Sprintf(" %s ", m.selectedComp.Name))

	if m.selectedComp.Version != "" {
		titleBar += dimStyle.Render(" v" + m.selectedComp.Version)
	}

	content := lipgloss.JoinVertical(lipgloss.Left,
		titleBar,
		"",
		m.viewport.View(),
	)

	return content
}

func (m Model) renderJSONView() string {
	titleBar := lipgloss.NewStyle().
		Foreground(secondaryColor).
		Bold(true).
		Render(fmt.Sprintf(" Raw JSON: %s ", m.selectedComp.Name))

	content := lipgloss.JoinVertical(lipgloss.Left,
		titleBar,
		"",
		m.viewport.View(),
	)

	return content
}

func (m Model) renderSearchView() string {
	var title string
	if m.mode == searchView {
		title = " Search Components "
	} else {
		title = " Filter by Type "
	}

	titleStyle := lipgloss.NewStyle().
		Foreground(secondaryColor).
		Bold(true)

	hint := dimStyle.Render("Type to search across all fields including metadata")
	if m.mode == filterView {
		hint = dimStyle.Render("Filter by package type: npm, apk, golang, pypi, deb, rpm...")
	}

	content := lipgloss.JoinVertical(lipgloss.Left,
		"",
		titleStyle.Render(title),
		"",
		m.textInput.View(),
		"",
		hint,
	)

	// Center the search box
	return lipgloss.Place(
		m.width, m.height-4,
		lipgloss.Center, lipgloss.Center,
		modalStyle.Render(content),
	)
}

func (m Model) renderHelpView() string {
	return m.viewport.View()
}

func (m Model) renderComponentDetail(c sbom.Component) string {
	var sb strings.Builder

	// Basic Info Section
	sb.WriteString(sectionTitleStyle.Render("PACKAGE INFO"))
	sb.WriteString("\n")

	// Name with type badge
	sb.WriteString(labelStyle.Render("Name"))
	sb.WriteString(valueStyle.Render(c.Name))
	if pkgType := extractPkgType(c.PURL); pkgType != "" {
		sb.WriteString("  ")
		sb.WriteString(tagStyle.Render(pkgType))
	}
	sb.WriteString("\n")

	// Version
	sb.WriteString(labelStyle.Render("Version"))
	if c.Version != "" {
		sb.WriteString(valueStyle.Render(c.Version))
	} else {
		sb.WriteString(dimStyle.Render("not specified"))
	}
	sb.WriteString("\n")

	// PURL
	if c.PURL != "" {
		sb.WriteString(labelStyle.Render("PURL"))
		sb.WriteString(dimStyle.Render(c.PURL))
		sb.WriteString("\n")
	}

	// Namespace
	if c.Namespace != "" {
		sb.WriteString(labelStyle.Render("Namespace"))
		sb.WriteString(valueStyle.Render(c.Namespace))
		sb.WriteString("\n")
	}

	// Supplier
	if c.Supplier != "" {
		sb.WriteString(labelStyle.Render("Supplier"))
		sb.WriteString(valueStyle.Render(c.Supplier))
		sb.WriteString("\n")
	}

	// Licenses Section
	sb.WriteString("\n")
	sb.WriteString(sectionTitleStyle.Render("LICENSES"))
	sb.WriteString("\n")
	if len(c.Licenses) > 0 {
		for _, lic := range c.Licenses {
			sb.WriteString("  ")
			sb.WriteString(successTagStyle.Render(lic))
			sb.WriteString("\n")
		}
	} else {
		sb.WriteString("  ")
		sb.WriteString(warningTagStyle.Render(" No license info"))
		sb.WriteString("\n")
	}

	// Hashes Section
	if len(c.Hashes) > 0 {
		sb.WriteString("\n")
		sb.WriteString(sectionTitleStyle.Render("INTEGRITY"))
		sb.WriteString("\n")
		for algo, hash := range c.Hashes {
			sb.WriteString(labelStyle.Render(algo))
			displayHash := hash
			if len(hash) > 32 {
				displayHash = hash[:32] + "..."
			}
			sb.WriteString(dimStyle.Render(displayHash))
			sb.WriteString("\n")
		}
	}

	// CPEs Section
	if len(c.CPEs) > 0 {
		sb.WriteString("\n")
		sb.WriteString(sectionTitleStyle.Render("CPEs"))
		sb.WriteString("\n")
		for _, cpe := range c.CPEs {
			sb.WriteString("  ")
			sb.WriteString(dimStyle.Render(cpe))
			sb.WriteString("\n")
		}
	}

	// Dependencies Section
	sb.WriteString("\n")
	sb.WriteString(sectionTitleStyle.Render(fmt.Sprintf("DEPENDENCIES (%d)", len(c.Dependencies))))
	sb.WriteString("\n")
	if len(c.Dependencies) > 0 {
		for _, dep := range c.Dependencies {
			sb.WriteString("  ")
			sb.WriteString(lipgloss.NewStyle().Foreground(secondaryColor).Render(""))
			sb.WriteString(" ")
			sb.WriteString(valueStyle.Render(dep))
			sb.WriteString("\n")
		}
	} else {
		sb.WriteString("  ")
		sb.WriteString(dimStyle.Render("No dependencies listed"))
		sb.WriteString("\n")
	}

	// Identifiers Section
	sb.WriteString("\n")
	sb.WriteString(sectionTitleStyle.Render("IDENTIFIERS"))
	sb.WriteString("\n")
	sb.WriteString(labelStyle.Render("ID"))
	sb.WriteString(dimStyle.Render(c.ID))
	sb.WriteString("\n")

	if c.BOMRef != "" {
		sb.WriteString(labelStyle.Render("BOM-ref"))
		sb.WriteString(dimStyle.Render(c.BOMRef))
		sb.WriteString("\n")
	}
	if c.SPDXID != "" {
		sb.WriteString(labelStyle.Render("SPDX-ID"))
		sb.WriteString(dimStyle.Render(c.SPDXID))
		sb.WriteString("\n")
	}

	// Footer hint
	sb.WriteString("\n")
	sb.WriteString(dimStyle.Render("Press 'j' to view the complete raw JSON from the SBOM"))

	return sb.String()
}

// renderComponentJSON renders the component as syntax-highlighted JSON
func (m Model) renderComponentJSON(c sbom.Component) string {
	var jsonBytes []byte
	var err error

	// Use raw JSON if available (preserves all original fields)
	if len(c.RawJSON) > 0 {
		var raw interface{}
		if err = json.Unmarshal(c.RawJSON, &raw); err == nil {
			jsonBytes, err = json.MarshalIndent(raw, "", "  ")
		}
	}

	// Fallback to normalized component if no raw JSON
	if len(jsonBytes) == 0 || err != nil {
		jsonBytes, err = json.MarshalIndent(c, "", "  ")
		if err != nil {
			return errorTagStyle.Render("Error rendering JSON: " + err.Error())
		}
	}

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
				inString = true
				stringStart = i
				inKey = false
				for j := i + 1; j < length; j++ {
					if runes[j] == '"' && runes[j-1] != '\\' {
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
			if i < length && runes[i] == ' ' {
				i++
			}
			continue

		case !inString && ch == ',':
			result.WriteString(jsonColonStyle.Render(","))
			i++
			continue

		case !inString && (ch == 't' || ch == 'f'):
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
			if i+4 <= length && string(runes[i:i+4]) == "null" {
				result.WriteString(jsonNullStyle.Render("null"))
				i += 4
				continue
			}

		case !inString && (ch >= '0' && ch <= '9' || ch == '-'):
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

	sb.WriteString(helpSectionStyle.Render("Navigation"))
	sb.WriteString("\n\n")
	sb.WriteString(helpKeyStyle.Render("  "))
	sb.WriteString(helpDescStyle.Render("Move up\n"))
	sb.WriteString(helpKeyStyle.Render("  "))
	sb.WriteString(helpDescStyle.Render("Move down\n"))
	sb.WriteString(helpKeyStyle.Render("  PgUp / Ctrl+u"))
	sb.WriteString(helpDescStyle.Render("  Half page up\n"))
	sb.WriteString(helpKeyStyle.Render("  PgDn / Ctrl+d"))
	sb.WriteString(helpDescStyle.Render("  Half page down\n"))
	sb.WriteString(helpKeyStyle.Render("  Enter"))
	sb.WriteString(helpDescStyle.Render("         View details\n"))
	sb.WriteString(helpKeyStyle.Render("  Esc"))
	sb.WriteString(helpDescStyle.Render("           Go back\n"))
	sb.WriteString(helpKeyStyle.Render("  q"))
	sb.WriteString(helpDescStyle.Render("             Quit\n"))

	sb.WriteString("\n")
	sb.WriteString(helpSectionStyle.Render("Views"))
	sb.WriteString("\n\n")
	sb.WriteString(helpKeyStyle.Render("  j"))
	sb.WriteString(helpDescStyle.Render("             View raw JSON\n"))
	sb.WriteString(helpKeyStyle.Render("  d"))
	sb.WriteString(helpDescStyle.Render("             Back to details (from JSON)\n"))

	sb.WriteString("\n")
	sb.WriteString(helpSectionStyle.Render("Search & Filter"))
	sb.WriteString("\n\n")
	sb.WriteString(helpKeyStyle.Render("  /"))
	sb.WriteString(helpDescStyle.Render("             Deep search (all fields)\n"))
	sb.WriteString(helpKeyStyle.Render("  t"))
	sb.WriteString(helpDescStyle.Render("             Filter by package type\n"))
	sb.WriteString(helpKeyStyle.Render("  c"))
	sb.WriteString(helpDescStyle.Render("             Clear all filters\n"))

	sb.WriteString("\n")
	sb.WriteString(helpSectionStyle.Render("Package Types"))
	sb.WriteString("\n\n")
	typeList := [][]string{
		{"npm", "Node.js"},
		{"apk", "Alpine"},
		{"deb", "Debian"},
		{"rpm", "RedHat"},
		{"golang", "Go"},
		{"pypi", "Python"},
		{"maven", "Java"},
		{"cargo", "Rust"},
		{"gem", "Ruby"},
		{"nuget", ".NET"},
	}

	for i := 0; i < len(typeList); i += 2 {
		sb.WriteString("  ")
		sb.WriteString(tagStyle.Render(typeList[i][0]))
		sb.WriteString(" ")
		sb.WriteString(dimStyle.Render(typeList[i][1]))
		if i+1 < len(typeList) {
			sb.WriteString("    ")
			sb.WriteString(tagStyle.Render(typeList[i+1][0]))
			sb.WriteString(" ")
			sb.WriteString(dimStyle.Render(typeList[i+1][1]))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
