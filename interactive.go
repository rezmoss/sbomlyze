package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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

	normalStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#DDDDDD"))

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

// View modes
type viewMode int

const (
	listView viewMode = iota
	detailView
	jsonView
	searchView
	filterView
	helpView
)

// ComponentItem represents a list item
type ComponentItem struct {
	component Component
	index     int
}

func (i ComponentItem) Title() string {
	version := i.component.Version
	if version == "" {
		version = "(no version)"
	}
	return fmt.Sprintf("%s %s", i.component.Name, dimStyle.Render(version))
}

func (i ComponentItem) Description() string {
	var parts []string
	if i.component.PURL != "" {
		// Extract type from PURL
		if strings.HasPrefix(i.component.PURL, "pkg:") {
			parts := strings.SplitN(i.component.PURL[4:], "/", 2)
			if len(parts) > 0 {
				return fmt.Sprintf("Type: %s", parts[0])
			}
		}
	}
	if len(i.component.Licenses) > 0 {
		parts = append(parts, fmt.Sprintf("License: %s", i.component.Licenses[0]))
	}
	if len(i.component.Dependencies) > 0 {
		parts = append(parts, fmt.Sprintf("Deps: %d", len(i.component.Dependencies)))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " | ")
}

func (i ComponentItem) FilterValue() string {
	return i.component.Name + " " + i.component.PURL + " " + strings.Join(i.component.Licenses, " ")
}

// Model is the main TUI model
type Model struct {
	components    []Component
	filteredComps []Component
	list          list.Model
	viewport      viewport.Model
	textInput     textinput.Model
	mode          viewMode
	selected      int
	selectedComp  Component
	width         int
	height        int
	searchQuery   string
	filterType    string
	stats         SBOMStats
	ready         bool
	quitting      bool
}

// Key bindings
type keyMap struct {
	Up       key.Binding
	Down     key.Binding
	Enter    key.Binding
	Back     key.Binding
	Quit     key.Binding
	Search   key.Binding
	Filter   key.Binding
	Help     key.Binding
	ClearAll key.Binding
	JSON     key.Binding
}

var keys = keyMap{
	Up: key.NewBinding(
		key.WithKeys("up", "k"),
		key.WithHelp("↑/k", "up"),
	),
	Down: key.NewBinding(
		key.WithKeys("down", "j"),
		key.WithHelp("↓/j", "down"),
	),
	Enter: key.NewBinding(
		key.WithKeys("enter"),
		key.WithHelp("enter", "select"),
	),
	Back: key.NewBinding(
		key.WithKeys("esc", "backspace"),
		key.WithHelp("esc", "back"),
	),
	Quit: key.NewBinding(
		key.WithKeys("q", "ctrl+c"),
		key.WithHelp("q", "quit"),
	),
	Search: key.NewBinding(
		key.WithKeys("/"),
		key.WithHelp("/", "search"),
	),
	Filter: key.NewBinding(
		key.WithKeys("t"),
		key.WithHelp("t", "filter type"),
	),
	Help: key.NewBinding(
		key.WithKeys("?"),
		key.WithHelp("?", "help"),
	),
	ClearAll: key.NewBinding(
		key.WithKeys("c"),
		key.WithHelp("c", "clear filters"),
	),
	JSON: key.NewBinding(
		key.WithKeys("j"),
		key.WithHelp("j", "view JSON"),
	),
}

// NewInteractiveModel creates a new interactive model
func NewInteractiveModel(comps []Component, stats SBOMStats) Model {
	// Sort components by name
	sorted := make([]Component, len(comps))
	copy(sorted, comps)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Name < sorted[j].Name
	})

	// Create list items
	items := make([]list.Item, len(sorted))
	for i, c := range sorted {
		items[i] = ComponentItem{component: c, index: i}
	}

	// Create list
	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = selectedStyle
	delegate.Styles.SelectedDesc = selectedStyle

	l := list.New(items, delegate, 0, 0)
	l.Title = "📦 SBOM Explorer"
	l.SetShowStatusBar(true)
	l.SetFilteringEnabled(true)
	l.Styles.Title = titleStyle

	// Create text input for search
	ti := textinput.New()
	ti.Placeholder = "Search components..."
	ti.CharLimit = 100

	// Create viewport for details
	vp := viewport.New(0, 0)

	return Model{
		components:    sorted,
		filteredComps: sorted,
		list:          l,
		viewport:      vp,
		textInput:     ti,
		mode:          listView,
		stats:         stats,
	}
}

func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.list.SetSize(msg.Width, msg.Height-4)
		m.viewport.Width = msg.Width
		m.viewport.Height = msg.Height - 6
		m.ready = true
		return m, nil

	case tea.KeyMsg:
		// Global keys
		if key.Matches(msg, keys.Quit) && m.mode != searchView && m.mode != filterView {
			m.quitting = true
			return m, tea.Quit
		}

		switch m.mode {
		case listView:
			switch {
			case key.Matches(msg, keys.Enter):
				if i, ok := m.list.SelectedItem().(ComponentItem); ok {
					m.selected = i.index
					m.selectedComp = i.component
					m.mode = detailView
					m.viewport.SetContent(m.renderComponentDetail(i.component))
					m.viewport.GotoTop()
				}
			case key.Matches(msg, keys.Search):
				m.mode = searchView
				m.textInput.SetValue("")
				m.textInput.Placeholder = "Search by name, PURL, license..."
				m.textInput.Focus()
				return m, textinput.Blink
			case key.Matches(msg, keys.Filter):
				m.mode = filterView
				m.textInput.SetValue("")
				m.textInput.Placeholder = "Filter by type (npm, apk, golang, pypi...)"
				m.textInput.Focus()
				return m, textinput.Blink
			case key.Matches(msg, keys.Help):
				m.mode = helpView
				m.viewport.SetContent(m.renderHelp())
				m.viewport.GotoTop()
			case key.Matches(msg, keys.ClearAll):
				m.searchQuery = ""
				m.filterType = ""
				m.applyFilters()
			}

		case detailView:
			switch {
			case key.Matches(msg, keys.Back):
				m.mode = listView
			case key.Matches(msg, keys.JSON):
				m.mode = jsonView
				m.viewport.SetContent(m.renderComponentJSON(m.selectedComp))
				m.viewport.GotoTop()
			case msg.String() == "up", msg.String() == "k":
				m.viewport.LineUp(1)
			case msg.String() == "down", msg.String() == "j":
				m.viewport.LineDown(1)
			case msg.String() == "pgup", msg.String() == "pageup", msg.String() == "ctrl+u":
				m.viewport.HalfViewUp()
			case msg.String() == "pgdown", msg.String() == "pagedown", msg.String() == "ctrl+d":
				m.viewport.HalfViewDown()
			}

		case jsonView:
			switch {
			case key.Matches(msg, keys.Back):
				m.mode = detailView
				m.viewport.SetContent(m.renderComponentDetail(m.selectedComp))
				m.viewport.GotoTop()
			case msg.String() == "d":
				// Toggle back to detail view
				m.mode = detailView
				m.viewport.SetContent(m.renderComponentDetail(m.selectedComp))
				m.viewport.GotoTop()
			case msg.String() == "up", msg.String() == "k":
				m.viewport.LineUp(1)
			case msg.String() == "down", msg.String() == "j":
				m.viewport.LineDown(1)
			case msg.String() == "pgup", msg.String() == "pageup", msg.String() == "ctrl+u":
				m.viewport.HalfViewUp()
			case msg.String() == "pgdown", msg.String() == "pagedown", msg.String() == "ctrl+d":
				m.viewport.HalfViewDown()
			case msg.String() == "home", msg.String() == "g":
				m.viewport.GotoTop()
			case msg.String() == "end", msg.String() == "G":
				m.viewport.GotoBottom()
			}

		case searchView, filterView:
			switch msg.String() {
			case "enter":
				if m.mode == searchView {
					m.searchQuery = m.textInput.Value()
				} else {
					m.filterType = m.textInput.Value()
				}
				m.applyFilters()
				m.mode = listView
				m.textInput.Blur()
			case "esc":
				m.mode = listView
				m.textInput.Blur()
			default:
				m.textInput, cmd = m.textInput.Update(msg)
				cmds = append(cmds, cmd)
			}
			return m, tea.Batch(cmds...)

		case helpView:
			if key.Matches(msg, keys.Back) || msg.String() == "?" {
				m.mode = listView
			}
		}
	}

	// Update list in list view
	if m.mode == listView {
		m.list, cmd = m.list.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m *Model) applyFilters() {
	var filtered []Component

	for _, c := range m.components {
		// Apply search filter
		if m.searchQuery != "" {
			query := strings.ToLower(m.searchQuery)
			searchable := strings.ToLower(c.Name + " " + c.PURL + " " + strings.Join(c.Licenses, " "))
			if !strings.Contains(searchable, query) {
				continue
			}
		}

		// Apply type filter
		if m.filterType != "" {
			typeFilter := strings.ToLower(m.filterType)
			pkgType := extractPkgType(c.PURL)
			if !strings.Contains(strings.ToLower(pkgType), typeFilter) {
				continue
			}
		}

		filtered = append(filtered, c)
	}

	m.filteredComps = filtered

	// Update list items
	items := make([]list.Item, len(filtered))
	for i, c := range filtered {
		items[i] = ComponentItem{component: c, index: i}
	}
	m.list.SetItems(items)
}

func extractPkgType(purl string) string {
	if strings.HasPrefix(purl, "pkg:") {
		parts := strings.SplitN(purl[4:], "/", 2)
		if len(parts) > 0 {
			return parts[0]
		}
	}
	return ""
}

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

	return fmt.Sprintf("%s\n%s\n%s",
		status.String(),
		m.list.View(),
		help,
	)
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

func (m Model) renderComponentDetail(c Component) string {
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
func (m Model) renderComponentJSON(c Component) string {
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
	sb.WriteString("  /           Search by name, PURL, license\n")
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

// RunInteractive starts the interactive TUI
func RunInteractive(comps []Component, stats SBOMStats) error {
	p := tea.NewProgram(
		NewInteractiveModel(comps, stats),
		tea.WithAltScreen(),
	)

	_, err := p.Run()
	return err
}
