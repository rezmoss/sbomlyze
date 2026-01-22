package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/rezmoss/sbomlyze/internal/analysis"
	"github.com/rezmoss/sbomlyze/internal/sbom"
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
	component sbom.Component
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
	components    []sbom.Component
	filteredComps []sbom.Component
	list          list.Model
	viewport      viewport.Model
	textInput     textinput.Model
	mode          viewMode
	selected      int
	selectedComp  sbom.Component
	width         int
	height        int
	searchQuery   string
	filterType    string
	stats         analysis.Stats
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

// NewModel creates a new interactive model
func NewModel(comps []sbom.Component, stats analysis.Stats) Model {
	// Sort components by name
	sorted := make([]sbom.Component, len(comps))
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
	l.Title = "📦 SBOMlyze Explorer"
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
				m.textInput.Placeholder = "Search all fields..."
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
				m.viewport.ScrollUp(1)
			case msg.String() == "down", msg.String() == "j":
				m.viewport.ScrollDown(1)
			case msg.String() == "pgup", msg.String() == "pageup", msg.String() == "ctrl+u":
				m.viewport.HalfPageUp()
			case msg.String() == "pgdown", msg.String() == "pagedown", msg.String() == "ctrl+d":
				m.viewport.HalfPageDown()
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
				m.viewport.ScrollUp(1)
			case msg.String() == "down", msg.String() == "j":
				m.viewport.ScrollDown(1)
			case msg.String() == "pgup", msg.String() == "pageup", msg.String() == "ctrl+u":
				m.viewport.HalfPageUp()
			case msg.String() == "pgdown", msg.String() == "pagedown", msg.String() == "ctrl+d":
				m.viewport.HalfPageDown()
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
	var filtered []sbom.Component

	for _, c := range m.components {
		// Apply search filter
		if m.searchQuery != "" {
			query := strings.ToLower(m.searchQuery)
			searchable := strings.ToLower(c.Name + " " + c.PURL + " " + strings.Join(c.Licenses, " ") + " " + string(c.RawJSON))
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

// Run starts the interactive TUI
func Run(comps []sbom.Component, stats analysis.Stats) error {
	p := tea.NewProgram(
		NewModel(comps, stats),
		tea.WithAltScreen(),
	)

	_, err := p.Run()
	return err
}
