package admin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Run starts the admin terminal UI over the config file. When the file does
// not exist yet, the UI asks for the host and domain and generates the whole
// deployment first.
func Run(path string) error {
	m := newModel(path)
	p := tea.NewProgram(m, tea.WithAltScreen())
	out, err := p.Run()
	if err != nil {
		return err
	}
	if fm, ok := out.(model); ok && fm.fatal != nil {
		return fm.fatal
	}
	return nil
}

// ---------- model ----------

type screen int

const (
	screenMain screen = iota
	screenClients
	screenInbounds
	screenExport
)

type inputKind int

const (
	kindClientID inputKind = iota
	kindInboundID
	kindInboundDomain
	kindInboundListen
	kindInitHost
	kindInitDomain
)

type inputStep struct {
	kind        inputKind
	prompt      string
	placeholder string
	fallback    string // used when submitted empty
}

type model struct {
	path      string
	store     *Store
	fatal     error
	needsInit bool

	screen    screen
	list      list
	input     textInput
	steps     []inputStep
	stepVals  []string
	exportFor string

	message  string
	quitting bool
	width    int
	height   int
}

func newModel(path string) model {
	m := model{path: path, screen: screenMain}
	store, err := Load(path)
	if errors.Is(err, os.ErrNotExist) {
		m.needsInit = true
		m.startInit()
		return m
	}
	if err != nil {
		m.fatal = err
		return m
	}
	m.store = store
	m.rebuildMain()
	return m
}

func (m *model) startInit() {
	m.steps = []inputStep{
		{kind: kindInitHost, prompt: "public host or IP", placeholder: "203.0.113.10"},
		{kind: kindInitDomain, prompt: "server domain (SNI)", placeholder: "example.com"},
	}
	m.input = textInput{placeholder: m.steps[0].placeholder}
}

// ---------- list and input widgets ----------

type listItem struct {
	id   string
	text string
}

type list struct {
	items []listItem
	index int
}

func (l *list) up() {
	if l.index > 0 {
		l.index--
	}
}

func (l *list) down() {
	if l.index < len(l.items)-1 {
		l.index++
	}
}

func (l *list) selected() listItem {
	if len(l.items) == 0 {
		return listItem{}
	}
	return l.items[l.index]
}

type textInput struct {
	buf         []rune
	cursor      int
	placeholder string
}

func (t *textInput) Update(key tea.KeyMsg) {
	switch key.Type {
	case tea.KeyRunes:
		t.buf = append(t.buf[:t.cursor], append(key.Runes, t.buf[t.cursor:]...)...)
		t.cursor += len(key.Runes)
	case tea.KeyBackspace:
		if t.cursor > 0 {
			t.buf = append(t.buf[:t.cursor-1], t.buf[t.cursor:]...)
			t.cursor--
		}
	case tea.KeyLeft:
		if t.cursor > 0 {
			t.cursor--
		}
	case tea.KeyRight:
		if t.cursor < len(t.buf) {
			t.cursor++
		}
	case tea.KeyHome:
		t.cursor = 0
	case tea.KeyEnd:
		t.cursor = len(t.buf)
	}
}

func (t *textInput) Value() string { return string(t.buf) }

func (t *textInput) Reset() { t.buf, t.cursor = nil, 0 }

func (t *textInput) View() string {
	if len(t.buf) == 0 && t.placeholder != "" {
		return hintStyle.Render(t.placeholder)
	}
	return string(t.buf[:t.cursor]) + "▋" + string(t.buf[t.cursor:])
}

// ---------- styles ----------

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	selStyle   = lipgloss.NewStyle().Bold(true)
	hintStyle  = lipgloss.NewStyle().Faint(true)
	errStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	okStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
)

// ---------- bubbletea interface ----------

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			m.quitting = true
			return m, tea.Quit
		}
		if m.fatal != nil {
			return m, tea.Quit
		}
		m.message = ""
		if len(m.steps) > 0 {
			return m.updateInput(msg)
		}
		if msg.String() == "q" {
			m.quitting = true
			return m, tea.Quit
		}
		if msg.Type == tea.KeyEsc {
			return m.back(), nil
		}
		switch m.screen {
		case screenMain:
			return m.updateMain(msg)
		case screenClients:
			return m.updateClients(msg)
		case screenInbounds:
			return m.updateInbounds(msg)
		case screenExport:
			return m.updateExport(msg)
		}
	}
	return m, nil
}

func (m model) updateInput(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key.Type {
	case tea.KeyEnter:
		val := strings.TrimSpace(m.input.Value())
		if val == "" {
			val = m.steps[len(m.stepVals)].fallback
		}
		if val == "" {
			m.message = "a value is required"
			return m, nil
		}
		m.stepVals = append(m.stepVals, val)
		m.input.Reset()
		if len(m.stepVals) == len(m.steps) {
			return m.finishFlow()
		}
		m.input.placeholder = m.steps[len(m.stepVals)].placeholder
		return m, nil
	case tea.KeyEsc:
		m.steps, m.stepVals = nil, nil
		m.input.Reset()
		m.message = "cancelled"
		return m, nil
	}
	m.input.Update(key)
	return m, nil
}

func (m model) finishFlow() (tea.Model, tea.Cmd) {
	first, vals := m.steps[0].kind, m.stepVals
	m.steps, m.stepVals = nil, nil
	m.input.Reset()

	switch first {
	case kindClientID:
		if err := m.store.AddClient(vals[0]); err != nil {
			m.message = err.Error()
			return m, nil
		}
		m.message = "client " + vals[0] + " added (save to keep it)"
		m.rebuildClients()
	case kindInboundID:
		if err := m.store.AddInbound(vals[0], vals[1], vals[2]); err != nil {
			m.message = err.Error()
			return m, nil
		}
		m.message = "inbound " + vals[0] + " added (save to keep it)"
		m.rebuildInbounds()
	case kindInitHost:
		dir := filepath.Dir(m.path)
		if err := Init(dir, vals[0], vals[1]); err != nil {
			m.fatal = err
			return m, tea.Quit
		}
		store, err := Load(m.path)
		if err != nil {
			m.fatal = err
			return m, tea.Quit
		}
		m.store = store
		m.needsInit = false
		m.message = "deployment created in " + dir
		m.screen = screenMain
		m.rebuildMain()
	}
	return m, nil
}

func (m model) back() model {
	switch m.screen {
	case screenExport:
		m.screen = screenClients
		m.rebuildClients()
	case screenClients, screenInbounds:
		m.screen = screenMain
		m.rebuildMain()
	}
	return m
}

func (m model) updateMain(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key.Type {
	case tea.KeyUp, tea.KeyShiftTab:
		m.list.up()
	case tea.KeyDown, tea.KeyTab:
		m.list.down()
	case tea.KeyEnter, tea.KeySpace:
		switch m.list.selected().id {
		case "clients":
			m.screen = screenClients
			m.rebuildClients()
		case "inbounds":
			m.screen = screenInbounds
			m.rebuildInbounds()
		case "save":
			if err := m.store.Save(); err != nil {
				m.message = err.Error()
				return m, nil
			}
			m.quitting = true
			return m, tea.Quit
		case "quit":
			m.quitting = true
			return m, tea.Quit
		}
	}
	return m, nil
}

// navigate moves the list selection. Returns true when the key was used.
func (m model) navigate(key tea.KeyMsg) (model, bool) {
	switch key.Type {
	case tea.KeyUp, tea.KeyShiftTab:
		m.list.up()
		return m, true
	case tea.KeyDown, tea.KeyTab:
		m.list.down()
		return m, true
	}
	return m, false
}

func (m model) updateClients(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m, used := m.navigate(key); used {
		return m, nil
	}
	switch key.String() {
	case "a":
		m.steps = []inputStep{{
			kind:        kindClientID,
			prompt:      "client id",
			placeholder: "e.g. alice",
		}}
		m.input = textInput{placeholder: "e.g. alice"}
	case "d":
		if id := m.list.selected().id; id != "" {
			if m.store.RemoveClient(id) {
				m.message = "client " + id + " removed (save to keep it)"
				m.rebuildClients()
			}
		}
	case "e":
		if len(m.store.Inbounds()) == 0 {
			m.message = "no inbound configured"
			return m, nil
		}
		m.exportFor = m.list.selected().id
		m.screen = screenExport
		m.rebuildExport()
	}
	return m, nil
}

func (m model) updateInbounds(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m, used := m.navigate(key); used {
		return m, nil
	}
	switch key.String() {
	case "a":
		m.steps = []inputStep{
			{kind: kindInboundID, prompt: "inbound id", placeholder: "e.g. second"},
			{kind: kindInboundDomain, prompt: "domain (SNI)", placeholder: "cdn.example.com"},
			{kind: kindInboundListen, prompt: "listen address", placeholder: ":443", fallback: ":443"},
		}
		m.input = textInput{placeholder: m.steps[0].placeholder}
	case "d":
		if id := m.list.selected().id; id != "" {
			if m.store.RemoveInbound(id) {
				m.message = "inbound " + id + " removed (save to keep it)"
				m.rebuildInbounds()
			}
		}
	}
	return m, nil
}

func (m model) updateExport(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m, used := m.navigate(key); used {
		return m, nil
	}
	switch key.Type {
	case tea.KeyEnter, tea.KeySpace:
		ib := m.list.selected().id
		out, err := m.store.ExportClient(m.exportFor, ib)
		if err != nil {
			m.message = err.Error()
		} else {
			m.message = "wrote " + out
		}
		m.screen = screenClients
		m.rebuildClients()
	}
	return m, nil
}

// ---------- list building ----------

func (m *model) rebuildMain() {
	m.list = list{items: []listItem{
		{id: "clients", text: fmt.Sprintf("Clients (%d)", len(m.store.ClientIDs()))},
		{id: "inbounds", text: fmt.Sprintf("Inbounds (%d)", len(m.store.Inbounds()))},
		{id: "save", text: "Save & exit"},
		{id: "quit", text: "Quit without saving"},
	}}
}

func (m *model) rebuildClients() {
	var items []listItem
	for _, id := range m.store.ClientIDs() {
		psk, _ := m.store.PSK(id)
		items = append(items, listItem{
			id:   id,
			text: fmt.Sprintf("%-12s psk:%s…", id, psk[:8]),
		})
	}
	m.list = list{items: items}
}

func (m *model) rebuildInbounds() {
	var items []listItem
	for _, in := range m.store.Inbounds() {
		items = append(items, listItem{
			id:   in.ID,
			text: fmt.Sprintf("%-10s %-12s %s", in.ID, in.Listen, in.Domain),
		})
	}
	m.list = list{items: items}
}

func (m *model) rebuildExport() {
	var items []listItem
	for _, in := range m.store.Inbounds() {
		items = append(items, listItem{
			id:   in.ID,
			text: fmt.Sprintf("%-10s %s", in.ID, in.Domain),
		})
	}
	m.list = list{items: items}
}

// ---------- rendering ----------

func (m model) View() string {
	if m.fatal != nil {
		return fmt.Sprintf("error: %v\n", m.fatal)
	}
	var b strings.Builder
	b.WriteString(titleStyle.Render("Mirage admin"))
	b.WriteString("\n")
	if m.store != nil {
		b.WriteString(hintStyle.Render("config: " + m.path))
		b.WriteString("\n\n")
	} else {
		b.WriteString(hintStyle.Render("no config yet — answering a few questions creates one"))
		b.WriteString("\n\n")
	}

	if len(m.steps) > 0 {
		step := m.steps[len(m.stepVals)]
		b.WriteString(step.prompt + ":\n")
		b.WriteString(m.input.View())
		b.WriteString("\n")
		if step.fallback != "" {
			b.WriteString(hintStyle.Render("(empty = " + step.fallback + ")"))
			b.WriteString("\n")
		}
	} else {
		switch m.screen {
		case screenMain:
			b.WriteString(m.listView("Main menu"))
		case screenClients:
			b.WriteString(m.listView("Clients"))
		case screenInbounds:
			b.WriteString(m.listView("Inbounds"))
		case screenExport:
			b.WriteString(m.listView("Export client " + m.exportFor + " via"))
		}
	}

	if m.message != "" {
		style := okStyle
		if strings.HasPrefix(m.message, "admin:") || strings.Contains(m.message, "error") {
			style = errStyle
		}
		b.WriteString("\n" + style.Render(m.message) + "\n")
	}
	if !m.quitting {
		b.WriteString("\n" + hintStyle.Render(m.hints()) + "\n")
	}
	return b.String()
}

func (m model) hints() string {
	if len(m.steps) > 0 {
		return "enter confirm · esc cancel · ctrl-c abort"
	}
	switch m.screen {
	case screenMain:
		return "↑↓ move · enter open · q quit"
	case screenClients:
		return "a add · d delete · e export config · esc back · q quit"
	case screenInbounds:
		return "a add · d delete · esc back · q quit"
	case screenExport:
		return "↑↓ move · enter choose · esc back · q quit"
	}
	return ""
}

func (m model) listView(title string) string {
	var b strings.Builder
	b.WriteString(title + "\n")
	if len(m.list.items) == 0 {
		b.WriteString(hintStyle.Render("(none — press a to add)") + "\n")
		return b.String()
	}
	for i, it := range m.list.items {
		line := "  " + it.text
		if i == m.list.index {
			line = selStyle.Render("> " + it.text)
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}
