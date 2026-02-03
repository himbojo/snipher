package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ProgressMsg is sent when the scanner reports a new status
type ProgressMsg string

// ResultMsg is sent when the scan is complete
type ResultMsg struct{}

// ErrorMsg is sent when the scan fails
type ErrorMsg error

// ProgressModel holds the state for the interactive UI
type ProgressModel struct {
	spinner  spinner.Model
	message  string
	quitting bool
	err      error
}

var (
	textStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).Render // Cyan
	spinnerStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF00FF"))        // Magenta
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Render // Lime
)

// NewProgressModel creates a new progress model
func NewProgressModel() ProgressModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = spinnerStyle
	return ProgressModel{
		spinner: s,
		message: "Initializing...",
	}
}

func (m ProgressModel) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m ProgressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			m.quitting = true
			return m, tea.Quit
		}

	case ProgressMsg:
		m.message = string(msg)
		return m, nil

	case ResultMsg:
		m.quitting = true
		return m, tea.Quit

	case ErrorMsg:
		m.err = error(msg)
		m.quitting = true
		return m, tea.Quit

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m ProgressModel) View() string {
	if m.err != nil {
		return fmt.Sprintf("\n%s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render(fmt.Sprintf("Error: %v", m.err)))
	}
	if m.quitting {
		return ""
	}

	// Create a "cool" header/frame
	pad := strings.Repeat(" ", 2)
	spin := m.spinner.View()
	msg := textStyle(m.message)

	return fmt.Sprintf("\n%s%s %s\n", pad, spin, msg)
}
