package ui

import "github.com/charmbracelet/lipgloss"

// Theme defines the color palette for the UI
type Theme struct {
	Name       string
	Title      lipgloss.Color
	Label      lipgloss.Color
	Value      lipgloss.Color
	SubValue   lipgloss.Color
	Warning    lipgloss.Color
	Critical   lipgloss.Color
	Secure     lipgloss.Color
	Dim        lipgloss.Color
	Border     lipgloss.Color
	TagText    lipgloss.Color // Text color for tags
	BgCritical lipgloss.Color
	BgHigh     lipgloss.Color
	BgMedium   lipgloss.Color
	BgLow      lipgloss.Color
	BgPolicy   lipgloss.Color
}

var (
	// CurrentTheme holds the active theme
	CurrentTheme = DefaultTheme

	// Predefined Themes
	DefaultTheme = Theme{
		Name:       "default",
		Title:      lipgloss.Color("#00FFFF"), // Cyan
		Label:      lipgloss.Color("#FF00FF"), // Magenta
		Value:      lipgloss.Color("#FFFFFF"), // White
		SubValue:   lipgloss.Color("#00FFFF"), // Cyan
		Warning:    lipgloss.Color("#FF8800"), // Orange
		Critical:   lipgloss.Color("#FF0000"), // Red
		Secure:     lipgloss.Color("#00FF00"), // Lime
		Dim:        lipgloss.Color("#444444"), // Dim Grey
		Border:     lipgloss.Color("#00FFFF"), // Cyan
		TagText:    lipgloss.Color("#FFFFFF"),
		BgCritical: lipgloss.Color("#880000"),
		BgHigh:     lipgloss.Color("#AA5500"),
		BgMedium:   lipgloss.Color("#990099"),
		BgLow:      lipgloss.Color("#000088"),
		BgPolicy:   lipgloss.Color("#006666"),
	}

	NoColorTheme = Theme{
		Name:       "no-color",
		Title:      lipgloss.Color(""),
		Label:      lipgloss.Color(""),
		Value:      lipgloss.Color(""),
		SubValue:   lipgloss.Color(""),
		Warning:    lipgloss.Color(""),
		Critical:   lipgloss.Color(""),
		Secure:     lipgloss.Color(""),
		Dim:        lipgloss.Color(""),
		Border:     lipgloss.Color(""),
		TagText:    lipgloss.Color(""),
		BgCritical: lipgloss.Color(""),
		BgHigh:     lipgloss.Color(""),
		BgMedium:   lipgloss.Color(""),
		BgLow:      lipgloss.Color(""),
		BgPolicy:   lipgloss.Color(""),
	}

	// DarkTheme is similar to Default but maybe different contrast if needed.
	// For now, Default IS a Dark mode theme (Neon).
	DarkTheme = DefaultTheme

	LightTheme = Theme{
		Name:       "light",
		Title:      lipgloss.Color("#000088"), // Dark Blue
		Label:      lipgloss.Color("#880088"), // Purple
		Value:      lipgloss.Color("#000000"), // Black
		SubValue:   lipgloss.Color("#000088"), // Dark Blue
		Warning:    lipgloss.Color("#BB5500"), // Dark Orange
		Critical:   lipgloss.Color("#CC0000"), // Dark Red
		Secure:     lipgloss.Color("#008800"), // Dark Green
		Dim:        lipgloss.Color("#AAAAAA"), // Light Grey
		Border:     lipgloss.Color("#000088"), // Dark Blue
		TagText:    lipgloss.Color("#FFFFFF"), // Tags still need standard contrast
		BgCritical: lipgloss.Color("#CC0000"),
		BgHigh:     lipgloss.Color("#DD6600"),
		BgMedium:   lipgloss.Color("#AA00AA"),
		BgLow:      lipgloss.Color("#0000AA"),
		BgPolicy:   lipgloss.Color("#008888"),
	}
)

// SetTheme sets the global CurrentTheme based on name
func SetTheme(name string) {
	switch name {
	case "no-color", "none":
		CurrentTheme = NoColorTheme
	case "light":
		CurrentTheme = LightTheme
	case "dark":
		CurrentTheme = DarkTheme
	default:
		CurrentTheme = DefaultTheme
	}
}
