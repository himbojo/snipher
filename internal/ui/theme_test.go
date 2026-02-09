package ui

import (
	"testing"
)

func TestSetTheme(t *testing.T) {
	// Test Default
	SetTheme("default")
	if CurrentTheme.Name != "default" {
		t.Errorf("Expected default theme, got %s", CurrentTheme.Name)
	}

	// Test Dark
	SetTheme("dark")
	// Dark theme is currently alias for default
	if CurrentTheme.Name != "default" {
		t.Errorf("Expected default theme (for dark), got %s", CurrentTheme.Name)
	}

	// Test Light
	SetTheme("light")
	if CurrentTheme.Name != "light" {
		t.Errorf("Expected light theme, got %s", CurrentTheme.Name)
	}

	// Test NoColor
	SetTheme("no-color")
	if CurrentTheme.Name != "no-color" {
		t.Errorf("Expected no-color theme, got %s", CurrentTheme.Name)
	}
	// Verify actual color values being empty/no-color-ish?
	// The implementation uses distinct colors, but for NoColor we expect effectively empty or transparent?
	// lipgloss.Color("") is NoColor.
	// But let's just check the name for now as the logic is simple map lookup.
}

func TestGetStyles(t *testing.T) {
	SetTheme("default")
	styles := GetStyles()

	if styles.Title.GetForeground() != CurrentTheme.Title {
		t.Error("Title style foreground mismatch")
	}
}
