package ui

import (
	"crypto/tls"
	"fmt"
	"snipher/internal/engine"
	"snipher/internal/models"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

var (
	styleTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1).
			MarginBottom(1)

	styleLabel = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888")).
			Width(12)

	styleValue = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF"))

	styleSubValue = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#AAAAAA"))

	styleWarn = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFF00"))

	styleCrit = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FF0000"))

	styleChain = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7D56F4")).
			Faint(true)

	styleCard = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#7D56F4")).
			Padding(1, 2).
			Margin(1, 0)
)

// render applies styling only if not in CI mode
func render(style lipgloss.Style, text string) string {
	if IsCI() {
		return text
	}
	return style.Render(text)
}

// RenderVitalsCard displays a summary of the connection and target status
func RenderVitalsCard(res models.ScanResult, showSans bool) {
	title := render(styleTitle, "VITALS CARD")

	// Max width for text content within the card
	const maxTextWidth = 60
	const indent = "  "

	ipRow := fmt.Sprintf("%s %s", render(styleLabel, "IP:"), render(styleValue, res.IP))
	targetRow := fmt.Sprintf("%s %s", render(styleLabel, "Target:"), render(styleValue, res.Target))
	portRow := fmt.Sprintf("%s %d", render(styleLabel, "Port:"), res.Port)
	latencyRow := fmt.Sprintf("%s %s", render(styleLabel, "Latency:"), render(styleValue, res.Latency.String()))

	// Certificate Info Section
	// Remove width constraint for header to prevent colon wrapping
	certHeader := styleLabel.Copy().Width(0).Render("Certificates:")
	if IsCI() {
		certHeader = "Certificates:"
	}

	// Indented Attributes
	// Wrap Subject (CN)
	wrappedSubject := res.Subject
	if !IsCI() {
		wrappedSubject = lipgloss.NewStyle().Width(maxTextWidth).Render(res.Subject)
	}
	cnRow := fmt.Sprintf("%s%s %s", indent, render(styleLabel, "CN:"), render(styleValue, wrappedSubject))

	serialRow := fmt.Sprintf("%s%s %s", indent, render(styleLabel, "Serial:"), render(styleValue, res.SerialNumber))

	sans := ""
	if showSans && len(res.DNSNames) > 0 {
		sansList := fmt.Sprintf("%v", res.DNSNames)
		wrappedSans := sansList
		if !IsCI() {
			wrappedSans = lipgloss.NewStyle().Width(maxTextWidth).Render(sansList)
		}
		sans = fmt.Sprintf("%s%s %s", indent, render(styleLabel, "SANs:"), render(styleSubValue, wrappedSans))
	}

	expiryStr := res.NotAfter.Format("2006-01-02")
	expiryStyle := styleValue

	daysRemaining := time.Until(res.NotAfter).Hours() / 24
	if daysRemaining < 0 {
		expiryStyle = styleCrit
	} else if daysRemaining < 30 {
		expiryStyle = styleWarn
	}

	expiryRow := fmt.Sprintf("%s%s %s", indent, render(styleLabel, "Expires:"), render(expiryStyle, expiryStr))

	statusStr := "Trusted"
	statusStyle := styleValue
	if daysRemaining < 0 {
		statusStr = "EXPIRED"
		statusStyle = styleCrit
	} else if !res.IsTrusted {
		statusStr = "Untrusted"
		statusStyle = styleCrit
	}
	statusRow := fmt.Sprintf("%s%s %s", indent, render(styleLabel, "Status:"), render(statusStyle, statusStr))

	// Trust Chain Visualization
	chainHeader := fmt.Sprintf("%s%s", indent, render(styleLabel, "Chain:"))
	chainRows := []string{chainHeader}
	for i, c := range res.Chain {
		prefix := "    ├─"
		if i == len(res.Chain)-1 {
			prefix = "    └─"
		}
		if i == 0 {
			prefix = "    ● "
		}

		cStyle := styleSubValue
		// Include Serial Number in parentheses for the chain
		label := fmt.Sprintf("%s (%s)", c.Subject, c.SerialNumber)

		if c.IsAnchor {
			label = fmt.Sprintf("%s (ANCHOR)", label)
			cStyle = styleValue // Bold/White for anchor
		}

		// Wrap long subject names in the chain too
		wrappedLabel := label
		if !IsCI() {
			wrappedLabel = lipgloss.NewStyle().Width(maxTextWidth - 6).Render(label)
		}
		// Handle multi-line wrapping in the chain by prefixing each line
		lines := strings.Split(wrappedLabel, "\n")
		for k, line := range lines {
			if k == 0 {
				chainRows = append(chainRows, fmt.Sprintf("%s%s", render(styleChain, prefix), render(cStyle, line)))
			} else {
				nodeIndent := "      "
				chainRows = append(chainRows, fmt.Sprintf("%s%s", nodeIndent, render(cStyle, line)))
			}
		}
	}

	rows := []string{
		targetRow,
		ipRow,
		portRow,
		latencyRow,
		"",
		certHeader,
		cnRow,
		serialRow,
	}
	if sans != "" {
		rows = append(rows, sans)
	}
	rows = append(rows, expiryRow, statusRow, "")
	rows = append(rows, chainRows...)

	content := lipgloss.JoinVertical(lipgloss.Left, rows...)

	// Apply card styling only if not in CI mode
	output := lipgloss.JoinVertical(lipgloss.Left, title, content)
	if !IsCI() {
		output = styleCard.Render(output)
	} else {
		// In CI mode, add simple border
		output = fmt.Sprintf("\n%s\n%s\n%s\n", strings.Repeat("=", 50), output, strings.Repeat("=", 50))
	}

	fmt.Println(output)
}

// RenderCapabilityTable displays the supported protocols in a table-like format
func RenderCapabilityTable(res models.ScanResult, verbose bool) {
	title := render(styleTitle, "CAPABILITY TABLE")

	headerCol1 := render(styleLabel, "PROTOCOL")
	headerCol2 := render(styleLabel, "STATUS")

	header := lipgloss.JoinHorizontal(lipgloss.Left,
		lipgloss.NewStyle().Width(15).Render(headerCol1),
		headerCol2,
	)
	if IsCI() {
		header = fmt.Sprintf("%-15s %s", "PROTOCOL", "STATUS")
	}

	rows := []string{header, render(styleChain, strings.Repeat("─", 30))}
	if IsCI() {
		rows = []string{header, strings.Repeat("-", 30)}
	}

	for _, p := range res.Protocols {
		status := render(styleValue, "Enabled")
		if !p.Supported {
			status = render(styleSubValue, "Disabled")
		}

		row := lipgloss.JoinHorizontal(lipgloss.Left,
			lipgloss.NewStyle().Width(15).Render(p.Name),
			status,
		)
		if IsCI() {
			statusText := "Enabled"
			if !p.Supported {
				statusText = "Disabled"
			}
			row = fmt.Sprintf("%-15s %s", p.Name, statusText)
		}
		rows = append(rows, row)

		// Display ciphers
		if verbose && p.Supported {
			// In verbose mode, show ALL possible ciphers with status indicators
			// But only for enabled protocols
			allCiphers := engine.GetAllCiphersForProtocol(getVersionForProtocol(p.Name))
			for _, cipher := range allCiphers {
				isEnabled := false
				for _, enabledCipher := range p.Ciphers {
					if enabledCipher == cipher {
						isEnabled = true
						break
					}
				}

				cipherStyle := styleSubValue
				statusIndicator := "✗"

				if isEnabled {
					// Highlight weak ciphers even when enabled
					cipherLower := strings.ToLower(cipher)
					if strings.Contains(cipherLower, "rc4") ||
						strings.Contains(cipherLower, "des") ||
						strings.Contains(cipherLower, "md5") ||
						strings.Contains(cipherLower, "null") {
						cipherStyle = styleWarn
					} else {
						cipherStyle = styleValue
					}
					statusIndicator = "✓"
				}

				cipherRow := fmt.Sprintf("  %s %s", statusIndicator, render(cipherStyle, cipher))
				rows = append(rows, cipherRow)
			}
		} else {
			// Default mode: only show enabled ciphers
			if p.Supported && len(p.Ciphers) > 0 {
				for i, cipher := range p.Ciphers {
					cipherStyle := styleSubValue
					// Highlight weak ciphers
					cipherLower := strings.ToLower(cipher)
					if strings.Contains(cipherLower, "rc4") ||
						strings.Contains(cipherLower, "des") ||
						strings.Contains(cipherLower, "md5") ||
						strings.Contains(cipherLower, "null") {
						cipherStyle = styleWarn
					}

					// Use └─ for last cipher, ├─ for others
					prefix := "├─"
					if i == len(p.Ciphers)-1 {
						prefix = "└─"
					}

					cipherRow := fmt.Sprintf("  %s %s", prefix, render(cipherStyle, cipher))
					rows = append(rows, cipherRow)
				}
			}
		}
	}

	content := lipgloss.JoinVertical(lipgloss.Left, rows...)

	// Apply card styling only if not in CI mode
	output := lipgloss.JoinVertical(lipgloss.Left, title, content)
	if !IsCI() {
		output = styleCard.Render(output)
	} else {
		// In CI mode, add simple border
		output = fmt.Sprintf("\n%s\n%s\n%s\n", strings.Repeat("=", 50), output, strings.Repeat("=", 50))
	}

	fmt.Println(output)
}

// getVersionForProtocol maps protocol names to tls.Version constants
func getVersionForProtocol(name string) uint16 {
	switch name {
	case "TLS 1.0":
		return tls.VersionTLS10
	case "TLS 1.1":
		return tls.VersionTLS11
	case "TLS 1.2":
		return tls.VersionTLS12
	case "TLS 1.3":
		return tls.VersionTLS13
	default:
		return 0
	}
}
