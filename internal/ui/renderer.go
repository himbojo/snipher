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
	// Neon Palette
	colorCyan    = lipgloss.Color("#00FFFF")
	colorMagenta = lipgloss.Color("#FF00FF")
	colorLime    = lipgloss.Color("#00FF00")
	colorRed     = lipgloss.Color("#FF0000")
	colorWhite   = lipgloss.Color("#FFFFFF")
	colorDim     = lipgloss.Color("#444444")

	styleTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorCyan).
			Border(lipgloss.DoubleBorder(), false, false, true, false).
			BorderForeground(colorCyan).
			MarginBottom(1).
			Padding(0, 1)

	styleLabel = lipgloss.NewStyle().
			Foreground(colorMagenta).
			Width(14).
			Bold(true)

	styleValue = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorWhite)

	styleSubValue = lipgloss.NewStyle().
			Foreground(colorCyan)

	styleWarn = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFF00"))

	styleCrit = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorRed)

	styleSecure = lipgloss.NewStyle().
			Foreground(colorLime)

	styleChain = lipgloss.NewStyle().
			Foreground(colorMagenta).
			Bold(true)

	styleCard = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(colorCyan).
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

// RenderTargetIntelligence displays a summary of the connection and target status
func RenderTargetIntelligence(res models.ScanResult, showSans bool) {
	title := render(styleTitle, "TARGET INTELLIGENCE")

	// Max width for text content within the card
	const maxTextWidth = 60
	const indent = "  "

	ipRow := fmt.Sprintf("%s %s", render(styleLabel, "HOST IP"), render(styleValue, res.IP))
	targetRow := fmt.Sprintf("%s %s", render(styleLabel, "TARGET HOST"), render(styleValue, res.Target))
	portRow := fmt.Sprintf("%s %d", render(styleLabel, "TARGET PORT"), res.Port)
	latencyRow := fmt.Sprintf("%s %s", render(styleLabel, "LATENCY"), render(styleValue, res.Latency.String()))

	rows := []string{
		targetRow,
		ipRow,
		portRow,
		latencyRow,
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

// RenderCertificateIdentity displays certificate chain and validity info
func RenderCertificateIdentity(res models.ScanResult, showSans bool) {
	styleTitle.SetString("CERTIFICATE IDENTITY")
	title := render(styleTitle, "CERTIFICATE IDENTITY")

	const maxTextWidth = 60
	const indent = "  "

	// Certificate Info Section
	wrappedSubject := res.Subject
	if !IsCI() {
		wrappedSubject = lipgloss.NewStyle().Width(maxTextWidth).Render(res.Subject)
	}
	cnRow := fmt.Sprintf("%s %s", render(styleLabel, "COMMON NAME"), render(styleValue, wrappedSubject))

	serialRow := fmt.Sprintf("%s %s", render(styleLabel, "SERIAL NUM"), render(styleValue, res.SerialNumber))

	rows := []string{cnRow, serialRow}

	if showSans && len(res.DNSNames) > 0 {
		sansHeader := render(styleLabel, "SANs")
		rows = append(rows, sansHeader)

		for _, san := range res.DNSNames {
			wrappedSan := san
			if !IsCI() {
				// Truncate or wrap if too long (optional, keeping simple for now)
			}
			rows = append(rows, fmt.Sprintf("%s%s", "    ", render(styleSubValue, wrappedSan)))
		}
	} else if showSans {
		rows = append(rows, fmt.Sprintf("%s %s", render(styleLabel, "SANs"), render(styleSubValue, "(None)")))
	}

	expiryStr := res.NotAfter.Format("2006-01-02")
	expiryStyle := styleValue

	daysRemaining := time.Until(res.NotAfter).Hours() / 24
	if daysRemaining < 0 {
		expiryStyle = styleCrit
	} else if daysRemaining < 30 {
		expiryStyle = styleWarn
	}

	expiryRow := fmt.Sprintf("%s %s", render(styleLabel, "EXPIRES"), render(expiryStyle, expiryStr))

	statusStr := "TRUSTED"
	statusStyle := styleSecure
	if daysRemaining < 0 {
		statusStr = "EXPIRED"
		statusStyle = styleCrit
	} else if !res.IsTrusted {
		statusStr = "UNTRUSTED"
		statusStyle = styleCrit
	}
	statusRow := fmt.Sprintf("%s %s", render(styleLabel, "STATUS"), render(statusStyle, statusStr))

	// Trust Chain Visualization
	chainHeader := fmt.Sprintf("\n%s", render(styleLabel.Copy().Width(0).Foreground(colorCyan).Underline(true), "CERTIFICATE CHAIN"))
	if IsCI() {
		chainHeader = "\nCERTIFICATE CHAIN"
	}

	chainRows := []string{chainHeader}
	for i, c := range res.Chain {
		prefix := "  ├─"
		if i == len(res.Chain)-1 {
			prefix = "  └─"
		}
		if i == 0 {
			prefix = "  ● "
		}

		cStyle := styleSubValue
		// Include Serial Number in parentheses for the chain
		label := fmt.Sprintf("%s", c.Subject)

		if c.IsAnchor {
			label = fmt.Sprintf("%s [ANCHOR]", label)
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
				nodeIndent := "    "
				chainRows = append(chainRows, fmt.Sprintf("%s%s", nodeIndent, render(cStyle, line)))
			}
		}
	}

	rows = append(rows, "", expiryRow, statusRow)
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

// RenderProtocolMatrix displays the supported protocols in a table-like format
func RenderProtocolMatrix(res models.ScanResult, verbose bool) {
	title := render(styleTitle, "PROTOCOL MATRIX")

	headerCol1 := render(styleLabel, "PROTOCOL")
	headerCol2 := render(styleLabel, "STATUS")

	header := lipgloss.JoinHorizontal(lipgloss.Left,
		lipgloss.NewStyle().Width(15).Render(headerCol1),
		headerCol2,
	)
	if IsCI() {
		header = fmt.Sprintf("%-15s %s", "PROTOCOL", "STATUS")
	}

	rows := []string{header, render(styleChain, strings.Repeat("═", 40))}
	if IsCI() {
		rows = []string{header, strings.Repeat("=", 40)}
	}

	for _, p := range res.Protocols {
		status := render(styleSecure, "SECURE")
		if !p.Supported {
			status = render(styleSubValue.Copy().Faint(true), "DISABLED")
		} else if strings.Contains(p.Name, "SSL") || p.Name == "TLS 1.0" || p.Name == "TLS 1.1" {
			// Mark old protocols as WARNING even if enabled (technically they are insecure)
			status = render(styleWarn, "WEAK")
		}

		row := lipgloss.JoinHorizontal(lipgloss.Left,
			lipgloss.NewStyle().Width(15).Foreground(colorWhite).Render(p.Name),
			status,
		)
		if IsCI() {
			statusText := "SECURE"
			if !p.Supported {
				statusText = "DISABLED"
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
				severityLabel := ""

				if isEnabled {
					// Categorize cipher security level
					cipherLower := strings.ToLower(cipher)
					if strings.Contains(cipherLower, "null") || strings.Contains(cipherLower, "md5") {
						// Critically weak ciphers
						cipherStyle = styleCrit
						severityLabel = " [CRITICAL]"
					} else if strings.Contains(cipherLower, "rc4") || strings.Contains(cipherLower, "des") {
						// Weak ciphers
						cipherStyle = styleWarn
						severityLabel = " [WARNING]"
					} else {
						// Secure ciphers
						cipherStyle = styleSecure
					}
					statusIndicator = "✓"
				}

				cipherRow := fmt.Sprintf("  %s %s%s", statusIndicator, render(cipherStyle, cipher), severityLabel)
				rows = append(rows, cipherRow)
			}
		} else {
			// Default mode: only show enabled ciphers
			if p.Supported && len(p.Ciphers) > 0 {
				for i, cipher := range p.Ciphers {
					cipherStyle := styleSecure
					severityLabel := ""

					// Categorize cipher security level
					cipherLower := strings.ToLower(cipher)
					if strings.Contains(cipherLower, "null") || strings.Contains(cipherLower, "md5") {
						// Critically weak ciphers
						cipherStyle = styleCrit
						severityLabel = " [CRITICAL]"
					} else if strings.Contains(cipherLower, "rc4") || strings.Contains(cipherLower, "des") {
						// Weak ciphers
						cipherStyle = styleWarn
						severityLabel = " [WARNING]"
					}

					// Use └─ for last cipher, ├─ for others
					prefix := "├─"
					if i == len(p.Ciphers)-1 {
						prefix = "└─"
					}

					cipherRow := fmt.Sprintf("  %s %s%s", render(styleChain, prefix), render(cipherStyle, cipher), severityLabel)
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
