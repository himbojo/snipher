package ui

import (
	"crypto/tls"
	"fmt"
	"snipher/internal/engine"
	"snipher/internal/models"
	"sort"
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
	colorOrange  = lipgloss.Color("#FF8800") // Better accessibility than Yellow
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
			Foreground(colorOrange)

	styleCrit = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorRed)

	styleVulnTag = lipgloss.NewStyle().
			Background(colorRed).
			Foreground(colorWhite).
			Bold(true).
			Padding(0, 1)

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

	statusStr := "🔒 TRUSTED"
	statusStyle := styleSecure
	if daysRemaining < 0 {
		statusStr = "⚠ EXPIRED"
		statusStyle = styleCrit
	} else if !res.IsTrusted {
		statusStr = "✗ UNTRUSTED"
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

// GetCipherDisplayStatus returns the security icon and style for a cipher
func GetCipherDisplayStatus(cipher string) (string, lipgloss.Style) {
	lower := strings.ToLower(cipher)

	// CRITICAL: Broken or Dangerous ciphers
	if strings.Contains(lower, "null") || strings.Contains(lower, "md5") ||
		strings.Contains(lower, "rc4") || strings.Contains(lower, "3des") ||
		strings.Contains(lower, "des") || strings.Contains(lower, "export") ||
		strings.Contains(lower, "anon") {
		return "⊘", styleCrit // Use circle with line (⊘) for critical/broken
	}

	// WARNING: Weak ciphers (CBC)
	if strings.Contains(lower, "cbc") {
		return "⚠", styleWarn
	}

	// SECURE
	return "", styleSecure // Empty string for secure ciphers (no issues)
}

// RenderProtocolMatrix displays the supported protocols in a table-like format
func RenderProtocolMatrix(res models.ScanResult, verbose bool) {
	title := render(styleTitle, "PROTOCOL MATRIX")
	if IsCI() {
		fmt.Println("PROTOCOL MATRIX")
		fmt.Println("===============")
		fmt.Println()
	}

	var rows []string
	header := lipgloss.JoinHorizontal(lipgloss.Left,
		lipgloss.NewStyle().Width(15).Foreground(colorWhite).Bold(true).Render("PROTOCOL"),
		lipgloss.NewStyle().Foreground(colorWhite).Bold(true).Render("STATUS"),
	)
	if IsCI() {
		header = fmt.Sprintf("%-15s %s", "PROTOCOL", "STATUS")
	}

	rows = []string{header}
	if !IsCI() {
		rows = []string{header, render(styleChain, strings.Repeat("═", 40))}
	} else {
		rows = []string{header, strings.Repeat("=", 40)}
	}

	// map to track unique vulnerabilities for the notes section
	vulnMap := make(map[string]engine.Vulnerability)

	for i, p := range res.Protocols {
		// Add separator between protocols (but not before the first one)
		if i > 0 {
			sep := render(lipgloss.NewStyle().Foreground(colorDim), strings.Repeat("─", 40))
			if IsCI() {
				sep = strings.Repeat("-", 40)
			}
			rows = append(rows, sep)
		}

		status := render(styleSecure, "🔒 SECURE")
		if !p.Supported {
			status = render(styleSubValue.Copy().Faint(true), "─ DISABLED")
		} else if p.Name == "TLS 1.0" || p.Name == "TLS 1.1" {
			// Mark old protocols as WARNING even if enabled (technically they are insecure)
			status = render(styleWarn, "🔓 WEAK")
		}

		row := lipgloss.JoinHorizontal(lipgloss.Left,
			lipgloss.NewStyle().Width(15).Foreground(colorWhite).Render(p.Name),
			status,
		)
		if IsCI() {
			statusText := "SECURE"
			if !p.Supported {
				statusText = "DISABLED"
			} else if p.Name == "TLS 1.0" || p.Name == "TLS 1.1" {
				statusText = "WEAK"
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

				// Front indicator: enabled or not
				frontInd := "✗"
				if isEnabled {
					frontInd = "✓"
				}

				// Security status (after name)
				secInd, cipherStyle := GetCipherDisplayStatus(cipher)
				if !isEnabled {
					cipherStyle = styleSubValue.Copy().Faint(true)
				}

				// Check for vulnerabilities
				vulns := engine.GetCipherVulnerabilities(cipher)
				vulnLabels := ""
				for _, v := range vulns {
					vulnLabels += fmt.Sprintf(" %s", render(styleVulnTag, v.Label))
					vulnMap[v.ID] = v
				}

				if secInd != "" {
					secInd = " " + secInd
				}

				cipherRow := fmt.Sprintf("  %s %s%s%s", frontInd, render(cipherStyle, cipher), secInd, vulnLabels)
				rows = append(rows, cipherRow)
			}
		} else {
			// Default mode: only show enabled ciphers
			if p.Supported && len(p.Ciphers) > 0 {
				for i, cipher := range p.Ciphers {
					prefix := "    ├─"
					if i == len(p.Ciphers)-1 {
						prefix = "    └─"
					}
					// Use shared logic for security status (after name)
					secInd, cStyle := GetCipherDisplayStatus(cipher)

					vulns := engine.GetCipherVulnerabilities(cipher)
					vulnLabels := ""
					for _, v := range vulns {
						vulnLabels += fmt.Sprintf(" %s", render(styleVulnTag, v.Label))
						vulnMap[v.ID] = v
					}

					if secInd != "" {
						secInd = " " + secInd
					}

					cipherRow := fmt.Sprintf("%s %s%s%s", prefix, render(cStyle, cipher), secInd, vulnLabels)
					rows = append(rows, cipherRow)
				}
			}
		}
	}

	// Render Vulnerability Notes
	if len(vulnMap) > 0 {
		rows = append(rows, RenderVulnerabilitySection(vulnMap)...)
	}

	// Inject Legend at the top if not CI
	if !IsCI() {
		legend := GetLegend()
		// Add legend and a separator/spacer
		rows = append([]string{legend, strings.Repeat(" ", 40)}, rows...)
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

	// Render Vulnerability Notes

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

// GetLegend returns the formatted legend string
func GetLegend() string {
	if IsCI() {
		return ""
	}

	// Define legend items
	items := []struct {
		symbol string
		desc   string
		style  lipgloss.Style
	}{
		{"🔒", "Secure", styleSecure},
		{"🔓", "Weak", styleWarn},
		{"⚠", "Warning", styleWarn},
		{"⊘", "Critical", styleCrit},
		{"✓", "Enabled", styleSecure},
		{"✗", "Disabled", styleSubValue.Copy().Faint(true)},
	}

	var nodes []string
	for _, item := range items {
		nodes = append(nodes, fmt.Sprintf("%s %s", render(item.style, item.symbol), render(styleSubValue, item.desc)))
	}

	// Join horizontally with spacing
	return lipgloss.JoinHorizontal(lipgloss.Top, strings.Join(nodes, "   "))
}

// RenderVulnerabilityCard creates a stylized card for a vulnerability
func RenderVulnerabilityCard(v engine.Vulnerability) string {
	if IsCI() {
		// Plain text fallback
		return fmt.Sprintf("VULN: %s [%s]\n  %s\n  Link: %s", v.Label, v.Severity, v.Description, v.URL)
	}

	// Determine color based on severity
	borderColor := colorDim
	titleColor := colorWhite
	switch strings.ToLower(v.Severity) {
	case "critical":
		borderColor = colorRed
		titleColor = colorRed
	case "high":
		borderColor = colorOrange
		titleColor = colorOrange
	case "medium":
		borderColor = colorMagenta
		titleColor = colorMagenta
	}

	// Styles
	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(borderColor).
		Padding(0, 1).
		Margin(0, 0, 1, 0).
		Width(60)

	titleStyle := lipgloss.NewStyle().Foreground(titleColor).Bold(true)
	headerStyle := lipgloss.NewStyle().Foreground(colorCyan).Bold(true).Width(14)
	valueStyle := lipgloss.NewStyle().Foreground(colorWhite)

	// Content Construction

	// Header Line: Label [SEVERITY]
	headerLine := fmt.Sprintf("%s [%s]", titleStyle.Render(v.Label), strings.ToUpper(v.Severity))

	// Body Lines
	body := []string{
		fmt.Sprintf("%s %s", headerStyle.Render("Quick Ref:"), valueStyle.Render(v.Description)),
		fmt.Sprintf("%s %s", headerStyle.Render("Risk Rating:"), valueStyle.Render(v.RiskRating)),
		fmt.Sprintf("%s %s", headerStyle.Render("Risk Detail:"), valueStyle.Render(v.Risk)),
		fmt.Sprintf("%s %s", headerStyle.Render("Impact Rating:"), valueStyle.Render(v.ImpactRating)),
		fmt.Sprintf("%s %s", headerStyle.Render("Impact Detail:"), valueStyle.Render(v.Impact)),
		fmt.Sprintf("%s %s", headerStyle.Render("Exploited:"), valueStyle.Render(v.Exploited)),
		fmt.Sprintf("%s %s", headerStyle.Render("CVE:"), lipgloss.NewStyle().Foreground(colorCyan).Underline(true).Render(v.URL)),
	}

	if v.ExploitURL != "" {
		body = append(body, fmt.Sprintf("%s %s", headerStyle.Render("Exploit Ref:"), lipgloss.NewStyle().Foreground(colorCyan).Underline(true).Render(v.ExploitURL)))
	}

	content := lipgloss.JoinVertical(lipgloss.Left,
		headerLine,
		strings.Repeat("─", 58), // Separator
		lipgloss.JoinVertical(lipgloss.Left, body...),
	)

	return boxStyle.Render(content)
}

// RenderVulnerabilitySection returns a slice of formatted strings for vulnerabilities
func RenderVulnerabilitySection(vulnMap map[string]engine.Vulnerability) []string {
	if len(vulnMap) == 0 {
		return nil
	}

	var rows []string
	rows = append(rows, "", render(styleTitle, "VULNERABILITY DOSSIERS"))

	sep := strings.Repeat("─", 60)
	if IsCI() {
		sep = strings.Repeat("-", 60)
	}
	rows = append(rows, render(styleChain, sep))

	// Sort IDs for deterministic output
	ids := make([]string, 0, len(vulnMap))
	for id := range vulnMap {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		rows = append(rows, RenderVulnerabilityCard(vulnMap[id]))
	}
	return rows
}
