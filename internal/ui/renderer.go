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

// Background Colors for Tags (Removed global vars)

const (
	// Layout Constants
	maxTextWidth             = 60
	indent                   = "  "
	separatorWidth           = 40
	vulnerabilityBorderWidth = 58
	vulnerabilityBoxWidth    = 60
)

// UIStyles holds all the lipgloss styles for the UI
type UIStyles struct {
	Title    lipgloss.Style
	Label    lipgloss.Style
	Value    lipgloss.Style
	SubValue lipgloss.Style
	Warning  lipgloss.Style
	Critical lipgloss.Style
	TagBase  lipgloss.Style
	Secure   lipgloss.Style
	Chain    lipgloss.Style
	Card     lipgloss.Style
}

// GetStyles returns the styles for the current theme
func GetStyles() UIStyles {
	t := CurrentTheme
	return UIStyles{
		Title: lipgloss.NewStyle().
			Bold(true).
			Foreground(t.Title).
			Border(lipgloss.DoubleBorder(), false, false, true, false).
			BorderForeground(t.Border).
			MarginBottom(1).
			Padding(0, 1),

		Label: lipgloss.NewStyle().
			Foreground(t.Label).
			Width(14).
			Bold(true),

		Value: lipgloss.NewStyle().
			Bold(true).
			Foreground(t.Value),

		SubValue: lipgloss.NewStyle().
			Foreground(t.SubValue),

		Warning: lipgloss.NewStyle().
			Bold(true).
			Foreground(t.Warning),

		Critical: lipgloss.NewStyle().
			Bold(true).
			Foreground(t.Critical),

		TagBase: lipgloss.NewStyle().
			Foreground(t.TagText).
			Bold(true).
			Padding(0, 1),

		Secure: lipgloss.NewStyle().
			Foreground(t.Secure),

		Chain: lipgloss.NewStyle().
			Foreground(t.Label).
			Bold(true),

		Card: lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(t.Border).
			Padding(1, 2).
			Margin(1, 0),
	}
}

// render applies styling only if not in CI mode
func render(style lipgloss.Style, text string) string {
	if IsCI() {
		return text
	}
	return style.Render(text)
}

// getTagStyle returns a lipgloss Style with a background color based on severity or type
// getTagStyle returns a lipgloss Style with a background color based on severity or type
func getTagStyle(tagType string, severity string) lipgloss.Style {
	t := CurrentTheme
	style := GetStyles().TagBase.Copy()

	if tagType == "POLICY" {
		return style.Background(t.BgPolicy)
	}

	switch strings.ToLower(severity) {
	case "critical":
		return style.Background(t.BgCritical)
	case "high":
		return style.Background(t.BgHigh)
	case "medium":
		return style.Background(t.BgMedium)
	case "low":
		return style.Background(t.BgLow)
	default:
		return style.Background(t.Dim)
	}
}

// RenderTargetIntelligence displays a summary of the connection and target status
func RenderTargetIntelligence(res models.ScanResult, showSans bool) {
	styles := GetStyles()
	title := render(styles.Title, "TARGET INTELLIGENCE")

	// Max width for text content within the card

	ipRow := fmt.Sprintf("%s %s", render(styles.Label, "HOST IP"), render(styles.Value, res.IP))
	targetRow := fmt.Sprintf("%s %s", render(styles.Label, "TARGET HOST"), render(styles.Value, res.Target))
	portRow := fmt.Sprintf("%s %d", render(styles.Label, "TARGET PORT"), res.Port)
	latencyRow := fmt.Sprintf("%s %s", render(styles.Label, "LATENCY"), render(styles.Value, res.Latency.String()))

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
		output = styles.Card.Render(output)
	} else {
		// In CI mode, add simple border
		output = fmt.Sprintf("\n%s\n%s\n%s\n", strings.Repeat("=", 50), output, strings.Repeat("=", 50))
	}

	fmt.Println(output)
}

// RenderCertificateIdentity displays certificate chain and validity info
func RenderCertificateIdentity(res models.ScanResult, showSans bool) {
	styles := GetStyles()
	styles.Title.SetString("CERTIFICATE IDENTITY")
	title := render(styles.Title, "CERTIFICATE IDENTITY")

	// Certificate Info Section
	wrappedSubject := res.Subject
	if !IsCI() {
		wrappedSubject = lipgloss.NewStyle().Width(maxTextWidth).Render(res.Subject)
	}
	cnRow := fmt.Sprintf("%s %s", render(styles.Label, "COMMON NAME"), render(styles.Value, wrappedSubject))

	serialRow := fmt.Sprintf("%s %s", render(styles.Label, "SERIAL NUM"), render(styles.Value, res.SerialNumber))

	rows := []string{cnRow, serialRow}

	if showSans && len(res.DNSNames) > 0 {
		sansHeader := render(styles.Label, "SANs")
		rows = append(rows, sansHeader)

		for _, san := range res.DNSNames {
			wrappedSan := san
			if !IsCI() {
				// Truncate or wrap if too long (optional, keeping simple for now)
			}
			rows = append(rows, fmt.Sprintf("%s%s", "    ", render(styles.SubValue, wrappedSan)))
		}
	} else if showSans {
		rows = append(rows, fmt.Sprintf("%s %s", render(styles.Label, "SANs"), render(styles.SubValue, "(None)")))
	}

	expiryStr := res.NotAfter.Format("2006-01-02")
	expiryStyle := styles.Value

	daysRemaining := time.Until(res.NotAfter).Hours() / 24
	if daysRemaining < 0 {
		expiryStyle = styles.Critical
	} else if daysRemaining < 30 {
		expiryStyle = styles.Warning
	}

	expiryRow := fmt.Sprintf("%s %s", render(styles.Label, "EXPIRES"), render(expiryStyle, expiryStr))

	statusStr := "🔒 TRUSTED"
	statusStyle := styles.Secure
	if daysRemaining < 0 {
		statusStr = "⚠ EXPIRED"
		statusStyle = styles.Critical
	} else if !res.IsTrusted {
		statusStr = "✗ UNTRUSTED"
		statusStyle = styles.Critical
	}
	statusRow := fmt.Sprintf("%s %s", render(styles.Label, "STATUS"), render(statusStyle, statusStr))

	// Trust Chain Visualization
	chainHeader := fmt.Sprintf("\n%s", render(styles.Label.Copy().Width(0).Foreground(CurrentTheme.Title).Underline(true), "CERTIFICATE CHAIN"))
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

		cStyle := styles.SubValue
		// Include Serial Number in parentheses for the chain
		label := fmt.Sprintf("%s", c.Subject)

		if c.IsAnchor {
			label = fmt.Sprintf("%s [ANCHOR]", label)
			cStyle = styles.Value // Bold/White for anchor
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
				chainRows = append(chainRows, fmt.Sprintf("%s%s", render(styles.Chain, prefix), render(cStyle, line)))
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
		output = styles.Card.Render(output)
	} else {
		// In CI mode, add simple border
		output = fmt.Sprintf("\n%s\n%s\n%s\n", strings.Repeat("=", 50), output, strings.Repeat("=", 50))
	}

	fmt.Println(output)
}

// GetCipherDisplayStatus returns the security icon and style for a cipher
func GetCipherDisplayStatus(cipher string) (string, lipgloss.Style) {
	lower := strings.ToLower(cipher)
	styles := GetStyles()

	// CRITICAL: Broken or Dangerous ciphers
	if strings.Contains(lower, "null") || strings.Contains(lower, "md5") ||
		strings.Contains(lower, "rc4") || strings.Contains(lower, "3des") ||
		strings.Contains(lower, "des") || strings.Contains(lower, "export") ||
		strings.Contains(lower, "anon") {
		return "⊘", styles.Critical // Use circle with line (⊘) for critical/broken
	}

	// WARNING: Weak ciphers (CBC)
	if strings.Contains(lower, "cbc") {
		return "⚠", styles.Warning
	}

	// SECURE
	return "", styles.Secure // Empty string for secure ciphers (no issues)
}

// RenderProtocolMatrix displays the supported protocols in a table-like format
func RenderProtocolMatrix(res models.ScanResult, verbose bool, mode string, report *models.ComplianceResult) {
	styles := GetStyles()
	title := render(styles.Title, "PROTOCOL MATRIX")
	if IsCI() {
		fmt.Println("PROTOCOL MATRIX")
		fmt.Println("===============")
		fmt.Println()
	}

	var rows []string
	header := lipgloss.JoinHorizontal(lipgloss.Left,
		lipgloss.NewStyle().Width(15).Foreground(CurrentTheme.Value).Bold(true).Render("PROTOCOL"),
		lipgloss.NewStyle().Foreground(CurrentTheme.Value).Bold(true).Render("STATUS"),
	)
	if IsCI() {
		header = fmt.Sprintf("%-15s %s", "PROTOCOL", "STATUS")
	}

	rows = []string{header}
	if !IsCI() {
		rows = []string{header, render(styles.Chain, strings.Repeat("═", separatorWidth))}
	} else {
		rows = []string{header, strings.Repeat("=", separatorWidth)}
	}

	// map to track unique vulnerabilities for the notes section
	vulnMap := make(map[string]engine.Vulnerability)

	for i, p := range res.Protocols {
		// Add separator between protocols (but not before the first one)
		if i > 0 {
			sep := render(lipgloss.NewStyle().Foreground(CurrentTheme.Dim), strings.Repeat("─", separatorWidth))
			if IsCI() {
				sep = strings.Repeat("-", separatorWidth)
			}
			rows = append(rows, sep)
		}

		status := render(styles.Secure, "🔒 SECURE")
		if !p.Supported {
			status = render(styles.SubValue.Copy().Faint(true), "─ DISABLED")
		} else if p.Name == "TLS 1.0" || p.Name == "TLS 1.1" {
			// Mark old protocols as WARNING even if enabled (technically they are insecure)
			status = render(styles.Warning, "🔓 WEAK")
		}

		// Check policy for protocol
		if report != nil && p.Supported {
			if stat, ok := report.ProtocolStats[p.Name]; ok && stat == models.ComplianceViolation {
				status += " " + render(getTagStyle("POLICY", ""), "POLICY VIOLATION")
			}
		}

		row := lipgloss.JoinHorizontal(lipgloss.Left,
			lipgloss.NewStyle().Width(15).Foreground(CurrentTheme.Value).Render(p.Name),
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

				displayName := engine.GetCipherDisplayName(cipher, mode)

				// Security status (after name)
				secInd, cipherStyle := GetCipherDisplayStatus(cipher)
				if !isEnabled {
					cipherStyle = styles.SubValue.Copy().Faint(true)
				}

				// Check for vulnerabilities
				vulns := engine.GetCipherVulnerabilities(cipher)
				var vulnBuilder strings.Builder
				for _, v := range vulns {
					vulnBuilder.WriteString(fmt.Sprintf(" %s", render(getTagStyle("VULN", v.Severity), v.Label)))
					vulnMap[v.ID] = v
				}
				vulnLabels := vulnBuilder.String()

				// Check policy for cipher
				if report != nil && isEnabled {
					if stat, ok := report.CipherStats[cipher]; ok && stat == models.ComplianceViolation {
						vulnLabels += " " + render(getTagStyle("POLICY", ""), "POLICY VIOLATION")
					}
				}

				if secInd != "" {
					secInd = " " + secInd
				}

				cipherRow := fmt.Sprintf("  %s %s%s%s", frontInd, render(cipherStyle, displayName), secInd, vulnLabels)
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

					displayName := engine.GetCipherDisplayName(cipher, mode)

					// Use shared logic for security status (after name)
					secInd, cStyle := GetCipherDisplayStatus(cipher)

					vulns := engine.GetCipherVulnerabilities(cipher)
					var vulnBuilder strings.Builder
					for _, v := range vulns {
						vulnBuilder.WriteString(fmt.Sprintf(" %s", render(getTagStyle("VULN", v.Severity), v.Label)))
						vulnMap[v.ID] = v
					}
					vulnLabels := vulnBuilder.String()

					// Check policy for cipher
					if report != nil {
						if stat, ok := report.CipherStats[cipher]; ok && stat == models.ComplianceViolation {
							vulnLabels += " " + render(getTagStyle("POLICY", ""), "POLICY VIOLATION")
						}
					}

					if secInd != "" {
						secInd = " " + secInd
					}

					cipherRow := fmt.Sprintf("%s %s%s%s", prefix, render(cStyle, displayName), secInd, vulnLabels)
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
		output = styles.Card.Render(output)
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

	styles := GetStyles()

	// Define legend items
	items := []struct {
		symbol string
		desc   string
		style  lipgloss.Style
	}{
		{"🔒", "Secure", styles.Secure},
		{"🔓", "Weak", styles.Warning},
		{"⚠", "Warning", styles.Warning},
		{"⊘", "Critical", styles.Critical},
		{"✓", "Enabled", styles.Secure},
		{"✗", "Disabled", styles.SubValue.Copy().Faint(true)},
	}

	var nodes []string
	for _, item := range items {
		nodes = append(nodes, fmt.Sprintf("%s %s", render(item.style, item.symbol), render(styles.SubValue, item.desc)))
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

	t := CurrentTheme

	// Determine color based on severity
	borderColor := t.Dim
	titleColor := t.Value
	switch strings.ToLower(v.Severity) {
	case "critical":
		borderColor = t.Critical
		titleColor = t.Critical
	case "high":
		borderColor = t.Warning
		titleColor = t.Warning
	case "medium":
		borderColor = t.Label
		titleColor = t.Label
	}

	// Styles
	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(borderColor).
		Padding(0, 1).
		Margin(0, 0, 1, 0).
		Width(vulnerabilityBoxWidth)

	titleStyle := lipgloss.NewStyle().Foreground(titleColor).Bold(true)
	headerStyle := lipgloss.NewStyle().Foreground(t.Title).Bold(true).Width(14)
	valueStyle := lipgloss.NewStyle().Foreground(t.Value)

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
		fmt.Sprintf("%s %s", headerStyle.Render("CVE:"), lipgloss.NewStyle().Foreground(t.SubValue).Underline(true).Render(v.URL)),
	}

	if v.ExploitURL != "" {
		body = append(body, fmt.Sprintf("%s %s", headerStyle.Render("Exploit Ref:"), lipgloss.NewStyle().Foreground(t.SubValue).Underline(true).Render(v.ExploitURL)))
	}

	content := lipgloss.JoinVertical(lipgloss.Left,
		headerLine,
		strings.Repeat("─", vulnerabilityBorderWidth), // Separator
		lipgloss.JoinVertical(lipgloss.Left, body...),
	)

	return boxStyle.Render(content)
}

// RenderVulnerabilitySection returns a slice of formatted strings for vulnerabilities
func RenderVulnerabilitySection(vulnMap map[string]engine.Vulnerability) []string {
	if len(vulnMap) == 0 {
		return nil
	}

	styles := GetStyles()
	var rows []string
	rows = append(rows, "", render(styles.Title, "VULNERABILITY DOSSIERS"))

	sep := strings.Repeat("─", vulnerabilityBoxWidth)
	if IsCI() {
		sep = strings.Repeat("-", vulnerabilityBoxWidth)
	}
	rows = append(rows, render(styles.Chain, sep))

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
