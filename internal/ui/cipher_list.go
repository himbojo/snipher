package ui

import (
	"crypto/tls"
	"fmt"
	"snipher/internal/engine"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func RenderCipherList(mode string) {
	styles := GetStyles()
	title := render(styles.Title, "SUPPORTED CIPHER SUITES")

	var rows []string

	if !IsCI() {
		rows = append(rows, GetLegend(), "")
	}

	versions := []struct {
		ver  uint16
		name string
	}{
		{tls.VersionTLS13, "TLS 1.3"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS10, "TLS 1.0"},
	}

	vulnMap := make(map[string]engine.Vulnerability)

	for _, v := range versions {
		rows = append(rows, render(styles.Label, v.name))

		sep := strings.Repeat("─", 60)
		if IsCI() {
			sep = strings.Repeat("-", 60)
		}
		rows = append(rows, render(styles.Chain, sep))

		ciphers := engine.GetAllCiphersForProtocol(v.ver)
		for _, cipher := range ciphers {
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

			if secInd != "" {
				secInd = " " + secInd
			}

			rows = append(rows, fmt.Sprintf("  %s%s%s", render(cStyle, displayName), secInd, vulnLabels))
		}
		rows = append(rows, "")
	}

	// Render Vulnerability Notes
	if len(vulnMap) > 0 {
		rows = append(rows, RenderVulnerabilitySection(vulnMap)...)
	}

	content := lipgloss.JoinVertical(lipgloss.Left, rows...)

	// Apply card styling only if not in CI mode
	output := lipgloss.JoinVertical(lipgloss.Left, title, content)
	if !IsCI() {
		output = styles.Card.Render(output)
	} else {
		// In CI mode, add simple border
		output = fmt.Sprintf("\n%s\n%s\n%s\n", strings.Repeat("=", 60), output, strings.Repeat("=", 60))
	}

	fmt.Println(output)
}
