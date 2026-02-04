package ui

import (
	"crypto/tls"
	"fmt"
	"snipher/internal/engine"
	"strings"
)

func RenderCipherList() {
	render(styleTitle, "SUPPORTED CIPHER SUITES")

	if !IsCI() {
		fmt.Println(styleCard.Render(GetLegend()))
		fmt.Println()
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
		fmt.Println(render(styleLabel, v.name))
		fmt.Println(render(styleChain, strings.Repeat("─", 40)))

		ciphers := engine.GetAllCiphersForProtocol(v.ver)
		for _, cipher := range ciphers {
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

			fmt.Printf("  %s%s%s\n", render(cStyle, cipher), secInd, vulnLabels)
		}
		fmt.Println()
	}

	// Render Vulnerability Notes
	if len(vulnMap) > 0 {
		fmt.Println(render(styleTitle, "VULNERABILITY NOTES"))
		fmt.Println(render(styleChain, strings.Repeat("─", 40)))
		for _, v := range vulnMap {
			severity := ""
			if v.Severity != "" {
				severity = fmt.Sprintf(" [%s]", strings.ToUpper(v.Severity))
			}

			note := fmt.Sprintf("%s %s%s\n%s %s\n%s %s\n%s %s\n%s %s\n%s %s\n%s %s\n%s %s (Verified: 2026-02-03)\n%s %s",
				render(styleCrit, "●"),
				render(styleLabel, v.Label),
				render(styleCrit, severity),
				render(styleSubValue, "  Quick Ref:"),
				render(styleSubValue.Copy().Faint(false), v.Description),
				render(styleSubValue, "  Risk Rating:"),
				render(styleSubValue.Copy().Faint(false), v.RiskRating),
				render(styleSubValue, "  Risk Detail:"),
				render(styleSubValue.Copy().Faint(false), v.Risk),
				render(styleSubValue, "  Impact Rating:"),
				render(styleSubValue.Copy().Faint(false), v.ImpactRating),
				render(styleSubValue, "  Impact Detail:"),
				render(styleSubValue.Copy().Faint(false), v.Impact),
				render(styleSubValue, "  Complexity:"),
				render(styleSubValue.Copy().Faint(false), v.Complexity),
				render(styleSubValue, "  Exploited in Wild:"),
				render(styleSubValue.Copy().Faint(false), v.Exploited),
				render(styleSubValue, "  CVE:"),
				render(styleSubValue.Copy().Underline(true), v.URL))

			if v.ExploitURL != "" {
				note += fmt.Sprintf("\n%s %s",
					render(styleSubValue, "  Exploit Ref:"),
					render(styleSubValue.Copy().Underline(true), v.ExploitURL))
			}

			if v.SecondaryURL != "" && v.SecondaryURL != v.ExploitURL {
				note += fmt.Sprintf("\n%s %s",
					render(styleSubValue, "  Research Ref:"),
					render(styleSubValue.Copy().Underline(true), v.SecondaryURL))
			}

			fmt.Println(note)
			fmt.Println()
		}
	}
}
