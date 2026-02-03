package ui

import (
	"crypto/tls"
	"fmt"
	"snipher/internal/engine"
	"strings"
)

func RenderCipherList() {
	render(styleTitle, "SUPPORTED CIPHER SUITES")

	versions := []struct {
		ver  uint16
		name string
	}{
		{tls.VersionTLS13, "TLS 1.3"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS10, "TLS 1.0"},
	}

	for _, v := range versions {
		fmt.Println(render(styleLabel, v.name))
		fmt.Println(render(styleChain, strings.Repeat("─", 40)))

		ciphers := engine.GetAllCiphersForProtocol(v.ver)
		for _, cipher := range ciphers {
			fmt.Printf("  %s\n", render(styleValue, cipher))
		}
		fmt.Println()
	}
}
