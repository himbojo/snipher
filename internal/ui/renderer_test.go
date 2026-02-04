package ui

import (
	"crypto/tls"
	"snipher/internal/engine"
	"testing"
)

func TestGetCipherDisplayStatus(t *testing.T) {
	tests := []struct {
		name         string
		cipher       string
		expectStatus string
	}{
		{
			name:         "Secure TLS 1.3 Cipher",
			cipher:       "TLS_AES_256_GCM_SHA384",
			expectStatus: "",
		},
		{
			name:         "Secure AES-GCM Cipher",
			cipher:       "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			expectStatus: "",
		},
		{
			name:         "Weak CBC Cipher",
			cipher:       "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
			expectStatus: "⚠",
		},
		{
			name:         "Warning Sweet32 Cipher",
			cipher:       "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
			expectStatus: "⊘",
		},
		{
			name:         "Insecure RC4 Cipher",
			cipher:       "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
			expectStatus: "⊘",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, _ := GetCipherDisplayStatus(tc.cipher)
			if status != tc.expectStatus {
				t.Errorf("Expected status %q, got %q", tc.expectStatus, status)
			}
		})
	}
}

func TestGetVersionForProtocol(t *testing.T) {
	tests := []struct {
		name    string
		version uint16
	}{
		{"TLS 1.0", tls.VersionTLS10},
		{"TLS 1.1", tls.VersionTLS11},
		{"TLS 1.2", tls.VersionTLS12},
		{"TLS 1.3", tls.VersionTLS13},
		{"SSL 3.0", 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := getVersionForProtocol(tc.name)
			if v != tc.version {
				t.Errorf("Expected version %v, got %v", tc.version, v)
			}
		})
	}
}

func TestRenderVulnerabilityCard_SmokeTest(t *testing.T) {
	vuln := engine.Vulnerability{
		ID:          "TEST_VULN",
		Label:       "Sample Vulnerability",
		Severity:    "High",
		Description: "Just a test description",
		URL:         "https://example.com/cve",
	}

	output := RenderVulnerabilityCard(vuln)
	if output == "" {
		t.Fatal("RenderVulnerabilityCard returned empty string")
	}
}
