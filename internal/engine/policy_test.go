package engine

import (
	"snipher/internal/models"
	"testing"
)

func TestCheckCompliance(t *testing.T) {
	policy := models.Policy{
		Name:      "SecurePolicy",
		Protocols: []string{"TLS 1.2", "TLS 1.3"},
		Ciphers:   []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
	}

	// Case 1: Compliant
	res := models.ScanResult{
		Protocols: []models.ProtocolDetails{
			{Name: "TLS 1.2", Supported: true, Ciphers: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}},
			{Name: "TLS 1.1", Supported: false},
		},
	}

	report := CheckCompliance(res, policy)
	if !report.IsCompliant {
		t.Errorf("Expected compliant, got violations: %v", report.Violations)
	}

	// Case 2: Protocol Violation (TLS 1.1 enabled)
	res.Protocols = []models.ProtocolDetails{
		{Name: "TLS 1.1", Supported: true},
	}
	report = CheckCompliance(res, policy)
	if report.IsCompliant {
		t.Error("Expected compliance failure for TLS 1.1")
	}

	// Case 3: Cipher Violation
	res.Protocols = []models.ProtocolDetails{
		{
			Name:      "TLS 1.2",
			Supported: true,
			Ciphers:   []string{"TLS_RSA_WITH_AES_128_CBC_SHA"}, // Weak/Unallowed
		},
	}
	report = CheckCompliance(res, policy)
	if report.IsCompliant {
		t.Error("Expected compliance failure for unallowed cipher")
	}
}
