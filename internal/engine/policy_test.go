package engine

import (
	"snipher/internal/models"
	"testing"
)

func TestCheckCompliance(t *testing.T) {
	policy := models.Policy{
		Name:      "Test Policy",
		Protocols: []string{"TLS 1.3"},
		Ciphers:   []string{"TLS_AES_256_GCM_SHA384", "ECDHE-RSA-AES256-GCM-SHA384"},
	}

	res := models.ScanResult{
		Protocols: []models.ProtocolDetails{
			{
				Name:      "TLS 1.3",
				Supported: true,
				Ciphers:   []string{"TLS_AES_256_GCM_SHA384"},
			},
			{
				Name:      "TLS 1.2",
				Supported: true,
				Ciphers:   []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
			},
		},
	}

	report := CheckCompliance(res, policy)

	// TLS 1.3 should be allowed
	if report.ProtocolStats["TLS 1.3"] != models.ComplianceAllowed {
		t.Errorf("Expected TLS 1.3 to be Allowed, got %v", report.ProtocolStats["TLS 1.3"])
	}

	// TLS 1.2 should be violation
	if report.ProtocolStats["TLS 1.2"] != models.ComplianceViolation {
		t.Errorf("Expected TLS 1.2 to be Violation, got %v", report.ProtocolStats["TLS 1.2"])
	}

	// TLS_AES_256_GCM_SHA384 should be allowed
	if report.CipherStats["TLS_AES_256_GCM_SHA384"] != models.ComplianceAllowed {
		t.Errorf("Expected TLS_AES_256_GCM_SHA384 to be Allowed, got %v", report.CipherStats["TLS_AES_256_GCM_SHA384"])
	}

	// TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 should be allowed (matched via OpenSSL name in policy)
	if report.CipherStats["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"] != models.ComplianceAllowed {
		t.Errorf("Expected TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 to be Allowed (via OpenSSL), got %v", report.CipherStats["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"])
	}

	if report.IsCompliant {
		t.Errorf("Expected overall report to be non-compliant")
	}
}
