package engine

import (
	"testing"
)

func TestGetCipherVulnerabilities(t *testing.T) {
	tests := []struct {
		cipher      string
		expectIDs   []string
		description string
	}{
		{
			cipher:      "TLS_RSA_WITH_AES_128_CBC_SHA",
			expectIDs:   []string{"NO_PFS", "CBC_PADDING", "WEAK_HASH"},
			description: "RSA key exchange + CBC mode + SHA1",
		},
		{
			cipher:      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			expectIDs:   []string{},
			description: "Modern secure cipher (no vulns)",
		},
		{
			cipher:      "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
			expectIDs:   []string{"NO_PFS", "CBC_PADDING", "SWEET32", "WEAK_HASH"},
			description: "Triple DES (Sweet32) + RSA + CBC + SHA1",
		},
		{
			cipher:      "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
			expectIDs:   []string{"RC4_INSECURE", "WEAK_HASH"},
			description: "RC4 + SHA1",
		},
		{
			cipher:      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
			expectIDs:   []string{"CBC_PADDING"},
			description: "CBC mode with SHA256",
		},
		{
			cipher:      "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
			expectIDs:   []string{"NO_PFS", "RC4_INSECURE", "WEAK_HASH", "FREAK"},
			description: "Export grade RC4 + MD5 + RSA",
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			vulns := GetCipherVulnerabilities(tc.cipher)

			if len(vulns) != len(tc.expectIDs) {
				t.Errorf("Expected %d vulnerabilities, got %d", len(tc.expectIDs), len(vulns))
			}

			// Check for each expected ID
			for _, expectedID := range tc.expectIDs {
				found := false
				for _, v := range vulns {
					if v.ID == expectedID {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Missing expected vulnerability ID: %s", expectedID)
				}
			}
		})
	}
}
