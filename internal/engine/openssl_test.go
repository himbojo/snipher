package engine

import "testing"

func TestGetCipherDisplayName(t *testing.T) {
	tests := []struct {
		iana     string
		mode     string
		expected string
	}{
		{"TLS_AES_256_GCM_SHA384", "iana", "TLS_AES_256_GCM_SHA384"},
		{"TLS_AES_256_GCM_SHA384", "openssl", "TLS_AES_256_GCM_SHA384"},
		{"TLS_AES_256_GCM_SHA384", "both", "TLS_AES_256_GCM_SHA384"}, // Deduped
		{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "iana", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
		{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "openssl", "ECDHE-RSA-AES256-GCM-SHA384"},
		{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "both", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 / ECDHE-RSA-AES256-GCM-SHA384"},
		{"UNKNOWN", "both", "UNKNOWN"},
	}

	for _, tc := range tests {
		t.Run(tc.iana+"_"+tc.mode, func(t *testing.T) {
			got := GetCipherDisplayName(tc.iana, tc.mode)
			if got != tc.expected {
				t.Errorf("GetCipherDisplayName(%q, %q) = %q; want %q", tc.iana, tc.mode, got, tc.expected)
			}
		})
	}
}
