package engine

import (
	"testing"
)

func TestAllIANACiphersComplete(t *testing.T) {
	// We have 59 total ciphers covering all major categories from iana_ciphers.py
	// This includes TLS 1.3, TLS 1.2 (ECDHE, DHE, RSA), weak/legacy, NULL, EXPORT, and SSLv3
	expectedMinimumCiphers := 59

	ciphers := AllIANACiphers()
	actualCount := len(ciphers)

	if actualCount < expectedMinimumCiphers {
		t.Errorf("Expected at least %d ciphers, got %d", expectedMinimumCiphers, actualCount)
	}

	// Verify no duplicate IDs
	seen := make(map[uint16]string)
	for _, cipher := range ciphers {
		if existing, ok := seen[cipher.ID]; ok {
			t.Errorf("Duplicate cipher ID 0x%04X: '%s' and '%s'", cipher.ID, existing, cipher.Name)
		}
		seen[cipher.ID] = cipher.Name
	}

	t.Logf("Total ciphers defined: %d", actualCount)
}

func TestSpecificIANACiphersCoverage(t *testing.T) {
	// Test that specific ciphers from iana_ciphers.py are present
	expectedCiphers := map[uint16]string{
		// TLS 1.3
		0x1301: "TLS_AES_128_GCM_SHA256",
		0x1302: "TLS_AES_256_GCM_SHA384",
		0x1303: "TLS_CHACHA20_POLY1305_SHA256",

		// TLS 1.2 ECDHE - CCM variants (NEW)
		0xC0AC: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
		0xC0AD: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
		0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
		0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",

		// TLS 1.2 DHE - GCM and CAMELLIA (NEW)
		0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
		0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
		0x0045: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
		0x0088: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",

		// RSA - CAMELLIA, SEED, IDEA (NEW)
		0x0041: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
		0x0084: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
		0x0096: "TLS_RSA_WITH_SEED_CBC_SHA",
		0x0007: "TLS_RSA_WITH_IDEA_CBC_SHA",

		// NULL Ciphers (NEW)
		0x0001: "TLS_RSA_WITH_NULL_MD5",
		0x0002: "TLS_RSA_WITH_NULL_SHA",
		0xC006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
		0xC010: "TLS_ECDHE_RSA_WITH_NULL_SHA",

		// EXPORT Ciphers (NEW)
		0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
		0x0006: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
		0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
		0x0014: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",

		// SSLv3 Ciphers (NEW)
		0x0064: "SSL_CK_DES_64_CBC_WITH_MD5",
		0x0065: "SSL_CK_DES_192_EDE3_CBC_WITH_MD5",
		0x0062: "SSL_CK_DES_64_CBC_WITH_SHA",
		0x0063: "SSL_CK_RC2_128_CBC_WITH_MD5",
		0x0066: "SSL_CK_IDEA_128_CBC_WITH_MD5",
	}

	ciphers := AllIANACiphers()
	cipherMap := make(map[uint16]string)
	for _, cipher := range ciphers {
		cipherMap[cipher.ID] = cipher.Name
	}

	for id, expectedName := range expectedCiphers {
		actualName, found := cipherMap[id]
		if !found {
			t.Errorf("Missing cipher ID 0x%04X (expected: %s)", id, expectedName)
			continue
		}
		if actualName != expectedName {
			t.Errorf("Cipher ID 0x%04X: expected '%s', got '%s'", id, expectedName, actualName)
		}
	}
}

func TestOpenSSLMappingsComplete(t *testing.T) {
	// Test that all newly added ciphers have OpenSSL mappings
	newCiphers := []string{
		// ECDHE CCM
		"TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
		"TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",

		// DHE
		"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
		"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",

		// RSA
		"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
		"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
		"TLS_RSA_WITH_SEED_CBC_SHA",
		"TLS_RSA_WITH_IDEA_CBC_SHA",

		// NULL
		"TLS_RSA_WITH_NULL_MD5",
		"TLS_RSA_WITH_NULL_SHA",
		"TLS_ECDHE_ECDSA_WITH_NULL_SHA",
		"TLS_ECDHE_RSA_WITH_NULL_SHA",

		// EXPORT
		"TLS_RSA_EXPORT_WITH_RC4_40_MD5",
		"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
		"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
		"TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",

		// SSLv3
		"SSL_CK_DES_64_CBC_WITH_MD5",
		"SSL_CK_DES_192_EDE3_CBC_WITH_MD5",
		"SSL_CK_DES_64_CBC_WITH_SHA",
		"SSL_CK_DES_192_EDE3_CBC_WITH_SHA",
		"SSL_CK_RC2_128_CBC_WITH_MD5",
		"SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5",
		"SSL_CK_IDEA_128_CBC_WITH_MD5",
	}

	for _, ianaName := range newCiphers {
		opensslName := ToOpenSSL(ianaName)
		if opensslName == ianaName {
			t.Errorf("Missing OpenSSL mapping for: %s", ianaName)
		}
	}
}

func TestOpenSSLMappingExamples(t *testing.T) {
	// Verify specific OpenSSL mappings are correct
	tests := []struct {
		iana    string
		openssl string
	}{
		{"TLS_ECDHE_ECDSA_WITH_AES_128_CCM", "ECDHE-ECDSA-AES128-CCM"},
		{"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DHE-RSA-AES256-GCM-SHA384"},
		{"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", "CAMELLIA256-SHA"},
		{"TLS_RSA_WITH_SEED_CBC_SHA", "SEED-SHA"},
		{"TLS_RSA_WITH_IDEA_CBC_SHA", "IDEA-CBC-SHA"},
		{"TLS_RSA_WITH_NULL_SHA", "NULL-SHA"},
		{"TLS_RSA_EXPORT_WITH_RC4_40_MD5", "EXP-RC4-MD5"},
		{"SSL_CK_DES_64_CBC_WITH_MD5", "DES-CBC-MD5"},
		{"SSL_CK_DES_192_EDE3_CBC_WITH_SHA", "DES-CBC3-SHA"},
	}

	for _, tt := range tests {
		actual := ToOpenSSL(tt.iana)
		if actual != tt.openssl {
			t.Errorf("ToOpenSSL(%s): expected '%s', got '%s'", tt.iana, tt.openssl, actual)
		}
	}
}

func TestGetCipherDisplayNameModes(t *testing.T) {
	ianaName := "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
	opensslName := "DHE-RSA-AES256-GCM-SHA384"

	// Test "iana" mode (default)
	result := GetCipherDisplayName(ianaName, "iana")
	if result != ianaName {
		t.Errorf("IANA mode: expected '%s', got '%s'", ianaName, result)
	}

	// Test "openssl" mode
	result = GetCipherDisplayName(ianaName, "openssl")
	if result != opensslName {
		t.Errorf("OpenSSL mode: expected '%s', got '%s'", opensslName, result)
	}

	// Test "both" mode
	expectedBoth := ianaName + " / " + opensslName
	result = GetCipherDisplayName(ianaName, "both")
	if result != expectedBoth {
		t.Errorf("Both mode: expected '%s', got '%s'", expectedBoth, result)
	}
}
