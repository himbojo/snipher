package engine

import (
	"crypto/tls"
	"fmt"
	"sort"
	"strings"
)

// GetCipherSuiteName returns the name of a cipher suite ID, or a hex string if unknown
func GetCipherSuiteName(id uint16) string {
	for _, suite := range tls.CipherSuites() {
		if suite.ID == id {
			return suite.Name
		}
	}
	for _, suite := range tls.InsecureCipherSuites() {
		if suite.ID == id {
			return suite.Name
		}
	}
	// Fallback for common legacy IDs or just return hex
	return fmt.Sprintf("0x%04X", id)
}

// IsRecommended returns true if the cipher suite is recommended by IANA/Modern standards
func IsRecommended(id uint16) bool {
	for _, suite := range tls.CipherSuites() {
		if suite.ID == id {
			return true
		}
	}
	// InsecureCipherSuites are by definition not recommended
	return false
}

// IANACipher represents a cipher suite definition from IANA
type IANACipher struct {
	ID          uint16
	Name        string
	OpenSSLName string // OpenSSL equivalent name (empty if identical to IANA name)
}

// AllIANACiphers returns a comprehensive list of IANA cipher suites
// This includes ciphers not supported by Go's crypto/tls, for manual scanning.
func AllIANACiphers() []IANACipher {
	return []IANACipher{
		// TLS 1.3
		{0x1301, "TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256"},
		{0x1302, "TLS_AES_256_GCM_SHA384", "TLS_AES_256_GCM_SHA384"},
		{0x1303, "TLS_CHACHA20_POLY1305_SHA256", "TLS_CHACHA20_POLY1305_SHA256"},
		{0x1304, "TLS_AES_128_CCM_SHA256", "TLS_AES_128_CCM_SHA256"},
		{0x1305, "TLS_AES_128_CCM_8_SHA256", "TLS_AES_128_CCM_8_SHA256"},

		// TLS 1.2 ECDHE
		{0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256"},
		{0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE-ECDSA-AES256-GCM-SHA384"},
		{0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE-RSA-AES128-GCM-SHA256"},
		{0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE-RSA-AES256-GCM-SHA384"},
		{0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE-ECDSA-CHACHA20-POLY1305"},
		{0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE-RSA-CHACHA20-POLY1305"},
		{0xC0AC, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM", "ECDHE-ECDSA-AES128-CCM"},
		{0xC0AD, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM", "ECDHE-ECDSA-AES256-CCM"},
		{0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "ECDHE-ECDSA-AES128-SHA"},
		{0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "ECDHE-ECDSA-AES256-SHA"},
		{0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE-RSA-AES128-SHA"},
		{0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "ECDHE-RSA-AES256-SHA"},
		{0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "ECDHE-ECDSA-AES128-SHA256"},
		{0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "ECDHE-ECDSA-AES256-SHA384"},
		{0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE-RSA-AES128-SHA256"},
		{0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE-RSA-AES256-SHA384"},

		// TLS 1.2 RSA
		{0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256", "AES128-GCM-SHA256"},
		{0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384", "AES256-GCM-SHA384"},
		{0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA", "AES128-SHA"},
		{0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA", "AES256-SHA"},
		{0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256", "AES128-SHA256"},
		{0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256", "AES256-SHA256"},

		// Weak / Legacy (RC4, 3DES, CBC)
		{0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "DES-CBC3-SHA"},
		{0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "ECDHE-RSA-DES-CBC3-SHA"},
		{0x0005, "TLS_RSA_WITH_RC4_128_SHA", "RC4-SHA"},
		{0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA", "ECDHE-RSA-RC4-SHA"},
		{0x0004, "TLS_RSA_WITH_RC4_128_MD5", "RC4-MD5"},

		// DHE (Forward Secrecy, but often slow/deprecated)
		{0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DHE-RSA-AES128-GCM-SHA256"},
		{0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DHE-RSA-AES256-GCM-SHA384"},
		{0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "DHE-RSA-AES128-SHA"},
		{0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "DHE-RSA-AES256-SHA"},
		{0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "DHE-RSA-AES128-SHA256"},
		{0x006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "DHE-RSA-AES256-SHA256"},
		{0x0045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", "DHE-RSA-CAMELLIA128-SHA"},
		{0x0088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", "DHE-RSA-CAMELLIA256-SHA"},

		// RSA with CAMELLIA, SEED, IDEA
		{0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", "CAMELLIA128-SHA"},
		{0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", "CAMELLIA256-SHA"},
		{0x0096, "TLS_RSA_WITH_SEED_CBC_SHA", "SEED-SHA"},
		{0x0007, "TLS_RSA_WITH_IDEA_CBC_SHA", "IDEA-CBC-SHA"},

		// NULL Ciphers (No Encryption)
		{0x0001, "TLS_RSA_WITH_NULL_MD5", "NULL-MD5"},
		{0x0002, "TLS_RSA_WITH_NULL_SHA", "NULL-SHA"},
		{0xC006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA", "ECDHE-ECDSA-NULL-SHA"},
		{0xC010, "TLS_ECDHE_RSA_WITH_NULL_SHA", "ECDHE-RSA-NULL-SHA"},

		// EXPORT Ciphers (Weak 40-bit encryption)
		{0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "EXP-RC4-MD5"},
		{0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", "EXP-RC2-CBC-MD5"},
		{0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", "EXP-DES-CBC-SHA"},
		{0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", "EXP-EDH-RSA-DES-CBC-SHA"},

		// SSLv3 Ciphers (Legacy)
		{0x0064, "SSL_CK_DES_64_CBC_WITH_MD5", "DES-CBC-MD5"},
		{0x0065, "SSL_CK_DES_192_EDE3_CBC_WITH_MD5", "DES-CBC3-MD5"},
		{0x0062, "SSL_CK_DES_64_CBC_WITH_SHA", "DES-CBC-SHA"},
		{0xFEFF, "SSL_CK_DES_192_EDE3_CBC_WITH_SHA", "DES-CBC3-SHA"},
		{0x0063, "SSL_CK_RC2_128_CBC_WITH_MD5", "RC2-CBC-MD5"},
		{0xFEFE, "SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5", "EXP-RC2-CBC-MD5"},
		{0x0066, "SSL_CK_IDEA_128_CBC_WITH_MD5", "IDEA-CBC-MD5"},
	}
}

// AllModernCiphers returns a list of all cipher suites known to the Go standard library
func AllModernCiphers() []uint16 {
	var ids []uint16
	for _, suite := range tls.CipherSuites() {
		ids = append(ids, suite.ID)
	}
	for _, suite := range tls.InsecureCipherSuites() {
		ids = append(ids, suite.ID)
	}
	return ids
}

// GetAllCiphersForProtocol returns all possible cipher names for a given protocol version
// sorted by strength (strongest first)
// GetAllCiphersForProtocol returns all possible cipher names for a given protocol version
// sorted by strength (strongest first).
func GetAllCiphersForProtocol(version uint16) []string {
	// TLS 1.3 has a fixed set of ciphers
	if version == tls.VersionTLS13 {
		return []string{
			"TLS_AES_256_GCM_SHA384",       // Strongest: AES-256 + GCM
			"TLS_CHACHA20_POLY1305_SHA256", // Strong: ChaCha20
			"TLS_AES_128_GCM_SHA256",       // Good: AES-128 + GCM
		}
	}

	var names []string

	// Explicitly list ciphers for transparency and consistency
	// Go doesn't support all ciphers, so these are the ones we can actively test for.
	switch version {
	case tls.VersionTLS12:
		names = []string{
			// ECDHE - Modern (GCM/ChaCha20)
			"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
			"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",

			// ECDHE - CCM
			"TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
			"TLS_ECDHE_ECDSA_WITH_AES_128_CCM",

			// ECDHE - CBC
			"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
			"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
			"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
			"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
			"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",

			// DHE - GCM
			"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",

			// DHE - CBC
			"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
			"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
			"TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
			"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",

			// DHE - CAMELLIA
			"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
			"TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",

			// RSA - Modern (GCM)
			"TLS_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_RSA_WITH_AES_128_GCM_SHA256",

			// RSA - CBC
			"TLS_RSA_WITH_AES_256_CBC_SHA256",
			"TLS_RSA_WITH_AES_256_CBC_SHA",
			"TLS_RSA_WITH_AES_128_CBC_SHA256",
			"TLS_RSA_WITH_AES_128_CBC_SHA",

			// RSA - CAMELLIA, SEED, IDEA
			"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
			"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
			"TLS_RSA_WITH_SEED_CBC_SHA",
			"TLS_RSA_WITH_IDEA_CBC_SHA",

			// Weak/Legacy
			"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
			"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
			"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
			"TLS_RSA_WITH_RC4_128_SHA",
			"TLS_RSA_WITH_RC4_128_MD5",

			// NULL Ciphers (No Encryption - Critical Risk)
			"TLS_ECDHE_ECDSA_WITH_NULL_SHA",
			"TLS_ECDHE_RSA_WITH_NULL_SHA",
			"TLS_RSA_WITH_NULL_SHA",
			"TLS_RSA_WITH_NULL_MD5",

			// EXPORT Ciphers (40-bit - Critical Risk)
			"TLS_RSA_EXPORT_WITH_RC4_40_MD5",
			"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
			"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
			"TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
		}
	case tls.VersionTLS10, tls.VersionTLS11:
		names = []string{
			// ECDHE
			"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
			"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",

			// RSA
			"TLS_RSA_WITH_AES_256_CBC_SHA",
			"TLS_RSA_WITH_AES_128_CBC_SHA",

			// RSA - CAMELLIA, SEED, IDEA
			"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
			"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
			"TLS_RSA_WITH_SEED_CBC_SHA",
			"TLS_RSA_WITH_IDEA_CBC_SHA",

			// Weak/Legacy
			"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
			"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
			"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
			"TLS_RSA_WITH_RC4_128_SHA",
			"TLS_RSA_WITH_RC4_128_MD5",

			// NULL Ciphers
			"TLS_ECDHE_ECDSA_WITH_NULL_SHA",
			"TLS_ECDHE_RSA_WITH_NULL_SHA",
			"TLS_RSA_WITH_NULL_SHA",
			"TLS_RSA_WITH_NULL_MD5",

			// EXPORT Ciphers
			"TLS_RSA_EXPORT_WITH_RC4_40_MD5",
			"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
			"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
		}
	}

	// Sort by strength (bubble sort maintains stability if we ordered them well above, but let's ensure it)
	// Actually, the lists above are roughly ordered, but using the explicit sorter ensures consistency
	sortCiphersByStrength(names)
	return names
}

// sortCiphersByStrength sorts cipher names by security strength (strongest first)
// ✅ Fix #10: Use efficient sort.Slice instead of O(n²) bubble sort
func sortCiphersByStrength(ciphers []string) {
	sort.Slice(ciphers, func(i, j int) bool {
		return cipherStrength(ciphers[i]) > cipherStrength(ciphers[j])
	})
}

// cipherStrength returns a numeric score for cipher strength based on the rubric:
// Protocol Support (handled implicitly by list context): 30%
// Key Exchange: 30% (ECDHE/DHE=100%, RSA=60%)
// Cipher Strength: 40% (AES-GCM/CCM/ChaCha=100%, CAMELLIA/AES-CBC=80%, SEED/IDEA=40%, 3DES/RC4=0%, NULL/EXPORT=negative)
func cipherStrength(name string) int {
	score := 0
	nameLower := strings.ToLower(name)

	// Key Exchange (Max 30 points)
	if strings.Contains(nameLower, "ecdhe") || strings.Contains(nameLower, "dhe") {
		score += 30 // Forward Secrecy
	} else if strings.Contains(nameLower, "rsa") {
		score += 18 // No Forward Secrecy (60% of 30)
	}

	// Cipher Strength (Max 40 points)
	// Check weakest first to override any accidental matches
	if strings.Contains(nameLower, "null") {
		score -= 100 // NULL encryption - absolutely critical (negative score ensures it sorts last)
	} else if strings.Contains(nameLower, "export") {
		score -= 50 // EXPORT (40-bit) - critically weak
	} else if strings.Contains(nameLower, "3des") || strings.Contains(nameLower, "rc4") {
		score += 0 // Failure (0%) - Check this before CBC/GCM matches
	} else if strings.Contains(nameLower, "gcm") || strings.Contains(nameLower, "ccm") || strings.Contains(nameLower, "chacha20") || strings.Contains(nameLower, "poly1305") {
		score += 40 // AEAD (100% of 40) - includes CCM now
	} else if strings.Contains(nameLower, "camellia") {
		score += 32 // CAMELLIA is similar to AES-CBC in strength
	} else if strings.Contains(nameLower, "seed") || strings.Contains(nameLower, "idea") {
		score += 16 // SEED/IDEA are weaker (40% of 40)
	} else if strings.Contains(nameLower, "cbc") {
		score += 32 // CBC Penalty (-20% of 40 -> 32)
	}

	// Tie Breakers (Bit Strength & ECDSA Preference)
	if strings.Contains(nameLower, "aes_256") || strings.Contains(nameLower, "chacha20") {
		score += 5
	}
	if strings.Contains(nameLower, "ecdsa") {
		score += 1 // Prefer ECDSA over RSA in ties
	}

	return score
}
