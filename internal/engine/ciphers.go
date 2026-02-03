package engine

import (
	"crypto/tls"
	"fmt"
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
// sorted by strength (strongest first)
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
			"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
			"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
			"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
			"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
			"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
			"TLS_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_RSA_WITH_AES_256_CBC_SHA",
			"TLS_RSA_WITH_AES_128_CBC_SHA256",
			"TLS_RSA_WITH_AES_128_CBC_SHA",
			"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
			"TLS_RSA_WITH_RC4_128_SHA",
		}
	case tls.VersionTLS10, tls.VersionTLS11:
		names = []string{
			"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
			"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
			"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
			"TLS_RSA_WITH_AES_256_CBC_SHA",
			"TLS_RSA_WITH_AES_128_CBC_SHA",
			"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
			"TLS_RSA_WITH_RC4_128_SHA",
		}
	}

	// Sort by strength (bubble sort maintains stability if we ordered them well above, but let's ensure it)
	// Actually, the lists above are roughly ordered, but using the explicit sorter ensures consistency
	sortCiphersByStrength(names)
	return names
}

// sortCiphersByStrength sorts cipher names by security strength (strongest first)
func sortCiphersByStrength(ciphers []string) {
	// Use a simple bubble sort with strength comparison
	for i := 0; i < len(ciphers); i++ {
		for j := i + 1; j < len(ciphers); j++ {
			if cipherStrength(ciphers[j]) > cipherStrength(ciphers[i]) {
				ciphers[i], ciphers[j] = ciphers[j], ciphers[i]
			}
		}
	}
}

// cipherStrength returns a numeric score for cipher strength (higher = stronger)
// cipherStrength returns a numeric score for cipher strength based on the rubric:
// Protocol Support (handled implicitly by list context): 30%
// Key Exchange: 30% (ECDHE/DHE=100%, RSA=60%)
// Cipher Strength: 40% (AES-GCM/ChaCha=100%, AES-CBC=80%, 3DES/RC4=0%)
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
	if strings.Contains(nameLower, "3des") || strings.Contains(nameLower, "rc4") {
		score += 0 // Failure (0%) - Check this FIRST to override CBC/GCM matches
	} else if strings.Contains(nameLower, "gcm") || strings.Contains(nameLower, "chacha20") || strings.Contains(nameLower, "poly1305") {
		score += 40 // AEAD (100% of 40)
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
