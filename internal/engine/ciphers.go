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
func cipherStrength(name string) int {
	score := 0
	nameLower := strings.ToLower(name)

	// Key exchange strength
	if strings.Contains(nameLower, "ecdhe") {
		score += 1000 // ECDHE is strongest
	} else if strings.Contains(nameLower, "dhe") {
		score += 500 // DHE is good
	}
	// RSA-only key exchange gets 0

	// Encryption algorithm strength
	if strings.Contains(nameLower, "aes_256") {
		score += 200
	} else if strings.Contains(nameLower, "aes_128") {
		score += 150
	} else if strings.Contains(nameLower, "chacha20") {
		score += 180
	} else if strings.Contains(nameLower, "3des") {
		score += 50 // Weak
	} else if strings.Contains(nameLower, "rc4") {
		score += 10 // Very weak
	}

	// Mode of operation
	if strings.Contains(nameLower, "gcm") {
		score += 100 // AEAD mode, strongest
	} else if strings.Contains(nameLower, "poly1305") {
		score += 100 // AEAD mode
	} else if strings.Contains(nameLower, "cbc") {
		score += 30 // CBC is weaker
	}

	// Hash function
	if strings.Contains(nameLower, "sha384") {
		score += 20
	} else if strings.Contains(nameLower, "sha256") {
		score += 15
	} else if strings.Contains(nameLower, "sha") {
		score += 10
	} else if strings.Contains(nameLower, "md5") {
		score += 1 // Very weak
	}

	return score
}
