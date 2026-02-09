package engine

// ToOpenSSL converts a standard IANA cipher suite name to its OpenSSL equivalent.
// If no mapping is found, it returns the original name.
func ToOpenSSL(ianaName string) string {
	if mapping, ok := ianaToOpenSSL[ianaName]; ok {
		return mapping
	}
	return ianaName
}

// GetCipherDisplayName returns the cipher name based on the requested mode:
// "iana" (default), "openssl", or "both".
func GetCipherDisplayName(ianaName string, mode string) string {
	switch mode {
	case "openssl":
		return ToOpenSSL(ianaName)
	case "both":
		ossl := ToOpenSSL(ianaName)
		if ossl == ianaName {
			return ianaName
		}
		return ianaName + " / " + ossl
	default:
		return ianaName
	}
}

// ianaToOpenSSL maps IANA cipher suite names to OpenSSL equivalents.
// It is built automatically from AllIANACiphers() to ensure consistency
// and eliminate duplication between cipher definitions and OpenSSL mappings.
var ianaToOpenSSL map[string]string

// init builds the IANA to OpenSSL mapping from the consolidated cipher definitions in ciphers.go
// This creates a single source of truth for both cipher IDs and their OpenSSL equivalents.
func init() {
	ianaToOpenSSL = make(map[string]string)
	for _, cipher := range AllIANACiphers() {
		if cipher.OpenSSLName != "" {
			ianaToOpenSSL[cipher.Name] = cipher.OpenSSLName
		}
	}
}
