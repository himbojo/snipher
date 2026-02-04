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

var ianaToOpenSSL = map[string]string{
	// TLS 1.3 (Names are often identical in modern OpenSSL, but we list them for clarity)
	"TLS_AES_256_GCM_SHA384":       "TLS_AES_256_GCM_SHA384",
	"TLS_CHACHA20_POLY1305_SHA256": "TLS_CHACHA20_POLY1305_SHA256",
	"TLS_AES_128_GCM_SHA256":       "TLS_AES_128_GCM_SHA256",

	// TLS 1.2 ECDHE
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       "ECDHE-ECDSA-AES256-GCM-SHA384",
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":         "ECDHE-RSA-AES256-GCM-SHA384",
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   "ECDHE-RSA-CHACHA20-POLY1305",
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": "ECDHE-ECDSA-CHACHA20-POLY1305",
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":         "ECDHE-RSA-AES128-GCM-SHA256",
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":       "ECDHE-ECDSA-AES128-GCM-SHA256",
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":          "ECDHE-ECDSA-AES256-SHA",
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":            "ECDHE-RSA-AES256-SHA",
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":       "ECDHE-ECDSA-AES128-SHA256",
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":         "ECDHE-RSA-AES128-SHA256",
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":            "ECDHE-RSA-AES128-SHA",
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":          "ECDHE-ECDSA-AES128-SHA",
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":           "ECDHE-RSA-DES-CBC3-SHA",
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA":                "ECDHE-RSA-RC4-SHA",
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":              "ECDHE-ECDSA-RC4-SHA",

	// TLS 1.2 RSA
	"TLS_RSA_WITH_AES_256_GCM_SHA384": "AES256-GCM-SHA384",
	"TLS_RSA_WITH_AES_128_GCM_SHA256": "AES128-GCM-SHA256",
	"TLS_RSA_WITH_AES_256_CBC_SHA":    "AES256-SHA",
	"TLS_RSA_WITH_AES_128_CBC_SHA256": "AES128-SHA256",
	"TLS_RSA_WITH_AES_128_CBC_SHA":    "AES128-SHA",
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":   "DES-CBC3-SHA",
	"TLS_RSA_WITH_RC4_128_SHA":        "RC4-SHA",

	// Legacy / Other
	"TLS_EMPTY_RENEGOTIATION_INFO_SCSV": "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
}
