package engine

import (
	"strings"
)

type Vulnerability struct {
	ID           string
	Label        string
	Severity     string // scale: Low, Medium, High, Critical
	Description  string // One-line quick reference
	RiskRating   string // scale: Low, Medium, High, Critical
	ImpactRating string // scale: Low, Medium, High, Critical
	Complexity   string // scale: Low, Medium, High, Critical
	Exploited    string // "Yes" / "No" / "Proof of Concept"
	ExploitURL   string // URL to exploit proof or news
	Risk         string // Detailed risk info
	Impact       string // Detailed impact info
	URL          string // Primary URL (usually NVD/CVE)
	SecondaryURL string // Secondary URL (Research/Blog)
}

// Common Vulnerability Definitions
var (
	VulnNoPFS = Vulnerability{
		ID:           "NO_PFS",
		Label:        "NO PFS",
		Severity:     "Medium",
		Description:  "Lack of Perfect Forward Secrecy allows retroactive decryption of captured traffic.",
		RiskRating:   "High",
		ImpactRating: "High",
		Complexity:   "High",
		Exploited:    "Yes (State Actors)",
		ExploitURL:   "https://www.washingtonpost.com/world/national-security/nsa-collects-millions-of-e-mail-address-books-globally/2013/10/14/d3ad5986-34e8-11e3-80c6-7e6dd8d22d8f_story.html",
		Risk:         "Retroactive decryption of session traffic",
		Impact:       "Compromised private key allows decrypting historically captured traffic (Historical Data)",
		URL:          "https://scotthelme.co.uk/perfect-forward-secrecy/",
		SecondaryURL: "https://blog.cloudflare.com/staying-ahead-of-the-curve-with-pfs/",
	}
	VulnPaddingOracle = Vulnerability{
		ID:           "CBC_PADDING",
		Label:        "PADDING ORACLE",
		Severity:     "Critical",
		Description:  "Side-channel attack on CBC padding allows full plaintext recovery.",
		RiskRating:   "Critical",
		ImpactRating: "Critical",
		Complexity:   "Low",
		Exploited:    "Yes",
		ExploitURL:   "https://github.com/mubix/cve-2016-2107",
		Risk:         "Side-channel attack on CBC padding",
		Impact:       "Man-in-the-middle decryption of TLS session traffic (Full Session Decryption)",
		URL:          "https://nvd.nist.gov/vuln/detail/CVE-2016-2107",
		SecondaryURL: "https://blog.cloudflare.com/padding-oracles-and-the-decline-of-cbc-mode-ciphersuites/",
	}
	VulnWeakHash = Vulnerability{
		ID:           "WEAK_HASH",
		Label:        "WEAK HASH",
		Severity:     "High",
		Description:  "Usage of SHA-1 or MD5 which are susceptible to collision attacks.",
		RiskRating:   "High",
		ImpactRating: "High",
		Complexity:   "High",
		Exploited:    "Yes (SHAttered)",
		ExploitURL:   "https://shattered.io/",
		Risk:         "Cryptographic collision attacks",
		Impact:       "Handshake transcript tampering or certificate forgery (Integrity & Authenticity)",
		URL:          "https://nvd.nist.gov/vuln/detail/CVE-2005-4900",
		SecondaryURL: "https://shattered.io/",
	}
	VulnSweet32 = Vulnerability{
		ID:           "SWEET32",
		Label:        "SWEET32",
		Severity:     "High",
		Description:  "Birthday attack on 64-bit block ciphers like 3DES allowing cookie theft.",
		RiskRating:   "Medium",
		ImpactRating: "High",
		Complexity:   "High",
		Exploited:    "No (Limited demo)",
		Risk:         "Birthday attack on 64-bit block ciphers",
		Impact:       "Recovery of sensitive session data like cookies (Session Token Theft)",
		URL:          "https://nvd.nist.gov/vuln/detail/CVE-2016-2183",
		SecondaryURL: "https://sweet32.info/",
	}
	VulnRC4 = Vulnerability{
		ID:           "RC4_INSECURE",
		Label:        "INSECURE RC4",
		Severity:     "Medium",
		Description:  "RC4 keystream biases allow recovery of plaintext from long sessions.",
		RiskRating:   "Medium",
		ImpactRating: "Medium",
		Complexity:   "Medium",
		Exploited:    "Yes",
		ExploitURL:   "https://www.rc4nomore.com/",
		Risk:         "Keystream biases leading to plaintext recovery",
		Impact:       "Decryption of HTTPS traffic over extended sessions (Partial Plaintext Recovery)",
		URL:          "https://nvd.nist.gov/vuln/detail/CVE-2015-2808",
		SecondaryURL: "https://www.rc4nomore.com/",
	}
	VulnBarMitzvah = Vulnerability{
		ID:           "BAR_MITZVAH",
		Label:        "BAR MITZVAH",
		Severity:     "Medium",
		Description:  "RC4 vulnerability allowing prediction of initial keystream bytes.",
		RiskRating:   "Medium",
		ImpactRating: "Medium",
		Complexity:   "Medium",
		Exploited:    "Yes",
		ExploitURL:   "https://www.blackhat.com/docs/asia-15/materials/asia-15-Mantins-Bar-Mitzvah-Surprise-Decrypting-SSL-Transactions-Using-Predictable-IV-In-RC4.pdf",
		Risk:         "Prediction of RC4 initial keystream",
		Impact:       "Recovery of session cookies and other credentials (Credential Theft)",
		URL:          "https://nvd.nist.gov/vuln/detail/CVE-2015-2808",
		SecondaryURL: "https://www.blackhat.com/docs/asia-15/materials/asia-15-Mantins-Bar-Mitzvah-Surprise-Decrypting-SSL-Transactions-Using-Predictable-IV-In-RC4.pdf",
	}
	VulnLogjam = Vulnerability{
		ID:           "LOGJAM",
		Label:        "LOGJAM",
		Severity:     "Medium",
		Description:  "Man-in-the-middle downgrade attack to export-grade Diffie-Hellman.",
		RiskRating:   "Medium",
		ImpactRating: "Medium",
		Complexity:   "Medium",
		Exploited:    "Yes",
		ExploitURL:   "https://weakdh.org/",
		Risk:         "Discrete logarithm computation on weak DH groups",
		Impact:       "Downgrade of TLS connections to export-grade cryptography",
		URL:          "https://nvd.nist.gov/vuln/detail/CVE-2015-4000",
		SecondaryURL: "https://weakdh.org/",
	}
	VulnFreak = Vulnerability{
		ID:           "FREAK",
		Label:        "FREAK",
		Severity:     "High",
		Description:  "Downgrade attack to 512-bit export RSA allowing near real-time decryption.",
		RiskRating:   "High",
		ImpactRating: "High",
		Complexity:   "Low",
		Exploited:    "Yes",
		ExploitURL:   "https://mitls.org/pages/attacks/FREAK",
		Risk:         "Downgrade to 512-bit export-grade RSA",
		Impact:       "Near real-time decryption of TLS session traffic (Immediate Decryption)",
		URL:          "https://nvd.nist.gov/vuln/detail/CVE-2015-0204",
		SecondaryURL: "https://mitls.org/pages/attacks/FREAK",
	}
	VulnPoodle = Vulnerability{
		ID:           "POODLE",
		Label:        "POODLE",
		Severity:     "Medium",
		Description:  "Padding oracle attack in SSL 3.0 allowing theft of secure session cookies.",
		RiskRating:   "Medium",
		ImpactRating: "Medium",
		Complexity:   "Medium",
		Exploited:    "Yes",
		ExploitURL:   "https://www.openssl.org/~bodo/ssl-poodle.pdf",
		Risk:         "Padding oracle vulnerability in SSL 3.0",
		Impact:       "Extraction of secure cookies and credentials (Information Disclosure)",
		URL:          "https://nvd.nist.gov/vuln/detail/CVE-2014-3566",
		SecondaryURL: "https://www.openssl.org/~bodo/ssl-poodle.pdf",
	}
)

// GetCipherVulnerabilities returns a list of vulnerabilities associated with a cipher suite name
func GetCipherVulnerabilities(cipher string) []Vulnerability {
	var vulns []Vulnerability
	cipherLower := strings.ToLower(cipher)

	// RSA Key Exchange (No Forward Secrecy)
	// Only if it's strictly RSA key exchange (not ECDHE-RSA)
	if strings.Contains(cipherLower, "tls_rsa_") {
		vulns = append(vulns, VulnNoPFS)
	}

	// CBC Mode (Padding Oracle / BEAST / Lucky13)
	// TLS 1.3 doesn't use CBC, so this is mostly for < 1.3
	if strings.Contains(cipherLower, "_cbc_") {
		vulns = append(vulns, VulnPaddingOracle)
	}

	// 3DES (Sweet32)
	if strings.Contains(cipherLower, "3des") {
		vulns = append(vulns, VulnSweet32)
	}

	// RC4 (RC4 vulnerabilities / Bar Mitzvah)
	if strings.Contains(cipherLower, "rc4") {
		vulns = append(vulns, VulnRC4)
	}

	// Weak Hashes (SHA1, MD5)
	if strings.HasSuffix(cipherLower, "_sha") || strings.Contains(cipherLower, "_sha1") || strings.Contains(cipherLower, "_md5") {
		vulns = append(vulns, VulnWeakHash)
	}

	// EXPORT/NULL/ANON
	if strings.Contains(cipherLower, "export") {
		vulns = append(vulns, VulnFreak)
	}

	return vulns
}
