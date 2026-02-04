package engine

import (
	"fmt"
	"os"
	"snipher/internal/models"

	"gopkg.in/yaml.v3"
)

// LoadPolicy parses a YAML policy file
func LoadPolicy(path string) (*models.Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	var policy models.Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy YAML: %w", err)
	}

	return &policy, nil
}

// CheckCompliance evaluates a scan result against a policy
func CheckCompliance(res models.ScanResult, policy models.Policy) models.ComplianceResult {
	report := models.ComplianceResult{
		PolicyName:    policy.Name,
		IsCompliant:   true,
		ProtocolStats: make(map[string]models.ComplianceStatus),
		CipherStats:   make(map[string]models.ComplianceStatus),
	}

	// 1. Check Protocols
	allowedProtos := make(map[string]bool)
	for _, p := range policy.Protocols {
		allowedProtos[p] = true
	}

	for _, p := range res.Protocols {
		if !p.Supported {
			continue
		}

		if allowedProtos[p.Name] {
			report.ProtocolStats[p.Name] = models.ComplianceAllowed
		} else {
			report.ProtocolStats[p.Name] = models.ComplianceViolation
			report.IsCompliant = false
			report.Violations = append(report.Violations, fmt.Sprintf("Protocol %s is not allowed by policy", p.Name))
		}
	}

	// 2. Check Ciphers
	allowedCiphers := make(map[string]bool)
	for _, c := range policy.Ciphers {
		allowedCiphers[c] = true
		// Support OpenSSL mapping for matching
		// If user provides IANA, we store IANA.
		// If user provides OpenSSL, we store OpenSSL.
		// Matching logic will check both.
	}

	for _, p := range res.Protocols {
		if !p.Supported {
			continue
		}

		for _, c := range p.Ciphers {
			ianaName := c
			osslName := ToOpenSSL(ianaName)

			if allowedCiphers[ianaName] || allowedCiphers[osslName] {
				report.CipherStats[ianaName] = models.ComplianceAllowed
			} else {
				report.CipherStats[ianaName] = models.ComplianceViolation
				report.IsCompliant = false
				report.Violations = append(report.Violations, fmt.Sprintf("Cipher %s (%s) is not allowed by policy", ianaName, osslName))
			}
		}
	}

	return report
}
