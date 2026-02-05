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

	// ✅ Fix #16: Validate parsed policy
	if err := validatePolicy(&policy); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}

	return &policy, nil
}

// validatePolicy checks if the policy has valid data
func validatePolicy(policy *models.Policy) error {
	if policy.Name == "" {
		return fmt.Errorf("policy name is required")
	}
	if len(policy.Protocols) == 0 {
		return fmt.Errorf("policy must specify at least one allowed protocol")
	}
	if len(policy.Ciphers) == 0 {
		return fmt.Errorf("policy must specify at least one allowed cipher")
	}

	// Validate protocol names
	validProtocols := map[string]bool{
		"TLS 1.0": true,
		"TLS 1.1": true,
		"TLS 1.2": true,
		"TLS 1.3": true,
	}
	for _, proto := range policy.Protocols {
		if !validProtocols[proto] {
			return fmt.Errorf("invalid protocol name: %s (must be one of: TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3)", proto)
		}
	}

	return nil
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
