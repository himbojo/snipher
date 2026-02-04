package models

// Policy represents the YAML schema for a security policy
type Policy struct {
	Name      string   `yaml:"name"`
	Protocols []string `yaml:"protocols"`
	Ciphers   []string `yaml:"ciphers"`
}

// ComplianceStatus represents the result of a policy check for a specific item
type ComplianceStatus int

const (
	ComplianceUnknown ComplianceStatus = iota
	ComplianceAllowed
	ComplianceViolation
)

// ComplianceResult holds the overall compliance report for a scan
type ComplianceResult struct {
	PolicyName    string
	IsCompliant   bool
	Violations    []string
	ProtocolStats map[string]ComplianceStatus
	CipherStats   map[string]ComplianceStatus
}
