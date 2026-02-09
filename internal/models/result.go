package models

import "time"

// CertSummary provides a brief overview of a certificate in a chain
type CertSummary struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	SerialNumber string    `json:"serial_number"`
	NotAfter     time.Time `json:"not_after"`
	IsTrusted    bool      `json:"-"`
	IsAnchor     bool      `json:"is_anchor"`
}

// ProtocolDetails represents the support status of a specific TLS protocol version
type ProtocolDetails struct {
	Name      string   `json:"name"`
	Supported bool     `json:"supported"`
	Ciphers   []string `json:"ciphers,omitempty"`
}

// ScanResult represents the combined results of all scanning engines
type ScanResult struct {
	Target    string        `json:"host"`
	IP        string        `json:"ip"`
	Port      int           `json:"port"`
	Timestamp time.Time     `json:"timestamp"`
	Latency   time.Duration `json:"latency"`

	// Protocol Enumeration
	Protocols []ProtocolDetails `json:"protocols,omitempty"`

	// Certificate info (Leaf)
	SerialNumber string    `json:"serial_number,omitempty"`
	NotAfter     time.Time `json:"not_after,omitempty"`
	Issuer       string    `json:"issuer,omitempty"`
	Subject      string    `json:"subject,omitempty"`
	DNSNames     []string  `json:"dns_names,omitempty"`
	IsTrusted    bool      `json:"-"`

	// Full Trust Chain
	Chain []CertSummary `json:"chain,omitempty"`

	// Error handling
	Error    error  `json:"-"`
	ErrorMsg string `json:"errors,omitempty"`

	// Observability
	Metrics *ScanMetrics `json:"metrics,omitempty"`
}

// ScanMetrics holds telemetry data about the scan
type ScanMetrics struct {
	StartTime      time.Time     `json:"start_time"`
	EndTime        time.Time     `json:"end_time"`
	Duration       time.Duration `json:"duration"`
	CipherCount    int           `json:"cipher_count"`
	HandshakeCount int           `json:"handshake_count"` // Estimated
	ErrorCount     int           `json:"error_count"`
}
