package models

import (
	"time"
)

// Exit code constants as per FR12, FR13, FR14
const (
	ExitSuccess     = 0 // Scan completed successfully, no critical issues
	ExitCritical    = 1 // Critical security issue found (expired cert, SSLv2/v3, etc.)
	ExitOperational = 2 // Operational error (DNS failure, connection timeout, invalid input)
)

// CriticalError represents an error that should trigger Exit Code 1
type CriticalError struct {
	Msg string
}

func (e *CriticalError) Error() string { return e.Msg }

// OperationalError represents an error that should trigger Exit Code 2
type OperationalError struct {
	Msg string
}

func (e *OperationalError) Error() string { return e.Msg }

// WarningError represents a non-critical issue (doesn't affect exit code)
type WarningError struct {
	Msg string
}

func (e *WarningError) Error() string { return e.Msg }

// HasCriticalIssues checks if the scan result contains any critical security issues
func (r *ScanResult) HasCriticalIssues() bool {
	// Check for expired certificate
	if !r.NotAfter.IsZero() {
		if time.Now().After(r.NotAfter) {
			return true
		}
	}

	// Check for untrusted certificate
	if !r.NotAfter.IsZero() && !r.IsTrusted {
		return true
	}

	// Check for legacy protocols (SSLv2, SSLv3) - Removed
	// We no longer scan for these, but if they were somehow present, they would be critical.
	// Since detection logic is gone, this check is redundant.

	return false
}

// DetermineExitCode analyzes the scan result and returns the appropriate exit code
func DetermineExitCode(result ScanResult, scanErr error) int {
	// If there was a scan error, it's operational (DNS, connection, etc.)
	if scanErr != nil {
		return ExitOperational
	}

	// Check for critical security issues
	if result.HasCriticalIssues() {
		return ExitCritical
	}

	// No critical issues found - success
	return ExitSuccess
}

// GetCriticalIssueMessage returns a descriptive message for critical issues found
func (r *ScanResult) GetCriticalIssueMessage() string {
	// Check for expired certificate
	if !r.NotAfter.IsZero() && time.Now().After(r.NotAfter) {
		return "Certificate is EXPIRED"
	}

	// Check for untrusted certificate
	if !r.NotAfter.IsZero() && !r.IsTrusted {
		return "Certificate is UNTRUSTED"
	}

	return ""
}
