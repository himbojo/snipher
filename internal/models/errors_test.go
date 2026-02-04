package models

import (
	"testing"
	"time"
)

func TestHasCriticalIssues_ExpiredCert(t *testing.T) {
	result := ScanResult{
		NotAfter:  time.Now().Add(-24 * time.Hour), // Expired yesterday
		IsTrusted: true,
	}

	if !result.HasCriticalIssues() {
		t.Error("Expected HasCriticalIssues to return true for expired certificate")
	}
}

func TestHasCriticalIssues_UntrustedCert(t *testing.T) {
	result := ScanResult{
		NotAfter:  time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		IsTrusted: false,
	}

	if !result.HasCriticalIssues() {
		t.Error("Expected HasCriticalIssues to return true for untrusted certificate")
	}
}

// Tests regarding SSLv2/SSLv3 removal - deleted

func TestHasCriticalIssues_NoCriticalIssues(t *testing.T) {
	result := ScanResult{
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		IsTrusted: true,
		Protocols: []ProtocolDetails{
			{Name: "TLS 1.2", Supported: true},
			{Name: "TLS 1.3", Supported: true},
		},
	}

	if result.HasCriticalIssues() {
		t.Error("Expected HasCriticalIssues to return false for valid certificate and modern protocols")
	}
}

func TestDetermineExitCode_OperationalError(t *testing.T) {
	result := ScanResult{}
	err := &OperationalError{Msg: "DNS lookup failed"}

	exitCode := DetermineExitCode(result, err)
	if exitCode != ExitOperational {
		t.Errorf("Expected exit code %d for operational error, got %d", ExitOperational, exitCode)
	}
}

func TestDetermineExitCode_CriticalIssue(t *testing.T) {
	result := ScanResult{
		NotAfter:  time.Now().Add(-24 * time.Hour), // Expired
		IsTrusted: true,
	}

	exitCode := DetermineExitCode(result, nil)
	if exitCode != ExitCritical {
		t.Errorf("Expected exit code %d for critical issue, got %d", ExitCritical, exitCode)
	}
}

func TestDetermineExitCode_Success(t *testing.T) {
	result := ScanResult{
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		IsTrusted: true,
		Protocols: []ProtocolDetails{
			{Name: "TLS 1.2", Supported: true},
		},
	}

	exitCode := DetermineExitCode(result, nil)
	if exitCode != ExitSuccess {
		t.Errorf("Expected exit code %d for success, got %d", ExitSuccess, exitCode)
	}
}

func TestGetCriticalIssueMessage_ExpiredCert(t *testing.T) {
	result := ScanResult{
		NotAfter:  time.Now().Add(-24 * time.Hour),
		IsTrusted: true,
	}

	msg := result.GetCriticalIssueMessage()
	expected := "Certificate is EXPIRED"
	if msg != expected {
		t.Errorf("Expected message %q, got %q", expected, msg)
	}
}

func TestGetCriticalIssueMessage_UntrustedCert(t *testing.T) {
	result := ScanResult{
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		IsTrusted: false,
	}

	msg := result.GetCriticalIssueMessage()
	expected := "Certificate is UNTRUSTED"
	if msg != expected {
		t.Errorf("Expected message %q, got %q", expected, msg)
	}
}

// TestGetCriticalIssueMessage_LegacyProtocol removed

func TestGetCriticalIssueMessage_NoIssues(t *testing.T) {
	result := ScanResult{
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		IsTrusted: true,
	}

	msg := result.GetCriticalIssueMessage()
	if msg != "" {
		t.Errorf("Expected empty message for no issues, got %q", msg)
	}
}
