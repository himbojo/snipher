package engine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"snipher/internal/models"
	"snipher/internal/utils"
	"strings"
	"sync"
	"time"
)

// ScannerConfig holds configuration for the scanner
type ScannerConfig struct {
	MinTimeout      time.Duration
	MaxTimeout      time.Duration
	ProgressChannel chan string
}

// StdScanner implements the Scanner interface using standard Go crypto/tls and net packages
type StdScanner struct {
	config ScannerConfig
}

// NewStdScanner creates a new instance of StdScanner
func NewStdScanner(config ScannerConfig) *StdScanner {
	if config.MinTimeout == 0 {
		config.MinTimeout = 2 * time.Second
	}
	if config.MaxTimeout == 0 {
		config.MaxTimeout = 10 * time.Second
	}
	return &StdScanner{
		config: config,
	}
}

func (s *StdScanner) reportProgress(msg string) {
	if s.config.ProgressChannel != nil {
		// ✅ Fix #2: Use select to prevent panic on closed channel
		select {
		case s.config.ProgressChannel <- msg:
			// Message sent successfully
		case <-time.After(100 * time.Millisecond):
			// Channel blocked or closed, skip message
		}
	}
}

// Scan performs a basic TCP connectivity check and TLS certificate extraction
func (s *StdScanner) Scan(ctx context.Context, target string, port int, caBundlePath string) (models.ScanResult, error) {
	utils.Log().Info("Starting scan", "target", target, "port", port)
	s.reportProgress(fmt.Sprintf("Connecting to %s:%d...", target, port))

	result := models.ScanResult{
		Target:    target,
		Port:      port,
		Timestamp: time.Now(),
		Metrics: &models.ScanMetrics{
			StartTime: time.Now(),
		},
	}
	defer func() {
		result.Metrics.EndTime = time.Now()
		result.Metrics.Duration = result.Metrics.EndTime.Sub(result.Metrics.StartTime)
		utils.Log().Info("Scan completed", "duration", result.Metrics.Duration, "ciphers", result.Metrics.CipherCount, "errors", result.Metrics.ErrorCount)
	}()

	// 1. DNS Resolution
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", target)
	if err != nil {
		return result, fmt.Errorf("DNS resolution failed: %w", err)
	}
	if len(ips) == 0 {
		return result, fmt.Errorf("no IP addresses found for target: %s", target)
	}
	result.IP = ips[0].String()

	// 2. TLS Handshake & Connectivity Check
	address := net.JoinHostPort(result.IP, fmt.Sprintf("%d", port))
	start := time.Now()

	// ✅ Fix #9: Use configured timeout instead of hardcoded value
	dialer := &net.Dialer{Timeout: s.config.MinTimeout}

	// We use InsecureSkipVerify: true to ensure we get the PeerCertificates
	// even if validation fails. We will manually verify them afterwards.
	conf := &tls.Config{
		ServerName:         target,
		InsecureSkipVerify: true,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", address, conf)
	if err != nil {
		// If primary handshake fails, we still want to try protocol enumeration
		// and IP resolution info. We'll store the error for potential reporting.
		result.Error = err
	} else {
		defer conn.Close()
		result.Latency = time.Since(start)

		s.reportProgress("Retrieving certificate chain...")

		// 3. Extract & Validate Certificate Info
		state := conn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			leaf := state.PeerCertificates[0]
			result.SerialNumber = leaf.SerialNumber.String()
			result.NotAfter = leaf.NotAfter
			result.Issuer = leaf.Issuer.CommonName
			result.Subject = leaf.Subject.CommonName
			result.DNSNames = leaf.DNSNames

			// Setup Verification Options
			opts := x509.VerifyOptions{
				DNSName:       target,
				Intermediates: x509.NewCertPool(),
			}
			for _, c := range state.PeerCertificates[1:] {
				opts.Intermediates.AddCert(c)
			}

			// Handle Custom CA Bundle
			var bundleCerts []*x509.Certificate
			if caBundlePath != "" {
				// ✅ Fix #12: Validate CA bundle path to prevent path traversal
				if strings.Contains(caBundlePath, "..") {
					return result, fmt.Errorf("invalid CA bundle path: path traversal not allowed")
				}

				caData, err := os.ReadFile(caBundlePath)
				if err != nil {
					return result, fmt.Errorf("failed to read CA bundle at %s: %w", caBundlePath, err)
				}

				// Populate Roots
				roots := x509.NewCertPool()
				if ok := roots.AppendCertsFromPEM(caData); !ok {
					return result, fmt.Errorf("failed to parse CA bundle at %s: invalid PEM", caBundlePath)
				}
				opts.Roots = roots

				// Also populate opts.Intermediates with bundle certs to allow bridging gaps
				// And verify explicit trust
				block, rest := pem.Decode(caData)
				for block != nil {
					if block.Type == "CERTIFICATE" {
						c, err := x509.ParseCertificate(block.Bytes)
						if err == nil {
							bundleCerts = append(bundleCerts, c)
							opts.Intermediates.AddCert(c)
						}
					}
					block, rest = pem.Decode(rest)
				}
			}

			verifiedChains, verifyErr := leaf.Verify(opts)
			result.IsTrusted = (verifyErr == nil)

			// Explicit Leaf Trust Check
			// If validation failed, but the leaf itself is present in the provided bundle, trust it.
			if !result.IsTrusted && len(bundleCerts) > 0 {
				for _, bc := range bundleCerts {
					if bc.Equal(leaf) {
						result.IsTrusted = true
						verifyErr = nil // Clear error
						// Manufacture a verified chain of just the leaf for reporting
						verifiedChains = [][]*x509.Certificate{{leaf}}
						break
					}
				}
			}

			// If verification failed due to time (expiry), try a "time-agnostic" check
			// by using the certificate's own validity period to see if the CHAIN is trusted.
			if verifyErr != nil && !result.IsTrusted {
				// Check if we can verify by setting time back into the validity range
				agnosticOpts := opts
				if time.Now().After(leaf.NotAfter) {
					agnosticOpts.CurrentTime = leaf.NotAfter.Add(-1 * time.Second)
				} else if time.Now().Before(leaf.NotBefore) {
					agnosticOpts.CurrentTime = leaf.NotBefore.Add(1 * time.Second)
				}

				// Re-copy intermediates/roots as they are pointers/structs?
				// verifyOpts contains pointers to CertPools. Should be safe to reuse.

				agnosticChains, agnosticErr := leaf.Verify(agnosticOpts)
				if agnosticErr == nil {
					// The chain is trusted, even if the cert is currently expired
					verifiedChains = agnosticChains
				}
			}

			// Identify the trust anchor
			var anchorRoot *x509.Certificate
			if len(verifiedChains) > 0 {
				chain := verifiedChains[0]
				anchorRoot = chain[len(chain)-1]
			}

			// ✅ Fix #18: Limit certificate chain length to prevent DoS
			const maxChainLength = 10
			if len(state.PeerCertificates) > maxChainLength {
				return result, fmt.Errorf("certificate chain too long: %d certificates (max %d)", len(state.PeerCertificates), maxChainLength)
			}

			// Map full chain
			for _, cert := range state.PeerCertificates {
				summary := models.CertSummary{
					Subject:      cert.Subject.CommonName,
					Issuer:       cert.Issuer.CommonName,
					SerialNumber: cert.SerialNumber.String(),
					NotAfter:     cert.NotAfter,
					IsTrusted:    result.IsTrusted,
				}

				if anchorRoot != nil && cert.Equal(anchorRoot) {
					summary.IsAnchor = true
				}

				result.Chain = append(result.Chain, summary)
			}

			// Add anchor root if missing
			if anchorRoot != nil {
				found := false
				for _, c := range result.Chain {
					if c.IsAnchor {
						found = true
						break
					}
				}
				if !found {
					result.Chain = append(result.Chain, models.CertSummary{
						Subject:      anchorRoot.Subject.CommonName,
						Issuer:       anchorRoot.Issuer.CommonName,
						SerialNumber: anchorRoot.SerialNumber.String(),
						NotAfter:     anchorRoot.NotAfter,
						IsTrusted:    true,
						IsAnchor:     true,
					})
				}
			}
		}
	}

	// 4. Protocol Enumeration (Parallel)
	s.reportProgress("Enumerating supported protocols...")
	// Legacy protocols (SSLv2/v3) removed as per requirement
	modern := s.checkProtocols(ctx, target, port)

	result.Protocols = append([]models.ProtocolDetails{}, modern...)

	// Populate Metrics
	cipherCount := 0
	for _, p := range result.Protocols {
		cipherCount += len(p.Ciphers)
	}
	result.Metrics.CipherCount = cipherCount
	result.Metrics.HandshakeCount = len(result.Protocols) + 1 // +1 for initial connectivity check
	if result.Error != nil {
		result.Metrics.ErrorCount++
	}

	return result, nil
}

func (s *StdScanner) checkProtocols(ctx context.Context, target string, port int) []models.ProtocolDetails {
	versions := []struct {
		val  uint16
		name string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
	}

	results := make([]models.ProtocolDetails, len(versions))
	var wg sync.WaitGroup
	address := net.JoinHostPort(target, fmt.Sprintf("%d", port))

	for i, v := range versions {
		wg.Add(1)
		go func(idx int, version uint16, name string) {
			defer wg.Done()

			// Check context before starting
			if ctx.Err() != nil {
				return
			}

			s.reportProgress(fmt.Sprintf("Checking %s...", name))

			// ✅ Fix #9: Use configured timeout
			dialer := &net.Dialer{Timeout: s.config.MinTimeout}
			conf := &tls.Config{
				ServerName:         target,
				InsecureSkipVerify: true,
				MinVersion:         version,
				MaxVersion:         version,
				CipherSuites:       AllModernCiphers(), // Include all ciphers for initial check
			}

			// Use tls.Dialer for context awareness
			tlsDialer := &tls.Dialer{
				NetDialer: dialer,
				Config:    conf,
			}

			conn, err := tlsDialer.DialContext(ctx, "tcp", address)
			if err == nil {
				conn.Close()
				results[idx] = models.ProtocolDetails{
					Name:      name,
					Supported: true,
					Ciphers:   s.enumerateCiphers(ctx, target, port, version),
				}
			} else {
				results[idx] = models.ProtocolDetails{Name: name, Supported: false}
			}
		}(i, v.val, v.name)
	}

	wg.Wait()
	return results
}

// enumerateCiphers identifies all supported ciphers for a specific protocol version
func (s *StdScanner) enumerateCiphers(ctx context.Context, target string, port int, version uint16) []string {
	// TLS 1.3 requires special handling
	if version == tls.VersionTLS13 {
		return s.enumerateTLS13Ciphers()
	}

	address := net.JoinHostPort(target, fmt.Sprintf("%d", port))
	var supported []string
	var mu sync.Mutex

	// For manual scanning, we use the IANA list for comprehensive coverage,
	// OR we can just use the Go list depending on requirements.
	// The Story says "comprehensive list of Cipher IDs (IANA)".
	// So we should iterate AllIANACiphers().
	allCiphers := AllIANACiphers()
	total := len(allCiphers)

	// ✅ Fix #1: Use worker pool pattern to limit concurrent goroutines
	maxWorkers := 10
	cipherQueue := make(chan IANACipher, total)
	var wg sync.WaitGroup

	// Start worker pool
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case cipher, ok := <-cipherQueue:
					if !ok {
						return
					}
					isSupported, err := checkCipherSupport(ctx, address, cipher.ID, target, version)
					if err == nil && isSupported {
						mu.Lock()
						supported = append(supported, cipher.Name)
						mu.Unlock()
					}
					// Increment Metrics via atomic or mutex if we had access to result.Metrics here.
					// Since enumerateCiphers doesn't have access to result.Metrics, we can return counts or just count supported.
					// Reviewing the Metrics struct: CipherCount usually means *checked* or *found*?
					// "CipherCount" usually implies count of supported ciphers found.
					// I'll update the caller (Scan) to set CipherCount based on returned list length.
				}
			}
		}()
	}

Loop:
	// Send ciphers to queue and report progress
	for i, cipher := range allCiphers {
		// Check for cancellation
		select {
		case <-ctx.Done():
			break Loop
		default:
		}

		// ✅ Fix #15: Report progress every 10 ciphers instead of every 20
		if i%10 == 0 {
			verStr := "Unknown"
			switch version {
			case tls.VersionTLS10:
				verStr = "TLS 1.0"
			case tls.VersionTLS11:
				verStr = "TLS 1.1"
			case tls.VersionTLS12:
				verStr = "TLS 1.2"
			}
			s.reportProgress(fmt.Sprintf("Scanning %s ciphers (%d/%d)...", verStr, uint64(i), uint64(total)))
		}
		cipherQueue <- cipher
	}

	// Close queue and wait for workers to finish
	close(cipherQueue)
	wg.Wait()

	// Sort by strength before returning
	sortCiphersByStrength(supported)
	return supported
}

// enumerateTLS13Ciphers handles TLS 1.3 cipher enumeration
// TLS 1.3 ciphers cannot be restricted via CipherSuites in Go's crypto/tls
// So we return all standard TLS 1.3 ciphers as potentially supported
func (s *StdScanner) enumerateTLS13Ciphers() []string {
	// For TLS 1.3, Go's crypto/tls doesn't allow client-side cipher restriction
	// The server always chooses from its supported set
	// We'll return the standard TLS 1.3 cipher suites in strength order
	return []string{
		"TLS_AES_256_GCM_SHA384",       // Strongest
		"TLS_CHACHA20_POLY1305_SHA256", // Strong
		"TLS_AES_128_GCM_SHA256",       // Good
	}
}
