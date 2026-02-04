package engine

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"testing"
	"time"
)

// Helper to generate a cert
func generateCert(t *testing.T, template, parent *x509.Certificate, pub, parentPriv interface{}) (*x509.Certificate, []byte, interface{}) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Add SubjectKeyId
	pubKey := &priv.PublicKey
	if pub != nil {
		pubKey = pub.(*rsa.PublicKey)
	}
	// Calculate SKID (simple hash of Modulus)
	// For test purposes, just random or simple logic is fine,
	// but correct way is SHA-1 of public key structure.
	// Simplifying by generating a random SKID if needed, or better, marshal pubkey.
	// Actually x509.CreateCertificate doesn't automatically add it unless we put it in template?
	// Go's CreateCertificate uses template.SubjectKeyId.

	// We'll require the caller or this function to set it.
	// Let's compute it.
	b, _ := x509.MarshalPKIXPublicKey(pubKey)
	var kid []byte
	// simple hash
	// ... skipping complex hash, just use first 20 bytes of marshaled key
	if len(b) > 20 {
		kid = b[:20]
	} else {
		kid = b
	}

	template.SubjectKeyId = kid

	if parent != nil {
		template.AuthorityKeyId = parent.SubjectKeyId
	}

	signerPriv := priv
	if parentPriv != nil {
		signerPriv = parentPriv.(*rsa.PrivateKey)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pubKey, signerPriv)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	return cert, pemBytes, priv
}

func startTLSServer(t *testing.T, certPEM, keyPEM []byte, intermediates ...[]byte) (string, func()) {
	// Build cert chain
	fullChain := append([]byte{}, certPEM...)
	for _, inter := range intermediates {
		fullChain = append(fullChain, inter...)
	}

	cert, err := tls.X509KeyPair(fullChain, keyPEM)
	if err != nil {
		t.Fatalf("failed to load keypair: %v", err)
	}

	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Handle connection in goroutine to allow concurrency
			go func(c net.Conn) {
				defer c.Close()
				tlsConn, ok := c.(*tls.Conn)
				if ok {
					// Force handshake
					if err := tlsConn.Handshake(); err != nil {
						// Handshake failed (e.g. client check)
						return
					}
				}
				// Keep open briefly or write something?
				// The client just wants to connect and get certs.
				// It might try to read?
				// Just let it return.
			}(conn)
		}
	}()

	return ln.Addr().String(), func() { ln.Close() }
}

func privKeyToPEM(priv *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
}

func TestCertificateTrustScenarios(t *testing.T) {
	// 1. Setup PKI Hierarchy: Root -> Intermediate -> Issuing -> Leaf
	rootTempl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootCert, rootPEM, rootPriv := generateCert(t, rootTempl, rootTempl, nil, nil)

	interTempl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Intermediate CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	interCert, interPEM, interPriv := generateCert(t, interTempl, rootCert, nil, rootPriv)

	issuingTempl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "Issuing CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	issuingCert, issuingPEM, issuingPriv := generateCert(t, issuingTempl, interCert, nil, interPriv)

	leafTempl := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		DNSNames:     []string{"127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafCert, leafPEM, leafPriv := generateCert(t, leafTempl, issuingCert, nil, issuingPriv)
	leafKeyPEM := privKeyToPEM(leafPriv.(*rsa.PrivateKey))
	_ = leafCert

	tests := []struct {
		name          string
		serverChain   [][]byte // Leaf is always first implicitly by startTLSServer, these are appended
		trustedBundle []byte
		expectTrusted bool
	}{
		{
			name:          "Scenario 1: Root Issues Intermediate (Full Chain Sent, Trust Root)",
			serverChain:   [][]byte{issuingPEM, interPEM}, // Leaf -> Issuing -> Intermediate
			trustedBundle: rootPEM,
			expectTrusted: true,
		},
		{
			name:          "Scenario 2: Intermediate Issues Issuing (Leaf -> Issuing Sent, Trust Intermediate)",
			serverChain:   [][]byte{issuingPEM}, // Leaf -> Issuing
			trustedBundle: interPEM,             // Intermediate is anchor
			expectTrusted: true,
		},
		{
			name:          "Scenario 3: Issuing Issues Leaf (Only Leaf Sent, Trust Issuing)",
			serverChain:   [][]byte{}, // Only Leaf
			trustedBundle: issuingPEM, // Issuing is anchor
			expectTrusted: true,
		},
		{
			name:          "Scenario 4: Explicit Leaf Trust (No Chain Sent, Trust Leaf)",
			serverChain:   [][]byte{},
			trustedBundle: leafPEM,
			expectTrusted: true,
		},
		{
			name:          "Scenario 5: Explicit Leaf Trust (Chain Sent, Trust Leaf)",
			serverChain:   [][]byte{issuingPEM},
			trustedBundle: leafPEM,
			expectTrusted: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Start server
			addr, stop := startTLSServer(t, leafPEM, leafKeyPEM, tc.serverChain...)
			defer stop()

			// Write bundle to temp file
			f, err := os.CreateTemp("", "bundle-*.pem")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer os.Remove(f.Name())
			if _, err := f.Write(tc.trustedBundle); err != nil {
				t.Fatalf("failed to write bundle: %v", err)
			}
			f.Close()

			// Run scanner
			scanner := NewStdScanner(ScannerConfig{MinTimeout: 1 * time.Second, MaxTimeout: 1 * time.Second})
			_, portStr, _ := net.SplitHostPort(addr)
			port := 0
			fmt.Sscanf(portStr, "%d", &port)

			result, err := scanner.Scan(context.Background(), "127.0.0.1", port, f.Name())
			if err != nil {
				t.Fatalf("Scan failed: %v", err)
			}
			if result.Error != nil {
				t.Logf("Scan returned internal error: %v", result.Error)
			}

			if result.IsTrusted != tc.expectTrusted {
				t.Errorf("Expected IsTrusted=%v, got %v", tc.expectTrusted, result.IsTrusted)
			}
		})
	}
}
