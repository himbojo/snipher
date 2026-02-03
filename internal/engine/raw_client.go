package engine

import (
	"context"
	"fmt"
	"net"
	"os"
	"snipher/internal/models"
	"sync"
	"time"
)

// checkLegacyProtocols detects SSLv2 and SSLv3 using manual packet construction
func (s *StdScanner) checkLegacyProtocols(ctx context.Context, target string, port int) []models.ProtocolDetails {
	address := net.JoinHostPort(target, fmt.Sprintf("%d", port))

	results := make([]models.ProtocolDetails, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		results[0] = models.ProtocolDetails{Name: "SSLv2", Supported: s.checkSSLv2(address)}
	}()

	go func() {
		defer wg.Done()
		results[1] = models.ProtocolDetails{Name: "SSLv3", Supported: s.checkSSLv3(address)}
	}()

	wg.Wait()
	return results
}

// checkSSLv3 sends a more robust SSLv3 ClientHello with SNI
func (s *StdScanner) checkSSLv3(address string) bool {
	host, _, _ := net.SplitHostPort(address)
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return false
	}
	defer conn.Close()

	// SSLv3 ClientHello with SNI
	// This is a bit more complex, we'll build it manually

	// Handshake Type (1), Length (3 bytes)
	// Version (0x0300)
	// Random (32 bytes)
	// Session ID (0)
	// Cipher Suites (2 bytes len, 2 bytes val: 0x0004)
	// Compression (1 byte len, 1 byte val: 0x00)
	// Extensions (2 bytes len, SNI...)

	sni := []byte(host)
	sniLen := uint16(len(sni))

	// SNI Extension: Type (0x0000), Length (sniLen + 5),
	// Server Name List Length (sniLen + 3),
	// Server Name Type (0x00), Server Name Length (sniLen), Server Name
	sniExt := append([]byte{0x00, 0x00},
		byte((sniLen+5)>>8), byte(sniLen+5),
		byte((sniLen+3)>>8), byte(sniLen+3),
		0x00,
		byte(sniLen>>8), byte(sniLen),
	)
	sniExt = append(sniExt, sni...)

	extsLen := uint16(len(sniExt))

	helloBody := append([]byte{
		0x03, 0x00, // Version SSL 3.0
	}, make([]byte, 32)...) // Random
	helloBody = append(helloBody, 0x00)                            // Session ID length
	helloBody = append(helloBody, 0x00, 0x02, 0x00, 0x04)          // Ciphers (RSA_WITH_RC4_128_MD5)
	helloBody = append(helloBody, 0x01, 0x00)                      // Compression
	helloBody = append(helloBody, byte(extsLen>>8), byte(extsLen)) // Extensions length
	helloBody = append(helloBody, sniExt...)

	handshakeLen := uint32(len(helloBody))
	handshake := append([]byte{
		0x01, // ClientHello
		byte(handshakeLen >> 16), byte(handshakeLen >> 8), byte(handshakeLen),
	}, helloBody...)

	recordLen := uint16(len(handshake))
	record := append([]byte{
		0x16,       // Handshake
		0x03, 0x01, // Version 3.1 (TLS 1.0) - More compatible record header
		byte(recordLen >> 8), byte(recordLen),
	}, handshake...)

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(record)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SSLv3 Write error: %v\n", err)
		return false
	}

	resp := make([]byte, 2048)
	n, err := conn.Read(resp)
	if err != nil || n < 5 {
		return false
	}

	// Look for ServerHello (0x16) or Alert (0x15)
	if resp[0] == 0x16 {
		return true
	}
	// If it responds with Alert but specifically for version mismatch, it's still "Handled"
	// but if it accepts the handshake header it's usually enough to say it supports the check.
	// But we want "Supported: true".

	return false
}

// checkSSLv2 sends a standard SSLv2 ClientHello
func (s *StdScanner) checkSSLv2(address string) bool {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return false
	}
	defer conn.Close()

	// SSLv2 ClientHello (more standard)
	// 80 2b (Length 43)
	// 01 (ClientHello)
	// 00 02 (Version SSLv2)
	// 00 12 (Ciphers length 18)
	// 00 00 (Session ID length 0)
	// 00 10 (Challenge length 16)
	// [18 bytes ciphers]
	// [16 bytes challenge]
	hello := []byte{
		0x80, 0x2b, 0x01, 0x00, 0x02, 0x00, 0x12, 0x00, 0x00, 0x00, 0x10,
		// Ciphers (mostly RC4, 3DES, DES)
		0x01, 0x00, 0x80, 0x02, 0x00, 0x80, 0x03, 0x00, 0x80, 0x04, 0x00, 0x80,
		0x05, 0x00, 0x80, 0x06, 0x00, 0x40, 0x07, 0x00, 0xc0, 0x08, 0x00, 0x80,
		// Challenge (random)
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
	}

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(hello)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SSLv2 Write error: %v\n", err)
		return false
	}

	resp := make([]byte, 2048)
	n, err := conn.Read(resp)
	if err != nil || n < 2 {
		return false
	}

	// SSLv2 ServerHello starts with a length prefix where the first bit is 1 (0x80)
	if resp[0]&0x80 != 0 {
		return true
	}

	return false
}
