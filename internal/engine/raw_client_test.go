package engine

import (
	"bytes"
	"testing"
)

func TestMakeClientHello(t *testing.T) {
	cipherID := uint16(0x0033) // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
	hostname := "example.com"

	hello := makeClientHello(cipherID, hostname, 0x0303)

	// Minimal length check (Header 5 + HandshakeHeader 4 + Version 2 + Random 32 + SessID 1 + CipherLen 2 + Cipher 2 + CompLen 1 + Comp 1 + ExtLen 2 + Exts...)
	// With extensions, it should be much larger than 50
	if len(hello) < 100 {
		t.Errorf("ClientHello too short: %d bytes", len(hello))
	}

	// Check Record Header
	// Content Type: Handshake (22 -> 0x16)
	if hello[0] != 0x16 {
		t.Errorf("Expected Record Type 0x16, got 0x%02X", hello[0])
	}
	// Version: TLS 1.0 (0x0301) for compatibility in record layer
	if hello[1] != 0x03 || hello[2] != 0x01 {
		t.Errorf("Expected Record Version 0x0301, got 0x%02X%02X", hello[1], hello[2])
	}

	// Check Handshake Header
	// Message Type: ClientHello (1)
	// We need to skip the 5 byte record header
	handshake := hello[5:]
	if handshake[0] != 0x01 {
		t.Errorf("Expected Handshake Type 0x01 (ClientHello), got 0x%02X", handshake[0])
	}

	// Check Cipher Suite presence
	// This is hard to parse dynamically without full parser, but we can search for the byte sequence
	cipherBytes := []byte{0x00, 0x33}
	if !bytes.Contains(handshake, cipherBytes) {
		t.Errorf("ClientHello does not contain cipher suite 0x0033")
	}

	// Check SNI presence
	if !bytes.Contains(handshake, []byte("example.com")) {
		t.Errorf("ClientHello does not contain SNI hostname")
	}
}
