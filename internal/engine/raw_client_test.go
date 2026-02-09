package engine

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestMakeClientHello(t *testing.T) {
	cipherID := uint16(0xC02F) // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	hostname := "example.com"
	version := uint16(0x0303) // TLS 1.2

	req := makeClientHello(cipherID, hostname, version)

	// Minimal length check
	if len(req) < 40 {
		t.Errorf("ClientHello too short: %d", len(req))
	}

	// Check Record Header
	if req[0] != 0x16 {
		t.Errorf("Expected Handshake Record Type (0x16), got 0x%x", req[0])
	}
	if req[1] != 0x03 || req[2] != 0x01 {
		t.Errorf("Expected TLS 1.0 framing (0x0301), got 0x%02x%02x", req[1], req[2])
	}

	// Check Handshake Header
	// Record header is 5 bytes
	handshake := req[5:]
	if handshake[0] != 0x01 {
		t.Errorf("Expected ClientHello Handshake Type (0x01), got 0x%x", handshake[0])
	}

	// Check Protocol Version in Body
	// Handshake Header is 4 bytes (Type + Len)
	body := handshake[4:]
	ver := binary.BigEndian.Uint16(body[0:2])
	if ver != version {
		t.Errorf("Expected version 0x%x, got 0x%x", version, ver)
	}

	// Check Cipher Suite (skip Random 32, SessionID 1, CipherLen 2)
	// Offset = 2 + 32 + 1 + 2 = 37
	cipherOffset := 37
	if len(body) < cipherOffset+2 {
		t.Fatal("Body too short for cipher suite")
	}
	extractedCipher := binary.BigEndian.Uint16(body[cipherOffset : cipherOffset+2])
	if extractedCipher != cipherID {
		t.Errorf("Expected cipher 0x%x, got 0x%x", cipherID, extractedCipher)
	}

	// Check SNI presence (quick scan for hostname bytes)
	if !bytes.Contains(req, []byte(hostname)) {
		t.Error("ClientHello does not contain hostname")
	}
}
