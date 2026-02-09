package engine

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	// TLS Record Types
	recordTypeHandshake = 0x16

	// Handshake Types
	handshakeTypeClientHello = 0x01

	// TLS Versions
	tlsVersion10 = 0x0301

	// Lengths
	randomBytesLength = 32
	sessionIDLength   = 0
	cipherSuitesLen   = 2 // 1 cipher * 2 bytes
	compressionLen    = 1

	// Values
	randomByteVal    = 0xAA
	compressionNull  = 0x00
	extensionTypeSNI = 0x0000
	sniTypeHostName  = 0x00
)

// makeClientHello constructs a raw ClientHello message with the specified cipher ID, SNI, and protocol version.
func makeClientHello(cipherID uint16, hostname string, version uint16) []byte {
	// --- Body Construction ---

	// Protocol Version: Use the version we are probing for
	handshakeBody := []byte{byte(version >> 8), byte(version)}

	// Random (32 bytes)
	// In a real scenario we should generate random bytes, but for scanning zeroes or static is mostly fine
	// unless the server requires unique randoms for replay protection (rare for just ClientHello).
	// Let's use a static random for stability/determinism in tests.
	// 0xAA...AA
	randomBytes := make([]byte, randomBytesLength)
	for i := range randomBytes {
		randomBytes[i] = randomByteVal
	}
	handshakeBody = append(handshakeBody, randomBytes...)

	// Session ID Length (0)
	handshakeBody = append(handshakeBody, byte(sessionIDLength))

	// Cipher Suites Length (2 bytes) -> Value: 2 bytes (1 cipher)
	handshakeBody = append(handshakeBody, 0x00, byte(cipherSuitesLen))

	// Cipher Suite (The one we are probing)
	cs := make([]byte, 2)
	binary.BigEndian.PutUint16(cs, cipherID)
	handshakeBody = append(handshakeBody, cs...)

	// Compression Methods (1 byte len) -> Value: 0x00 (Null)
	handshakeBody = append(handshakeBody, byte(compressionLen), compressionNull)

	// --- Extensions ---
	// Start of Extensions block

	// We will build a list of extensions.
	// 1. Supported Groups (0x000a) - Essential for ECDHE
	// 2. EC Point Formats (0x000b) - Essential for ECDHE
	// 3. Signature Algorithms (0x000d) - Essential for TLS 1.2+
	// 4. SNI (0x0000)

	extensionsBody := []byte{}

	// 1. Supported Groups (0x000a)
	// List: X25519 (0x001d), P-256 (0x0017), P-384 (0x0018)
	supGroupsPayload := []byte{
		0x00, 0x06, // List Length
		0x00, 0x1d, // X25519
		0x00, 0x17, // P-256
		0x00, 0x18, // P-384
	}
	extensionsBody = append(extensionsBody, 0x00, 0x0a)                         // Type
	extensionsBody = append(extensionsBody, 0x00, uint8(len(supGroupsPayload))) // Length (short, so byte cast safe)
	extensionsBody = append(extensionsBody, supGroupsPayload...)

	// 2. EC Point Formats (0x000b)
	// List: uncompressed (0x00)
	ecPointsPayload := []byte{
		0x01, // List Length
		0x00, // uncompressed
	}
	extensionsBody = append(extensionsBody, 0x00, 0x0b)
	extensionsBody = append(extensionsBody, 0x00, uint8(len(ecPointsPayload)))
	extensionsBody = append(extensionsBody, ecPointsPayload...)

	// 3. Signature Algorithms (0x000d)
	// List: ECDSA+SHA256 (0x0403), RSA+SHA256 (0x0401), RSA+SHA1 (0x0201) etc.
	// Modern sane defaults.
	sigAlgsPayload := []byte{
		0x00, 0x08, // List Length
		0x04, 0x03, // ecdsa_secp256r1_sha256
		0x04, 0x01, // rsa_pkcs1_sha256
		0x02, 0x01, // rsa_pkcs1_sha1 (compat)
		0x05, 0x01, // rsa_pkcs1_sha384
	}
	extensionsBody = append(extensionsBody, 0x00, 0x0d)
	extensionsBody = append(extensionsBody, 0x00, uint8(len(sigAlgsPayload)))
	extensionsBody = append(extensionsBody, sigAlgsPayload...)

	// 4. SNI (0x0000)
	// Structure: [ListLen 2][Type 1][NameLen 2][Name bytes]
	sniContent := []byte{}
	nameLen := uint16(len(hostname))

	// List Length (NameLen + 3 bytes for Type and NameLen field)
	listLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(listLenBytes, nameLen+3)
	sniContent = append(sniContent, listLenBytes...)

	// Type (0x00 for HostName)
	sniContent = append(sniContent, sniTypeHostName)

	// Name Length
	nameLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(nameLenBytes, nameLen)
	sniContent = append(sniContent, nameLenBytes...)

	// The Hostname string
	sniContent = append(sniContent, []byte(hostname)...)

	// Append SNI extension container
	extensionsBody = append(extensionsBody, byte(extensionTypeSNI>>8), byte(extensionTypeSNI)) // Type
	extLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(extLenBytes, uint16(len(sniContent)))
	extensionsBody = append(extensionsBody, extLenBytes...)
	extensionsBody = append(extensionsBody, sniContent...)

	// 5. Append All Extensions to Handshake Body
	// Total Extensions Length (2 bytes)
	totalExtLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(totalExtLenBytes, uint16(len(extensionsBody)))
	handshakeBody = append(handshakeBody, totalExtLenBytes...)
	handshakeBody = append(handshakeBody, extensionsBody...)

	// --- Handshake Header ---
	// Msg Type (0x01 ClientHello)
	// Message Length (3 bytes)
	handshakeHeader := []byte{handshakeTypeClientHello, 0x00}
	msgLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(msgLenBytes, uint16(len(handshakeBody)))
	handshakeHeader = append(handshakeHeader, msgLenBytes...)

	fullHandshake := append(handshakeHeader, handshakeBody...)

	// --- Record Header ---
	// Content Type (0x16 Handshake)
	// Version (0x0301 - TLS 1.0 framing for compatibility)
	// Length (2 bytes)
	recordHeader := []byte{recordTypeHandshake, byte(tlsVersion10 >> 8), byte(tlsVersion10 & 0xFF)}
	recLen := make([]byte, 2)
	binary.BigEndian.PutUint16(recLen, uint16(len(fullHandshake)))
	recordHeader = append(recordHeader, recLen...)

	return append(recordHeader, fullHandshake...)
}

// checkCipherSupport probes the target for support of the given cipher ID with specific protocol version.
// It returns true if the server accepts the cipher, false otherwise.
func checkCipherSupport(ctx context.Context, target string, cipherID uint16, hostname string, version uint16) (bool, error) {
	// 1. Connect via TCP with Retry (3 attempts)
	var conn net.Conn
	var err error
	maxRetries := 3
	d := net.Dialer{Timeout: 5 * time.Second}

	for attempt := 0; attempt < maxRetries; attempt++ {
		// Check context before dialing
		if ctx.Err() != nil {
			return false, ctx.Err()
		}

		conn, err = d.DialContext(ctx, "tcp", target)
		if err == nil {
			break
		}
		// Exponential backoff: 500ms, 1s, 2s...
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(time.Duration(500*(1<<attempt)) * time.Millisecond):
			// continue
		}
	}
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// 2. Construct ClientHello with SNI
	clientHello := makeClientHello(cipherID, hostname, version)

	// ✅ Fix #14: Set deadline BEFORE write operation
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 3. Send ClientHello
	_, err = conn.Write(clientHello)
	if err != nil {
		return false, fmt.Errorf("failed to send ClientHello: %w", err)
	}

	// 4. Read Response Header (TLS Record Header is 5 bytes)
	header := make([]byte, 5)
	_, err = io.ReadFull(conn, header)
	if err != nil {
		// EOF often means the server saw our cipher list, hated it, and hung up.
		// This counts as "Not Supported".
		return false, nil
	}

	// Check if response is a Handshake (0x16)
	if header[0] != 0x16 {
		// Likely an Alert (0x15) or garbage. Alert levels: 1=Warning, 2=Fatal.
		// If Alert, it means rejected.
		return false, nil
	}

	// Read the rest of the message based on length in header
	length := binary.BigEndian.Uint16(header[3:5])
	body := make([]byte, length)
	_, err = io.ReadFull(conn, body)
	if err != nil {
		return false, nil
	}

	// 5. Parse ServerHello
	// Handshake Type 0x02 is ServerHello
	if body[0] != 0x02 {
		return false, nil
	}

	// Parse offsets manually
	// [MsgType 1][Len 3][Ver 2][Random 32] = 38 bytes
	if len(body) < 38 {
		return false, nil
	}

	idx := 38
	sessionIDLen := int(body[idx])
	idx++ // Move past ID length byte

	idx += sessionIDLen // Skip Session ID

	if len(body) < idx+2 {
		return false, nil
	}

	// The next 2 bytes are the Cipher Suite the server selected
	selectedCipher := binary.BigEndian.Uint16(body[idx : idx+2])

	return selectedCipher == cipherID, nil
}
