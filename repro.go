package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// Copied from internal/engine/ciphers.go
func AllModernCiphers() []uint16 {
	var ids []uint16
	for _, suite := range tls.CipherSuites() {
		ids = append(ids, suite.ID)
	}
	for _, suite := range tls.InsecureCipherSuites() {
		ids = append(ids, suite.ID)
	}
	return ids
}

func main() {
	target := "127.0.0.1"
	port := 4443
	address := fmt.Sprintf("%s:%d", target, port)

	fmt.Printf("Connecting to %s...\n", address)

	versions := []struct {
		val  uint16
		name string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
	}

	for _, v := range versions {
		fmt.Printf("Testing %s...\n", v.name)
		dialer := &net.Dialer{Timeout: 2 * time.Second}
		conf := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         v.val,
			MaxVersion:         v.val,
			CipherSuites:       AllModernCiphers(),
		}

		// Use DialContext as in std_client.go
		tlsDialer := &tls.Dialer{
			NetDialer: dialer,
			Config:    conf,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := tlsDialer.DialContext(ctx, "tcp", address)
		cancel()

		if err != nil {
			fmt.Printf("  Failed: %v\n", err)
		} else {
			tlsConn := conn.(*tls.Conn)
			fmt.Printf("  Success! Negotiated: %x\n", tlsConn.ConnectionState().CipherSuite)
			tlsConn.Close()
		}
	}
}
