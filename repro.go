package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
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
	targetName := "localhost"
	ips, err := net.LookupIP(targetName)
	if err != nil {
		fmt.Printf("Lookup failed: %v\n", err)
		return
	}
	fmt.Printf("localhost resolves to: %v\n", ips)

	// Force connection to localhost to see which IP is used if we just Dial "localhost"
	// But repro previously used explicit IP.
	// Let's test checking all IPs.

	port := 4443

	versions := []struct {
		val  uint16
		name string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
	}

	var wg sync.WaitGroup

	for _, ip := range ips {
		target := ip.String()
		fmt.Printf("--- Testing target IP: %s ---\n", target)
		address := fmt.Sprintf("[%s]:%d", target, port)
		if ip.To4() != nil {
			address = fmt.Sprintf("%s:%d", target, port)
		}

		for _, v := range versions {
			wg.Add(1)
			go func(v struct {
				val  uint16
				name string
			}, t string, addr string) {
				defer wg.Done()
				// fmt.Printf("Testing %s on %s...\n", v.name, t)

				dialer := &net.Dialer{Timeout: 2 * time.Second}
				conf := &tls.Config{
					InsecureSkipVerify: true,
					MinVersion:         v.val,
					MaxVersion:         v.val,
					CipherSuites:       AllModernCiphers(),
					ServerName:         targetName, // Send "localhost" as SNI
				}

				tlsDialer := &tls.Dialer{
					NetDialer: dialer,
					Config:    conf,
				}

				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				conn, err := tlsDialer.DialContext(ctx, "tcp", addr)
				cancel()

				if err != nil {
					// fmt.Printf("  %s (%s) Failed: %v\n", v.name, t, err)
				} else {
					tlsConn := conn.(*tls.Conn)
					fmt.Printf("  %s (%s) Success! Negotiated: %x\n", v.name, t, tlsConn.ConnectionState().CipherSuite)
					tlsConn.Close()
				}
			}(v, target, address)
		}
	}
	wg.Wait()
}
