package engine

import (
	"context"
	"fmt"
	"net"
	"testing"
)

func TestCheckLegacyProtocols(t *testing.T) {
	// Mock server that responds like an SSLv3 server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				if n == 0 {
					return
				}

				// If it looks like SSLv3 ClientHello
				if buf[0] == 0x16 && buf[1] == 0x03 && buf[2] == 0x00 {
					// Respond with a minimal SSLv3 ServerHello
					c.Write([]byte{0x16, 0x03, 0x00, 0x00, 0x4a, 0x02, 0x00, 0x00, 0x46, 0x03, 0x00})
				} else if buf[0] == 0x80 {
					// SSLv2 - respond with bit 15 set in first byte
					c.Write([]byte{0x80, 0x00})
				}
			}(conn)
		}
	}()

	addr := ln.Addr().String()
	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	scanner := NewStdScanner()
	results := scanner.checkLegacyProtocols(context.Background(), host, port)

	sslv2Found := false
	sslv3Found := false
	for _, p := range results {
		if p.Name == "SSLv2" && p.Supported {
			sslv2Found = true
		}
		if p.Name == "SSLv3" && p.Supported {
			sslv3Found = true
		}
	}

	if !sslv2Found {
		t.Errorf("expected SSLv2 to be detected")
	}
	if !sslv3Found {
		t.Errorf("expected SSLv3 to be detected")
	}
}

func TestCheckLegacyProtocols_Disabled(t *testing.T) {
	// Mock server that just closes connection
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	addr := ln.Addr().String()
	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	scanner := NewStdScanner()
	results := scanner.checkLegacyProtocols(context.Background(), host, port)

	for _, p := range results {
		if p.Supported {
			t.Errorf("expected %s to be Disabled, but got Enabled", p.Name)
		}
	}
}
