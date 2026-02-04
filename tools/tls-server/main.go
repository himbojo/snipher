package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	port := flag.Int("port", 4433, "Port to listen on")
	tls10 := flag.Bool("tls10", true, "Enable TLS 1.0")
	tls11 := flag.Bool("tls11", true, "Enable TLS 1.1")
	tls12 := flag.Bool("tls12", true, "Enable TLS 1.2")
	tls13 := flag.Bool("tls13", true, "Enable TLS 1.3")
	flag.Parse()

	cert, err := generateSelfSignedCert()
	if err != nil {
		fmt.Printf("Error generating cert: %v\n", err)
		os.Exit(1)
	}

	addr := fmt.Sprintf(":%d", *port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Printf("Error listening: %v\n", err)
		os.Exit(1)
	}
	defer ln.Close()

	fmt.Printf("TLS Mock Server listening on %s\n", addr)
	fmt.Printf("Status: TLS1.0=%v, TLS1.1=%v, TLS1.2=%v, TLS1.3=%v\n",
		*tls10, *tls11, *tls12, *tls13)

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Printf("Error accepting: %v\n", err)
			continue
		}
		go handleConnection(conn, cert, *tls10, *tls11, *tls12, *tls13)
	}
}

func handleConnection(conn net.Conn, cert tls.Certificate, t10, t11, t12, t13 bool) {
	defer conn.Close()

	// Peek at first few bytes to decide path
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	remote := conn.RemoteAddr().String()

	// 1. Check for Modern TLS record (Handshake 0x16)
	if n > 5 && buf[0] == 0x16 {
		// Version in Record Layer
		recMaj, recMin := buf[1], buf[2]

		// Handshake Type at offset 5
		if buf[5] == 0x01 { // ClientHello
			// Version in Handshake at offset 9
			hansMaj, hansMin := buf[9], buf[10]

			fmt.Printf("[%s] -> TLS %d.%d ClientHello (Handshake %d.%d). Upgrading to TLS server...\n",
				remote, recMaj, recMin, hansMaj, hansMin)

			// We need to "replay" the peeked bytes to the TLS server
			prefixedConn := &prefixConn{Conn: conn, prefix: buf[:n]}

			var ciphers []uint16
			for _, c := range tls.InsecureCipherSuites() {
				ciphers = append(ciphers, c.ID)
			}
			for _, c := range tls.CipherSuites() {
				ciphers = append(ciphers, c.ID)
			}

			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS10,
				MaxVersion:   tls.VersionTLS13,
				CipherSuites: ciphers,
				GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					fmt.Printf("[%s] -> TLS Handshake Request. SupportedVersions: %v\n", remote, hello.SupportedVersions)
					// Selective enforcement
					conf := &tls.Config{
						Certificates: []tls.Certificate{cert},
						MinVersion:   tls.VersionTLS10,
						MaxVersion:   tls.VersionTLS13,
						CipherSuites: ciphers,
					}
					canDo := false
					for _, v := range hello.SupportedVersions {
						switch v {
						case tls.VersionTLS10:
							if t10 {
								canDo = true
							}
						case tls.VersionTLS11:
							if t11 {
								canDo = true
							}
						case tls.VersionTLS12:
							if t12 {
								canDo = true
							}
						case tls.VersionTLS13:
							if t13 {
								canDo = true
							}
						}
					}
					if !canDo {
						return nil, fmt.Errorf("protocol version not enabled in mock server")
					}
					return conf, nil
				},
			}

			tlsConn := tls.Server(prefixedConn, tlsConfig)
			err := tlsConn.Handshake()
			if err != nil {
				fmt.Printf("[%s] -> TLS Handshake failed: %v\n", remote, err)
			} else {
				fmt.Printf("[%s] -> TLS Handshake successful (%v)\n", remote, tlsConn.ConnectionState().Version)
				// Keep open for a bit to ensure client sees it
				time.Sleep(100 * time.Millisecond)
			}
			return
		}
	}

	fmt.Printf("[%s] -> Unknown handshake (%x). Closing.\n", remote, buf[:n])
}

// prefixConn allows replaying peeked bytes
type prefixConn struct {
	net.Conn
	prefix []byte
	offset int
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if c.offset < len(c.prefix) {
		n := copy(b, c.prefix[c.offset:])
		c.offset += n
		return n, nil
	}
	return c.Conn.Read(b)
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(certPEM, keyPEM)
}
