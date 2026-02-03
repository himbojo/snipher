package main

import (
	"crypto/tls"
	"fmt"
	"strings"
)

func main() {
	fmt.Println("=== Insecure Cipher Suites (including 3DES) ===")
	for _, s := range tls.InsecureCipherSuites() {
		if strings.Contains(s.Name, "3DES") {
			fmt.Printf("%s - Versions: %v\n", s.Name, s.SupportedVersions)
		}
	}
}
