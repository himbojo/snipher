package cli

import (
	"time"

	"github.com/urfave/cli/v2"
)

// NewApp creates the main snipher CLI application
func NewApp() *cli.App {
	return &cli.App{
		Name:  "snipher",
		Usage: "A rapid security tool for SSL/TLS inspection",
		Description: `EXAMPLES:
   # Standard scan (Default IANA names)
   snipher google.com

   # Combined naming (IANA / OpenSSL format)
   snipher google.com --both

   # Verbose mode with OpenSSL naming convention
   snipher google.com --verbose --openssl

   # Scan custom port with JSON output
   snipher localhost:8443 --json

   # Reference only: list all supported ciphers
   snipher --cipher-list --both

   # Custom PKI validation
   snipher internal.local --ca-bundle ./root.pem --sans`,
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:    "port",
				Aliases: []string{"p"},
				Value:   443,
				Usage:   "Custom port to scan",
			},
			&cli.BoolFlag{
				Name:  "json",
				Usage: "Output results in JSON format",
			},
			&cli.BoolFlag{
				Name:  "sans",
				Usage: "Show Subject Alternative Names (SANs)",
			},
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"v"},
				Usage:   "Show all possible ciphers for each protocol (enabled and disabled)",
			},
			&cli.StringFlag{
				Name:    "ca-bundle",
				Usage:   "Path to a custom CA bundle (PEM format)",
				Aliases: []string{"ca"},
			},
			&cli.DurationFlag{
				Name:  "min-timeout",
				Value: 2 * time.Second,
				Usage: "Initial timeout per cipher check",
			},
			&cli.DurationFlag{
				Name:  "max-timeout",
				Value: 10 * time.Second,
				Usage: "Maximum timeout for cipher check retries",
			},
			&cli.BoolFlag{
				Name:  "cipher-list",
				Usage: "Display supported ciphers that will be tested for each protocol",
			},
			&cli.BoolFlag{
				Name:  "openssl",
				Usage: "Display cipher names in OpenSSL format",
			},
			&cli.BoolFlag{
				Name:  "both",
				Usage: "Show both IANA and OpenSSL cipher names",
			},
		},
		UseShortOptionHandling: true,
		Action:                 DefaultAction,
	}
}
