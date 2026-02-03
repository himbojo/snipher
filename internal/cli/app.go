package cli

import (
	"github.com/urfave/cli/v2"
)

// NewApp creates the main snipher CLI application
func NewApp() *cli.App {
	return &cli.App{
		Name:  "snipher",
		Usage: "A rapid security tool for SSL/TLS inspection",
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
		},
		UseShortOptionHandling: true,
		Action:                 DefaultAction,
	}
}
