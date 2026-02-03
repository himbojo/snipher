package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"snipher/internal/engine"
	"snipher/internal/models"
	"snipher/internal/ui"
	"strings"

	"github.com/urfave/cli/v2"
)

// DefaultAction is the handler for the main "snipher <target>" command
func DefaultAction(c *cli.Context) error {
	if c.NArg() < 1 {
		cli.ShowAppHelp(c)
		return nil
	}

	target := c.Args().First()

	// UX: Validate input - if it looks like a URL, fail gracefully
	if strings.Contains(target, "://") || strings.Contains(target, "/") {
		// Try to parse it to give a better suggestion
		cleanTarget := target
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			cleanTarget = u.Host
		} else {
			// Fallback cleaning
			cleanTarget = strings.TrimPrefix(cleanTarget, "https://")
			cleanTarget = strings.TrimPrefix(cleanTarget, "http://")
			cleanTarget = strings.Split(cleanTarget, "/")[0]
		}

		return fmt.Errorf("invalid target format '%s'. Did you mean '%s'?\n   Target must be a hostname or IP (e.g., google.com), not a URL.", target, cleanTarget)
	}
	port := c.Int("port")
	isJSON := c.Bool("json")
	minTimeout := c.Duration("min-timeout")
	maxTimeout := c.Duration("max-timeout")

	// 3. Execute Scan
	scanner := engine.NewStdScanner(engine.ScannerConfig{
		MinTimeout: minTimeout,
		MaxTimeout: maxTimeout,
	})
	res, err := scanner.Scan(context.Background(), target, port, c.String("ca-bundle"))

	if err != nil {
		if isJSON {
			errorRes := map[string]string{"errors": err.Error(), "host": target}
			b, _ := json.Marshal(errorRes)
			fmt.Println(string(b))
		} else {
			fmt.Printf("Error: %v\n", err)
		}
		os.Exit(models.ExitOperational) // Operational Error
	}

	if isJSON {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
	} else {
		ui.RenderVitalsCard(res, c.Bool("sans"))
		ui.RenderCapabilityTable(res, c.Bool("verbose"))
	}

	// Check for critical issues using centralized logic
	if res.HasCriticalIssues() {
		msg := res.GetCriticalIssueMessage()
		return &models.CriticalError{Msg: msg}
	}

	return nil
}
