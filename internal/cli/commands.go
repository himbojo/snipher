package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"snipher/internal/engine"
	"snipher/internal/models"
	"snipher/internal/ui"

	"github.com/urfave/cli/v2"
)

// DefaultAction is the handler for the main "snipher <target>" command
func DefaultAction(c *cli.Context) error {
	if c.NArg() < 1 {
		return fmt.Errorf("missing target argument")
	}

	target := c.Args().First()
	port := c.Int("port")
	isJSON := c.Bool("json")

	// 3. Execute Scan
	scanner := engine.NewStdScanner()
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
