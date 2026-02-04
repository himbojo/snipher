package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"snipher/internal/engine"
	"snipher/internal/models"
	"snipher/internal/ui"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/urfave/cli/v2"
)

// DefaultAction is the handler for the main "snipher <target>" command
func DefaultAction(c *cli.Context) error {
	// Handle --cipher-list flag
	if c.Bool("cipher-list") {
		mode := "iana"
		if c.Bool("both") {
			mode = "both"
		} else if c.Bool("openssl") {
			mode = "openssl"
		}
		ui.RenderCipherList(mode)
		return nil
	}

	if c.NArg() < 1 {
		return cli.ShowAppHelp(c)
	}

	target := c.Args().First()
	port := c.Int("port")

	// Support host:port syntax
	// Priority: Flag > host:port > Default (443)
	if host, portStr, err := net.SplitHostPort(target); err == nil {
		target = host
		if p, err := strconv.Atoi(portStr); err == nil {
			// Only override if flag wasn't explicitly set.
			// Since we can't easily check c.IsSet with urfave/cli v2 without iterating,
			// we'll assume if the user typed google.com:8443, they mean 8443.
			// If they typed snipher google.com:8443 -p 9000, the flag value (9000)
			// is already in 'port'. But we need to know if 'port' is default (443) or user-set.
			// A clean way is to rely on c.IsSet if available, or just verify if port != 443 (default).
			// But if user set -p 443 explicitly, we should technically respect it (though it's the same).
			// However, google.com:8443 implies 8443.
			// Let's use the flag if it's set.
			if !c.IsSet("port") {
				port = p
			}
		}
	}

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
	isJSON := c.Bool("json")
	mode := "iana"
	if c.Bool("both") {
		mode = "both"
	} else if c.Bool("openssl") {
		mode = "openssl"
	}

	minTimeout := c.Duration("min-timeout")
	maxTimeout := c.Duration("max-timeout")

	// 3. Execution
	isInteractive := !isJSON && !ui.IsCI()
	var progressChan chan string

	if isInteractive {
		progressChan = make(chan string, 10)
	}

	scanner := engine.NewStdScanner(engine.ScannerConfig{
		MinTimeout:      minTimeout,
		MaxTimeout:      maxTimeout,
		ProgressChannel: progressChan,
	})

	var res models.ScanResult
	var scanErr error

	if isInteractive {
		// --- Interactive Mode (Bubble Tea) ---
		p := tea.NewProgram(ui.NewProgressModel())

		// 1. Run Scan in background
		go func() {
			r, err := scanner.Scan(context.Background(), target, port, c.String("ca-bundle"))
			res = r
			scanErr = err

			if err != nil {
				p.Send(ui.ErrorMsg(err))
			} else {
				p.Send(ui.ResultMsg{})
			}
		}()

		// 2. Bridge Channel -> Program
		go func() {
			for msg := range progressChan {
				p.Send(ui.ProgressMsg(msg))
			}
		}()

		// 3. Block until program finishes
		if _, err := p.Run(); err != nil {
			fmt.Printf("Alas, there's been an error: %v", err)
			os.Exit(models.ExitOperational)
		}
	} else {
		// --- Non-interactive Mode (Blocking) ---
		res, scanErr = scanner.Scan(context.Background(), target, port, c.String("ca-bundle"))
	}

	// 4. Handle Results
	if scanErr != nil {
		if isJSON {
			errorRes := map[string]string{"errors": scanErr.Error(), "host": target}
			b, _ := json.Marshal(errorRes)
			fmt.Println(string(b))
		} else if !isInteractive { // If interactive, error was likely shown by TUI or handling logic above
			fmt.Printf("Error: %v\n", scanErr)
		}
		os.Exit(models.ExitOperational)
	}

	// 5. Evaluate Policy Compliance
	var complianceReport *models.ComplianceResult
	if c.String("policy") != "" {
		policy, err := engine.LoadPolicy(c.String("policy"))
		if err != nil {
			fmt.Printf("Policy Error: %v\n", err)
			os.Exit(models.ExitOperational)
		}
		report := engine.CheckCompliance(res, *policy)
		complianceReport = &report
	}

	if isJSON {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
	} else {
		// Render final output
		ui.RenderTargetIntelligence(res, c.Bool("sans"))
		ui.RenderCertificateIdentity(res, c.Bool("sans"))
		ui.RenderProtocolMatrix(res, c.Bool("verbose"), mode, complianceReport)
	}

	// Check for critical issues using centralized logic
	if res.HasCriticalIssues() {
		msg := res.GetCriticalIssueMessage()
		return &models.CriticalError{Msg: msg}
	}

	// Fail if policy violation exists
	if complianceReport != nil && !complianceReport.IsCompliant {
		return &models.CriticalError{Msg: "Policy compliance failed. See violations above."}
	}

	return nil
}
