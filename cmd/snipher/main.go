package main

import (
	"fmt"
	"net"
	"os"
	"snipher/internal/cli"
	"snipher/internal/models"
)

func main() {
	app := cli.NewApp()

	// Pre-process args to allow flags after target (e.g., snipher target --json)
	// urfave/cli v2 expects flags before arguments in the root action.
	args := os.Args
	if len(args) > 1 {
		args = preprocessArgs(args)
	}

	if err := app.Run(args); err != nil {
		handleError(err)
	}
}

func preprocessArgs(args []string) []string {
	flags := []string{args[0]}
	params := []string{}

	for i := 1; i < len(args); i++ {
		if args[i][0] == '-' {
			flags = append(flags, args[i])
			// If it's a flag with a value (like --port 443), take the next arg too
			if i+1 < len(args) && args[i+1][0] != '-' {
				flags = append(flags, args[i+1])
				i++
			}
		} else {
			params = append(params, args[i])
		}
	}

	return append(flags, params...)
}

func handleError(err error) {
	// Map errors to exit codes as per architecture/story requirements:
	// Code 1: Critical (Expired Cert, etc.)
	// Code 2: Operational (DNS, Connection, Timeout)

	// Check for CriticalError first
	if _, ok := err.(*models.CriticalError); ok {
		fmt.Fprintf(os.Stderr, "Critical Fail: %v\n", err)
		os.Exit(models.ExitCritical)
	}

	// Basic check for common operational errors
	isOpErr := false
	if _, ok := err.(*net.OpError); ok {
		isOpErr = true
	} else if _, ok := err.(*net.DNSError); ok {
		isOpErr = true
	}

	if isOpErr {
		fmt.Fprintf(os.Stderr, "Operational Error: %v\n", err)
		os.Exit(models.ExitOperational)
	}

	// For other errors (like usage)
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(models.ExitOperational)
}
