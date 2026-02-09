package utils

import (
	"log/slog"
	"os"
)

var Logger *slog.Logger

// InitLogger initializes the global logger.
// If debug is true, logs are written to the specified file (or stderr if empty).
// If debug is false, logs are discarded to prevent interference with TUI.
func InitLogger(debug bool, logFile string) error {
	var handler slog.Handler

	if !debug {
		handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelError + 1, // Disable logging effectively
		})
		Logger = slog.New(handler)
		return nil
	}

	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}

	var writer *os.File
	var err error

	if logFile != "" {
		writer, err = os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
	} else {
		writer = os.Stderr
	}

	handler = slog.NewJSONHandler(writer, opts)
	Logger = slog.New(handler)

	Logger.Info("Logger initialized", "debug", debug)
	return nil
}

// Log is a helper to access the global logger safely
func Log() *slog.Logger {
	if Logger == nil {
		// Fallback to discard logger if not initialized
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	return Logger
}
