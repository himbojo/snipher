package engine

import (
	"context"
	"snipher/internal/models"
)

// Scanner defines the interface for different scanning backends
type Scanner interface {
	Scan(ctx context.Context, target string, port int, caBundlePath string) (models.ScanResult, error)
}
