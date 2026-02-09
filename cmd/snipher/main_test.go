package main

import (
	"reflect"
	"testing"
)

func TestPreprocessArgs(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "Standard args",
			input:    []string{"snipher", "target.com"},
			expected: []string{"snipher", "target.com"},
		},
		{
			name:     "Flag after target",
			input:    []string{"snipher", "target.com", "--json"},
			expected: []string{"snipher", "--json", "target.com"},
		},
		{
			name:     "Flag with value after target",
			input:    []string{"snipher", "target.com", "--port", "8443"},
			expected: []string{"snipher", "--port", "8443", "target.com"},
		},
		{
			name:     "Mixed flags",
			input:    []string{"snipher", "target.com", "--verbose", "--naming", "openssl"},
			expected: []string{"snipher", "--verbose", "--naming", "openssl", "target.com"},
		},
		{
			name:  "Debug flag (bug repro)",
			input: []string{"snipher", "target.com", "--debug", "--json"},
			// If --debug is not known as bool, it consumes --json as its value
			expected: []string{"snipher", "--debug", "--json", "target.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := preprocessArgs(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("got %v, want %v", result, tt.expected)
			}
		})
	}
}
