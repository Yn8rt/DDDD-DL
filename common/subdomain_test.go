package common

import "testing"

func TestParseSubdomainOutput(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		root     string
		expected string
	}{
		{name: "plain", line: "www.example.com", root: "example.com", expected: "www.example.com"},
		{name: "ksubdomain txt", line: "api.example.com => 1.1.1.1", root: "example.com", expected: "api.example.com"},
		{name: "dnsx detail", line: "dev.example.com [A] [1.1.1.1]", root: "example.com", expected: "dev.example.com"},
		{name: "skip banner", line: "[INFO] Current Version: 2.4", root: "example.com", expected: ""},
		{name: "skip foreign domain", line: "www.other.com", root: "example.com", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseSubdomainOutput(tt.line, tt.root); got != tt.expected {
				t.Fatalf("parseSubdomainOutput() = %q, want %q", got, tt.expected)
			}
		})
	}
}
