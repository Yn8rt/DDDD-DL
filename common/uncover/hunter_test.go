package uncover

import "testing"

func TestNormalizeHunterKeyword(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "domain suffix", input: "domain.suffix=xxx.com", expected: "domain.suffix=\"xxx.com\""},
		{name: "already quoted", input: "domain.suffix=\"xxx.com\"", expected: "domain.suffix=\"xxx.com\""},
		{name: "complex query", input: "domain.suffix=xxx.com && port=80", expected: "domain.suffix=xxx.com && port=80"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeHunterKeyword(tt.input); got != tt.expected {
				t.Fatalf("normalizeHunterKeyword() = %q, want %q", got, tt.expected)
			}
		})
	}
}
