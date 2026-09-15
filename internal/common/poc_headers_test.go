package common

import (
	"net/http"
	"testing"

	"dddd/internal/structs"

	"github.com/projectdiscovery/goflags"
)

func TestBuildPocCustomHeadersNormalizesAndOverrides(t *testing.T) {
	headers, err := BuildPocCustomHeaders("UA-Final", goflags.StringSlice{
		"x-test: 1",
		"User-Agent: UA-Old",
		"X-Test: 2",
	})
	if err != nil {
		t.Fatalf("BuildPocCustomHeaders returned error: %v", err)
	}

	want := goflags.StringSlice{"X-Test: 2", "User-Agent: UA-Final"}
	if len(headers) != len(want) {
		t.Fatalf("headers length = %d, want %d: %#v", len(headers), len(want), headers)
	}
	for i := range want {
		if headers[i] != want[i] {
			t.Fatalf("headers[%d] = %q, want %q", i, headers[i], want[i])
		}
	}
}

func TestBuildPocCustomHeadersRejectsInvalidHeader(t *testing.T) {
	if _, err := BuildPocCustomHeaders("", goflags.StringSlice{"BadHeader"}); err == nil {
		t.Fatalf("expected invalid header error")
	}
	if _, err := BuildPocCustomHeaders("bad\r\nua", nil); err == nil {
		t.Fatalf("expected invalid user-agent error")
	}
}

func TestApplyPocHTTPHeadersOverridesDefaultUserAgent(t *testing.T) {
	originalConfig := structs.GlobalConfig
	t.Cleanup(func() { structs.GlobalConfig = originalConfig })

	structs.GlobalConfig.PocHeaders = goflags.StringSlice{
		"User-Agent: Custom-UA",
		"X-Test: 1",
	}
	header := http.Header{}
	ApplyPocHTTPHeaders(header, "Default-UA")

	if got := header.Get("User-Agent"); got != "Custom-UA" {
		t.Fatalf("User-Agent = %q, want Custom-UA", got)
	}
	if got := header.Get("X-Test"); got != "1" {
		t.Fatalf("X-Test = %q, want 1", got)
	}
}
