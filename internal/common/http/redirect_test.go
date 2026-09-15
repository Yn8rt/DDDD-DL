package http

import (
	"testing"

	"github.com/projectdiscovery/httpx/runner"
)

func TestResolveRedirectURL(t *testing.T) {
	tests := []struct {
		name string
		resp runner.Result
		want string
	}{
		{
			name: "absolute cross host redirect",
			resp: runner.Result{StatusCode: 302, URL: "http://example.com", Location: "https://www.example.org/login"},
			want: "https://www.example.org/login",
		},
		{
			name: "relative redirect",
			resp: runner.Result{StatusCode: 301, URL: "http://example.com/app", Location: "/login"},
			want: "http://example.com/login",
		},
		{
			name: "protocol relative redirect",
			resp: runner.Result{StatusCode: 302, URL: "https://example.com", Location: "//cdn.example.com/home"},
			want: "https://cdn.example.com/home",
		},
		{
			name: "non redirect status",
			resp: runner.Result{StatusCode: 200, URL: "http://example.com", Location: "https://www.example.org"},
			want: "",
		},
		{
			name: "unsupported scheme",
			resp: runner.Result{StatusCode: 302, URL: "http://example.com", Location: "mailto:test@example.com"},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveRedirectURL(tt.resp); got != tt.want {
				t.Fatalf("resolveRedirectURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
