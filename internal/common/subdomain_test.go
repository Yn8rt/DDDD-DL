package common

import (
	"dddd/internal/structs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

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

func TestBruteSubDomainAutoFallsBackWhenKsubdomainReturnsNoResults(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script test helper is unix-only")
	}

	tmpDir := t.TempDir()
	ksubdomainPath := writeExecutable(t, tmpDir, "ksubdomain", fakeKsubdomainScript())
	dnsxPath := writeExecutable(t, tmpDir, "dnsx", fakeDNSxScript())

	originalConfig := structs.GlobalConfig
	t.Cleanup(func() { structs.GlobalConfig = originalConfig })
	structs.GlobalConfig.SubdomainEngine = "auto"
	structs.GlobalConfig.KSubdomainPath = ksubdomainPath
	structs.GlobalConfig.DNSXPath = dnsxPath
	structs.GlobalConfig.SubdomainWordListFile = "embedded"
	structs.GlobalConfig.KSubdomainBand = "3m"
	structs.GlobalConfig.KSubdomainWildcard = "none"
	structs.GlobalConfig.SubdomainBruteForceThreads = 1

	got := bruteSubDomain("example.com")
	if len(got) != 1 || got[0] != "www.example.com" {
		t.Fatalf("bruteSubDomain() = %v, want [www.example.com]", got)
	}
}

func TestCleanSubdomainDiagnosticLine(t *testing.T) {
	line := "......................\x1b[1;31m[Fatal]\x1b[0m 获取网络设备超时，请尝试手动指定网卡"
	want := "[Fatal] 获取网络设备超时，请尝试手动指定网卡"
	if got := cleanSubdomainDiagnosticLine(line); got != want {
		t.Fatalf("cleanSubdomainDiagnosticLine() = %q, want %q", got, want)
	}
}

func writeExecutable(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0755); err != nil {
		t.Fatalf("os.WriteFile() error: %v", err)
	}
	return path
}

func fakeKsubdomainScript() string {
	return "#!/usr/bin/env sh\nexit 0\n"
}

func fakeDNSxScript() string {
	return "#!/usr/bin/env sh\nprintf 'www.example.com\\n'\n"
}

func TestLocalExecutableCandidatesIncludesNestedTool(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd() error: %v", err)
	}

	want := filepath.Join(wd, "dnsx", "dnsx")
	if runtime.GOOS == "windows" {
		want += ".exe"
	}

	if !containsPath(localExecutableCandidates("dnsx"), want) {
		t.Fatalf("localExecutableCandidates() 未包含当前目录下的 dnsx/dnsx.exe: %s", want)
	}
}

func TestResolveExternalToolFindsNestedExecutable(t *testing.T) {
	tmpDir := t.TempDir()
	toolDir := filepath.Join(tmpDir, "dnsx")
	if err := os.MkdirAll(toolDir, 0755); err != nil {
		t.Fatalf("os.MkdirAll() error: %v", err)
	}

	exeName := "dnsx"
	if runtime.GOOS == "windows" {
		exeName += ".exe"
	}
	want := filepath.Join(toolDir, exeName)
	if err := os.WriteFile(want, []byte("test"), 0755); err != nil {
		t.Fatalf("os.WriteFile() error: %v", err)
	}

	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd() error: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("os.Chdir() error: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })

	got, err := resolveExternalTool("dnsx", "dnsx")
	if err != nil {
		t.Fatalf("resolveExternalTool() error: %v", err)
	}
	if !samePath(got, want) {
		t.Fatalf("resolveExternalTool() = %q, want %q", got, want)
	}
}

func containsPath(paths []string, want string) bool {
	want = filepath.Clean(want)
	for _, item := range paths {
		item = filepath.Clean(item)
		if runtime.GOOS == "windows" {
			if samePath(item, want) {
				return true
			}
			continue
		}
		if item == want {
			return true
		}
	}
	return false
}

func samePath(a, b string) bool {
	a = filepath.Clean(a)
	b = filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	if resolved, err := filepath.EvalSymlinks(a); err == nil {
		a = filepath.Clean(resolved)
	}
	if resolved, err := filepath.EvalSymlinks(b); err == nil {
		b = filepath.Clean(resolved)
	}
	return a == b
}
