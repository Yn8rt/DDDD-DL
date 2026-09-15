package common

import (
	"dddd/internal/structs"
	"os"
	"path/filepath"
	"testing"
)

func TestValidatePrepareConfigNormalizesHelpDocumentedEnums(t *testing.T) {
	originalConfig := structs.GlobalConfig
	t.Cleanup(func() { structs.GlobalConfig = originalConfig })

	structs.GlobalConfig = structs.Config{
		APIConfigFilePath:          "config/api-config.yaml",
		PortScanType:               "SYN",
		OutputType:                 "JSON",
		SubdomainEngine:            "AUTO",
		KSubdomainWildcard:         "ADVANCED",
		Severities:                 "High,LOW",
		NoInteractsh:               false,
		TCPPortScanThreads:         1000,
		SYNPortScanThreads:         10000,
		SubdomainBruteForceThreads: 150,
	}

	validatePrepareConfig()

	if structs.GlobalConfig.PortScanType != "syn" {
		t.Fatalf("PortScanType = %q, want syn", structs.GlobalConfig.PortScanType)
	}
	if structs.GlobalConfig.OutputType != "json" {
		t.Fatalf("OutputType = %q, want json", structs.GlobalConfig.OutputType)
	}
	if structs.GlobalConfig.SubdomainEngine != "auto" {
		t.Fatalf("SubdomainEngine = %q, want auto", structs.GlobalConfig.SubdomainEngine)
	}
	if structs.GlobalConfig.KSubdomainWildcard != "advanced" {
		t.Fatalf("KSubdomainWildcard = %q, want advanced", structs.GlobalConfig.KSubdomainWildcard)
	}
	if structs.GlobalConfig.Severities != "high,low" {
		t.Fatalf("Severities = %q, want high,low", structs.GlobalConfig.Severities)
	}
	if !structs.GlobalConfig.NoInteractsh {
		t.Fatalf("Interactsh should be disabled by default")
	}
}

func TestValidatePrepareConfigAcceptsJSONFileAsOutputType(t *testing.T) {
	originalConfig := structs.GlobalConfig
	t.Cleanup(func() { structs.GlobalConfig = originalConfig })

	structs.GlobalConfig = structs.Config{
		APIConfigFilePath:          "config/api-config.yaml",
		PortScanType:               "tcp",
		OutputType:                 "res.json",
		OutputFile:                 "result.txt",
		SubdomainEngine:            "dnsx",
		KSubdomainWildcard:         "basic",
		TCPPortScanThreads:         1000,
		SYNPortScanThreads:         10000,
		SubdomainBruteForceThreads: 150,
	}

	validatePrepareConfig()

	if structs.GlobalConfig.OutputType != "json" {
		t.Fatalf("OutputType = %q, want json", structs.GlobalConfig.OutputType)
	}
	if structs.GlobalConfig.OutputFile != "res.json" {
		t.Fatalf("OutputFile = %q, want res.json", structs.GlobalConfig.OutputFile)
	}
}

func TestValidatePrepareConfigEnablesInteractshExplicitly(t *testing.T) {
	originalConfig := structs.GlobalConfig
	t.Cleanup(func() { structs.GlobalConfig = originalConfig })

	structs.GlobalConfig = structs.Config{
		APIConfigFilePath:          "config/api-config.yaml",
		PortScanType:               "tcp",
		OutputType:                 "text",
		SubdomainEngine:            "dnsx",
		KSubdomainWildcard:         "basic",
		EnableInteractsh:           true,
		NoInteractsh:               true,
		TCPPortScanThreads:         1000,
		SYNPortScanThreads:         10000,
		SubdomainBruteForceThreads: 150,
	}

	validatePrepareConfig()

	if structs.GlobalConfig.NoInteractsh {
		t.Fatalf("Interactsh should be enabled when EnableInteractsh is true")
	}
}

func TestLoadPortsFromFileCommaSeparated(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "ports.txt")
	if err := os.WriteFile(filePath, []byte("21,22,23,3306,6379"), 0o644); err != nil {
		t.Fatal(err)
	}

	ports := loadPortsFromFile(filePath)
	if ports != "21,22,23,3306,6379" {
		t.Fatalf("ports = %q, want 21,22,23,3306,6379", ports)
	}
	if got := len(ParsePort(ports)); got != 5 {
		t.Fatalf("ParsePort count = %d, want 5", got)
	}
}

func TestLoadPortsFromFileMixedSeparatorsAndRanges(t *testing.T) {
	content := "80,443\n8000-8002\n22;3389 7000\t9090\r\n53"
	filePath := filepath.Join(t.TempDir(), "ports.txt")
	if err := os.WriteFile(filePath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	ports := loadPortsFromFile(filePath)
	want := map[int]bool{80: true, 443: true, 8000: true, 8001: true, 8002: true, 22: true, 3389: true, 7000: true, 9090: true, 53: true}
	parsed := ParsePort(ports)
	if len(parsed) != len(want) {
		t.Fatalf("ParsePort count = %d, want %d (%v)", len(parsed), len(want), parsed)
	}
	for _, p := range parsed {
		if !want[p] {
			t.Fatalf("unexpected port %d in %v", p, parsed)
		}
	}
}

func TestLoadPortsFromFileSkipsInvalidTokens(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "ports.txt")
	if err := os.WriteFile(filePath, []byte("80,abc,0,65536,1-2-3,443"), 0o644); err != nil {
		t.Fatal(err)
	}

	ports := loadPortsFromFile(filePath)
	if ports != "80,443" {
		t.Fatalf("ports = %q, want 80,443", ports)
	}
}
