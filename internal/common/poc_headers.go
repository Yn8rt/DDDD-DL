package common

import (
	"fmt"
	"net/http"
	"strings"

	"dddd/internal/structs"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
)

func normalizePocHeaderConfig() {
	headers, err := BuildPocCustomHeaders(structs.GlobalConfig.PocUserAgent, structs.GlobalConfig.PocHeaders)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}
	structs.GlobalConfig.PocHeaders = headers
}

func BuildPocCustomHeaders(userAgent string, headers goflags.StringSlice) (goflags.StringSlice, error) {
	type headerEntry struct {
		name  string
		value string
	}

	entries := make([]headerEntry, 0, len(headers)+1)
	indexByName := make(map[string]int)
	addHeader := func(raw string) error {
		name, value, ok, err := parsePocHeader(raw)
		if err != nil || !ok {
			return err
		}
		if index, exists := indexByName[strings.ToLower(name)]; exists {
			entries[index] = headerEntry{name: name, value: value}
			return nil
		}
		indexByName[strings.ToLower(name)] = len(entries)
		entries = append(entries, headerEntry{name: name, value: value})
		return nil
	}

	for _, rawHeader := range headers {
		if err := addHeader(rawHeader); err != nil {
			return nil, err
		}
	}

	userAgent = strings.TrimSpace(userAgent)
	if userAgent != "" {
		if strings.ContainsAny(userAgent, "\r\n") {
			return nil, fmt.Errorf("POC请求User-Agent(-pua/--poc-user-agent)不能包含换行")
		}
		if err := addHeader("User-Agent: " + userAgent); err != nil {
			return nil, err
		}
	}

	normalized := make(goflags.StringSlice, 0, len(entries))
	for _, entry := range entries {
		normalized = append(normalized, entry.name+": "+entry.value)
	}
	return normalized, nil
}

func ApplyPocHTTPHeaders(header http.Header, defaultUserAgent string) {
	if strings.TrimSpace(defaultUserAgent) != "" {
		header.Set("User-Agent", defaultUserAgent)
	}
	for _, rawHeader := range structs.GlobalConfig.PocHeaders {
		name, value, ok, err := parsePocHeader(rawHeader)
		if err != nil || !ok {
			continue
		}
		header.Set(name, value)
	}
}

func parsePocHeader(raw string) (string, string, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", false, nil
	}
	if strings.ContainsAny(raw, "\r\n") {
		return "", "", false, fmt.Errorf("POC请求Header参数(-ph/--poc-header)不能包含换行: %q", raw)
	}
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) != 2 {
		return "", "", false, fmt.Errorf("POC请求Header参数(-ph/--poc-header)格式应为 'Name: value'，当前值: %q", raw)
	}
	name := strings.TrimSpace(parts[0])
	if !isHTTPHeaderToken(name) {
		return "", "", false, fmt.Errorf("POC请求Header名称不合法: %q", name)
	}
	return http.CanonicalHeaderKey(name), strings.TrimSpace(parts[1]), true, nil
}

func isHTTPHeaderToken(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			continue
		}
		if strings.ContainsRune("!#$%&'*+-.^_`|~", r) {
			continue
		}
		return false
	}
	return true
}
