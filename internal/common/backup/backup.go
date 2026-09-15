package backup

import (
	"context"
	"dddd/internal/common/progress"
	"dddd/internal/common/report"
	"dddd/internal/ddout"
	"dddd/internal/structs"
	"dddd/internal/utils"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
)

const defaultBackupExtensions = "zip,tar.gz,tgz,rar,7z,bak,sql"

type Candidate struct {
	Root string
	URL  string
}

type probeResult struct {
	URL           string
	Method        string
	StatusCode    int
	ContentLength int64
	ContentType   string
}

func Run(aliveURLs []string) {
	if !structs.GlobalConfig.EnableBackupScan || len(aliveURLs) == 0 {
		return
	}

	extensions := ParseExtensions(structs.GlobalConfig.BackupScanExtensions)
	targets := BuildCandidates(aliveURLs, extensions)
	if maxTargets := structs.GlobalConfig.BackupScanMaxTargets; maxTargets > 0 && len(targets) > maxTargets {
		gologger.Info().Msgf("备份扫描目标过多，按 --backup-max 截断: %d -> %d", len(targets), maxTargets)
		targets = targets[:maxTargets]
	}
	if len(targets) == 0 {
		return
	}

	client := newHTTPClient(structs.GlobalConfig.HTTPProxy, structs.GlobalConfig.WebTimeout)
	baselines := buildBaselines(client, aliveURLs)

	threads := structs.GlobalConfig.WebThreads
	if threads <= 0 {
		threads = 1
	}
	if threads > len(targets) {
		threads = len(targets)
	}

	gologger.Info().Msgf("开始网站备份扫描 (目标 %d)", len(targets))
	bar := progress.New("网站备份扫描", len(targets))
	defer bar.Finish()

	jobs := make(chan Candidate)
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for candidate := range jobs {
				probe := probeBackupURL(client, candidate.URL)
				if isBackupHit(probe, baselines[candidate.Root]) {
					emitBackupResult(probe)
				}
				bar.Add(1)
			}
		}()
	}

	for _, target := range targets {
		jobs <- target
	}
	close(jobs)
	wg.Wait()
}

func ParseExtensions(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		raw = defaultBackupExtensions
	}
	var result []string
	for _, item := range strings.Split(raw, ",") {
		item = strings.ToLower(strings.TrimSpace(item))
		item = strings.TrimPrefix(item, ".")
		if item != "" {
			result = append(result, item)
		}
	}
	return utils.RemoveDuplicateElement(result)
}

func BuildCandidates(rootURLs []string, extensions []string) []Candidate {
	var targets []Candidate
	seen := make(map[string]struct{})
	for _, rootURL := range rootURLs {
		rootURL = normalizeRootURL(rootURL)
		if rootURL == "" {
			continue
		}
		parsedURL, err := url.Parse(rootURL)
		if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
			continue
		}

		for _, name := range BuildBackupNames(parsedURL.Hostname(), extensions) {
			candidateURL := strings.TrimRight(rootURL, "/") + "/" + name
			if _, ok := seen[candidateURL]; ok {
				continue
			}
			seen[candidateURL] = struct{}{}
			targets = append(targets, Candidate{Root: rootURL, URL: candidateURL})
		}
	}
	return targets
}

func BuildBackupNames(host string, extensions []string) []string {
	host = strings.ToLower(strings.Trim(host, " ."))
	if host == "" || len(extensions) == 0 {
		return nil
	}

	bases := backupNameBases(host)
	var names []string
	seen := make(map[string]struct{})
	for _, base := range bases {
		base = strings.Trim(base, " ._-")
		if base == "" {
			continue
		}
		for _, ext := range extensions {
			name := base + "." + strings.TrimPrefix(ext, ".")
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}
	return names
}

func backupNameBases(host string) []string {
	var bases []string
	add := func(value string) {
		value = strings.ToLower(strings.Trim(value, " ._"))
		if value != "" {
			bases = append(bases, value)
		}
	}

	add(host)
	add(strings.ReplaceAll(host, ".", "_"))
	add(mixedDotUnderscoreBase(host))

	if strings.HasPrefix(host, "www.") {
		withoutWWW := strings.TrimPrefix(host, "www.")
		add(withoutWWW)
		add(strings.ReplaceAll(withoutWWW, ".", "_"))
		add(mixedDotUnderscoreBase(withoutWWW))
	}

	if ip := net.ParseIP(host); ip != nil {
		add(strings.ReplaceAll(host, ".", "_"))
		return utils.RemoveDuplicateElement(bases)
	}

	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		rootDomain := strings.Join(parts[len(parts)-2:], ".")
		add(rootDomain)
		add(strings.ReplaceAll(rootDomain, ".", "_"))
		add(mixedDotUnderscoreBase(rootDomain))
	}

	return utils.RemoveDuplicateElement(bases)
}

func mixedDotUnderscoreBase(host string) string {
	lastDot := strings.LastIndex(host, ".")
	if lastDot <= 0 || lastDot >= len(host)-1 {
		return ""
	}
	left := strings.ReplaceAll(host[:lastDot], ".", "_")
	tld := host[lastDot+1:]
	return left + host[lastDot:] + "_" + tld
}

func normalizeRootURL(raw string) string {
	parsedURL, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return ""
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return ""
	}
	return fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
}

func buildBaselines(client *http.Client, rootURLs []string) map[string]probeResult {
	baselines := make(map[string]probeResult)
	nonce := strconv.FormatInt(time.Now().UnixNano(), 36)
	for _, rootURL := range rootURLs {
		rootURL = normalizeRootURL(rootURL)
		if rootURL == "" {
			continue
		}
		baselineURL := strings.TrimRight(rootURL, "/") + "/dddd-not-exist-" + nonce + ".zip"
		baselines[rootURL] = probeBackupURL(client, baselineURL)
	}
	return baselines
}

func newHTTPClient(proxyRaw string, timeoutSeconds int) *http.Client {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 10
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if proxyRaw != "" {
		if proxyURL, err := url.Parse(proxyRaw); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	return &http.Client{Timeout: time.Duration(timeoutSeconds) * time.Second, Transport: transport}
}

func probeBackupURL(client *http.Client, targetURL string) probeResult {
	result := doProbeRequest(client, http.MethodHead, targetURL)
	if shouldRetryWithRange(result) {
		result = doProbeRequest(client, http.MethodGet, targetURL)
	}
	return result
}

func shouldRetryWithRange(result probeResult) bool {
	if result.StatusCode == http.StatusMethodNotAllowed || result.StatusCode == http.StatusNotImplemented {
		return true
	}
	if result.StatusCode == http.StatusOK && result.ContentLength < 0 && result.ContentType == "" {
		return true
	}
	return false
}

func doProbeRequest(client *http.Client, method, targetURL string) probeResult {
	ctx, cancel := context.WithTimeout(context.Background(), client.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		return probeResult{URL: targetURL, Method: method, StatusCode: 0, ContentLength: -1}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
	if method == http.MethodGet {
		req.Header.Set("Range", "bytes=0-0")
	}

	resp, err := client.Do(req)
	if err != nil {
		return probeResult{URL: targetURL, Method: method, StatusCode: 0, ContentLength: -1}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1))

	return probeResult{
		URL:           targetURL,
		Method:        method,
		StatusCode:    resp.StatusCode,
		ContentLength: resp.ContentLength,
		ContentType:   strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type"))),
	}
}

func isBackupHit(probe, baseline probeResult) bool {
	if probe.StatusCode != http.StatusOK && probe.StatusCode != http.StatusPartialContent {
		return false
	}
	if looksLikeBaseline(probe, baseline) {
		return false
	}
	if probe.ContentLength >= 0 && probe.ContentLength < 64 {
		return false
	}
	if isLikelyErrorPageContentType(probe.ContentType) {
		return false
	}
	return true
}

func looksLikeBaseline(probe, baseline probeResult) bool {
	if baseline.StatusCode != http.StatusOK && baseline.StatusCode != http.StatusPartialContent {
		return false
	}
	if probe.StatusCode != baseline.StatusCode {
		return false
	}
	if probe.ContentLength >= 0 && baseline.ContentLength >= 0 && probe.ContentLength == baseline.ContentLength {
		return true
	}
	if probe.ContentType != "" && baseline.ContentType != "" && probe.ContentType == baseline.ContentType && isLikelyErrorPageContentType(probe.ContentType) {
		return true
	}
	return false
}

func isLikelyErrorPageContentType(contentType string) bool {
	contentType = strings.ToLower(contentType)
	return strings.Contains(contentType, "text/html") || strings.Contains(contentType, "json") || strings.Contains(contentType, "xml")
}

func emitBackupResult(probe probeResult) {
	additional := fmt.Sprintf("method=%s length=%d type=%s", probe.Method, probe.ContentLength, probe.ContentType)
	result := ddout.OutputMessage{
		Type:          "Backup",
		URI:           probe.URL,
		Web:           ddout.WebInfo{Status: strconv.Itoa(probe.StatusCode)},
		AdditionalMsg: additional,
	}
	ddout.FormatOutput(result)
	report.AddBackupResult(result)
}
