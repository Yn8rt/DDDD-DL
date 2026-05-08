package unauth

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	dddhttp "dddd/common/http"
	"dddd/common/progress"
	"dddd/common/report"
	"dddd/ddout"
	"dddd/structs"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx"
	"github.com/projectdiscovery/httpx/runner"
)

var staticExtensions = map[string]struct{}{
	".7z": {}, ".avi": {}, ".bmp": {}, ".css": {}, ".eot": {}, ".gif": {}, ".gz": {},
	".ico": {}, ".jpeg": {}, ".jpg": {}, ".js": {}, ".map": {}, ".mp3": {}, ".mp4": {},
	".pdf": {}, ".png": {}, ".rar": {}, ".svg": {}, ".tar": {}, ".ttf": {}, ".txt": {},
	".wav": {}, ".webm": {}, ".webp": {}, ".woff": {}, ".woff2": {}, ".xml": {}, ".zip": {},
}

var apiPathKeywords = []string{
	"/api", "/rest", "/graphql", "/rpc", "/swagger", "/openapi", "/actuator",
	"/gateway", "/service", "/interface", "/endpoint",
	"/v1/", "/v2/", "/v3/",
}

type baselineProfile struct {
	loginHashes map[string]struct{}
	loginTitles map[string]struct{}
}

type probeDetector struct {
	sources   map[string]string
	baselines map[string]baselineProfile

	mu    sync.Mutex
	seen  map[string]struct{}
	found int
}

type katanaMode struct {
	Name string
	Flag string
}

type katanaRunResult struct {
	Mode string
	URLs []katanaDiscoveredURL
}

type katanaDiscoveredURL struct {
	URL      string
	Evidence string
}

func Run(baseURLs []string) {
	if !structs.GlobalConfig.EnableAPIUnauthScan {
		return
	}
	if len(baseURLs) == 0 {
		gologger.Warning().Msg("未授权接口探测跳过: 没有可用 Web 目标")
		return
	}

	if !katanaBinaryAvailable(structs.GlobalConfig.KatanaPath) {
		gologger.Warning().Msgf("未授权接口探测跳过: 未找到 katana 程序 (%s)", resolveKatanaPath(structs.GlobalConfig.KatanaPath))
		return
	}

	targets, sources := buildProbeTargets(baseURLs)
	if len(targets) == 0 {
		gologger.Warning().Msg("未授权接口探测跳过: Katana 未生成新的候选路径")
		return
	}

	gologger.Info().Msgf(aurora.BrightCyan("[未授权接口] 开始探测 %d 个候选目标").String(), len(targets))
	bar := progress.New("未授权接口", len(targets))
	defer bar.Finish()

	detector := &probeDetector{
		sources:   sources,
		baselines: buildBaselines(),
		seen:      make(map[string]struct{}),
	}
	onProgress := func(current, total int) { bar.Set(current) }
	httpx.CallHTTPxWithProgress(
		targets,
		detector.handleResponse,
		onProgress,
		structs.GlobalConfig.HTTPProxy,
		structs.GlobalConfig.WebThreads,
		structs.GlobalConfig.WebTimeout,
	)

	if detector.found == 0 {
		gologger.Info().Msg(aurora.BrightYellow("[未授权接口] 未发现疑似未授权接口").String())
		return
	}
	gologger.Info().Msgf(aurora.BrightGreen("[未授权接口] 共发现 %d 个疑似目标").String(), detector.found)
}

func buildProbeTargets(baseURLs []string) ([]string, map[string]string) {
	maxTargets := structs.GlobalConfig.APIUnauthMaxTargets
	if maxTargets <= 0 {
		maxTargets = 500
	}

	baseURLs = removeDuplicates(baseURLs)
	sort.Strings(baseURLs)

	var targets []string
	sources := make(map[string]string)

	for _, baseURL := range baseURLs {
		if len(targets) >= maxTargets {
			break
		}

		discovered, err := crawlWithKatana(baseURL)
		if err != nil {
			gologger.Warning().Msgf("[未授权接口] Katana 爬取失败 %s: %v", baseURL, err)
			continue
		}

		absolutePaths, firstLevelDirs, relativePaths := collectCandidateParts(baseURL, discovered)
		baseAdded := 0
		for _, candidate := range setToSortedStringMapKeys(absolutePaths) {
			if len(targets) >= maxTargets {
				break
			}
			fullURL := joinBaseAndPath(baseURL, candidate)
			if fullURL == "" || hasCandidate(targets, fullURL) {
				continue
			}
			targets = append(targets, fullURL)
			sources[fullURL] = formatProbeSource("绝对路径", absolutePaths[candidate])
			gologger.Info().Msg(formatKatanaProbeLine(sources[fullURL], fullURL))
			baseAdded++
		}

		for _, firstLevelDir := range setToSortedStringMapKeys(firstLevelDirs) {
			if len(targets) >= maxTargets {
				break
			}
			for _, relativePath := range setToSortedStringMapKeys(relativePaths) {
				if len(targets) >= maxTargets {
					break
				}
				joinedPath := joinRelativePath(firstLevelDir, relativePath)
				if joinedPath == "" || joinedPath == firstLevelDir || joinedPath == relativePath {
					continue
				}
				fullURL := joinBaseAndPath(baseURL, joinedPath)
				if fullURL == "" || hasCandidate(targets, fullURL) {
					continue
				}
				targets = append(targets, fullURL)
				if _, ok := sources[fullURL]; !ok {
					evidence := relativePaths[relativePath]
					if evidence == "" {
						evidence = firstLevelDirs[firstLevelDir]
					}
					sources[fullURL] = formatProbeSource("一级目录拼接", evidence)
				}
				gologger.Info().Msg(formatKatanaProbeLine(sources[fullURL], fullURL))
				baseAdded++
			}
		}

		gologger.Info().Msgf(
			"[未授权接口] %s -> Katana:%d 绝对路径:%d 一级目录:%d 相对路径:%d 候选:%d",
			baseURL, len(discovered), len(absolutePaths), len(firstLevelDirs), len(relativePaths), baseAdded,
		)
	}

	return targets, sources
}

func crawlWithKatana(baseURL string) ([]katanaDiscoveredURL, error) {
	mode := selectedKatanaMode()
	result, err := runKatanaMode(baseURL, mode)
	if err != nil {
		return dedupeDiscoveredURLs(result.URLs), err
	}
	gologger.Info().Msgf("%s 共发现 %d 条URL", formatKatanaTag(result.Mode), len(result.URLs))
	return dedupeDiscoveredURLs(result.URLs), nil
}

func runKatanaMode(baseURL string, mode katanaMode) (katanaRunResult, error) {
	args := []string{
		"-u", baseURL,
		mode.Flag,
		"-xhr",
		"-jc",
		"-v",
		"-jsl",
		"-d", strconv.Itoa(defaultKatanaDepth()),
		"-ct", defaultCrawlDuration(),
		"-timeout", strconv.Itoa(defaultKatanaTimeout()),
	}
	if structs.GlobalConfig.HTTPProxy != "" {
		args = append(args, "-proxy", structs.GlobalConfig.HTTPProxy)
	}

	gologger.Info().Msgf("%s %s %s", formatKatanaTag(mode.Name), aurora.BrightWhite(resolveKatanaPath(structs.GlobalConfig.KatanaPath)).String(), aurora.BrightBlack(strings.Join(args, " ")).String())
	cmd := exec.Command(resolveKatanaPath(structs.GlobalConfig.KatanaPath), args...)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color", "FORCE_COLOR=1", "CLICOLOR_FORCE=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return katanaRunResult{}, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return katanaRunResult{}, err
	}

	if err := cmd.Start(); err != nil {
		return katanaRunResult{}, err
	}

	var (
		urls []katanaDiscoveredURL
		mu   sync.Mutex
		wg   sync.WaitGroup
	)

	scanLines := func(scanner *bufio.Scanner) {
		defer wg.Done()
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			if shouldLogKatanaLine(line) {
				gologger.Silent().Msg(line)
			}
			extractedURL := extractURLFromKatanaLine(line)
			if extractedURL != "" {
				gologger.Info().Msgf("%s %s", formatKatanaTag(mode.Name), aurora.BrightCyan(extractedURL).String())
				mu.Lock()
				urls = append(urls, katanaDiscoveredURL{
					URL:      extractedURL,
					Evidence: classifyKatanaLine(line),
				})
				mu.Unlock()
			}
		}
	}

	wg.Add(2)
	go scanLines(bufio.NewScanner(stdout))
	go scanLines(bufio.NewScanner(stderr))
	wg.Wait()

	if err := cmd.Wait(); err != nil {
		if len(urls) > 0 {
			gologger.Warning().Msgf("%s 进程异常退出，但已获取 %d 条URL: %v", formatKatanaTag(mode.Name), len(dedupeDiscoveredURLs(urls)), err)
			return katanaRunResult{Mode: mode.Name, URLs: dedupeDiscoveredURLs(urls)}, nil
		}
		return katanaRunResult{Mode: mode.Name, URLs: dedupeDiscoveredURLs(urls)}, err
	}

	return katanaRunResult{Mode: mode.Name, URLs: dedupeDiscoveredURLs(urls)}, nil
}

func extractURLFromKatanaLine(line string) string {
	start := strings.Index(line, "http://")
	if start < 0 {
		start = strings.Index(line, "https://")
	}
	if start < 0 {
		return ""
	}

	raw := line[start:]
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return ""
	}
	token := strings.TrimSpace(fields[0])
	token = strings.TrimRight(token, ":,;)]}\"'")
	token = strings.TrimRight(token, ".")
	return token
}

func shouldLogKatanaLine(line string) bool {
	for _, marker := range []string{"[ERR]", "[WRN]", "[INF]", "[GET]", "[link]", "[script]", "[html]", "[xhr]", "[a]", "[img]", "[iframe]"} {
		if strings.Contains(line, marker) {
			return true
		}
	}
	return false
}

func selectedKatanaMode() katanaMode {
	switch strings.ToLower(strings.TrimSpace(structs.GlobalConfig.KatanaMode)) {
	case "hh":
		return katanaMode{Name: "hh", Flag: "-hh"}
	default:
		return katanaMode{Name: "hl", Flag: "-hl"}
	}
}

func classifyKatanaLine(line string) string {
	lowerLine := strings.ToLower(line)
	for _, item := range []struct {
		marker string
		name   string
	}{
		{"[xhr]", "xhr"},
		{"[script]", "script"},
		{"[html]", "html"},
		{"[link]", "link"},
		{"[img]", "img"},
		{"[iframe]", "iframe"},
		{"[a]", "anchor"},
		{"[get]", "get"},
	} {
		if strings.Contains(lowerLine, item.marker) {
			return item.name
		}
	}
	return "unknown"
}

func shouldUseDiscoveredPath(candidatePath, evidence string) bool {
	if looksAPIPath(candidatePath) {
		return true
	}
	switch evidence {
	case "xhr", "script":
		return !isLikelyFrontEndNoise(candidatePath)
	case "get":
		return strings.Count(strings.Trim(candidatePath, "/"), "/") >= 1 && !isLikelyFrontEndNoise(candidatePath)
	default:
		return false
	}
}

func isLikelyFrontEndNoise(candidatePath string) bool {
	lowerPath := strings.ToLower(candidatePath)
	if isLoginLike(lowerPath, "") || isPublicPath(lowerPath) {
		return true
	}
	trimmed := strings.Trim(lowerPath, "/")
	if trimmed == "" {
		return true
	}
	if !strings.Contains(trimmed, "/") && len(trimmed) <= 2 {
		return true
	}
	for _, keyword := range []string{"/captcha", "/static/", "/assets/", "/images/", "/img/", "/css/", "/js/"} {
		if strings.Contains(lowerPath, keyword) {
			return true
		}
	}
	return false
}

func preferredEvidence(current, incoming string) string {
	if evidencePriority(incoming) > evidencePriority(current) {
		return incoming
	}
	if current == "" {
		return incoming
	}
	return current
}

func evidencePriority(evidence string) int {
	switch evidence {
	case "xhr":
		return 5
	case "script":
		return 4
	case "get":
		return 3
	case "html":
		return 2
	case "link":
		return 1
	default:
		return 0
	}
}

func formatProbeSource(base, evidence string) string {
	if evidence == "" || evidence == "unknown" {
		return base
	}
	return fmt.Sprintf("%s | 来源:%s", base, evidence)
}

func formatKatanaTag(mode string) string {
	return aurora.BrightMagenta(fmt.Sprintf("[Katana-%s]", mode)).String()
}

func formatKatanaProbeLine(source, targetURL string) string {
	return fmt.Sprintf("%s [%s] %s",
		aurora.BrightBlue("[Katana-Probe]").String(),
		aurora.BrightYellow(source).String(),
		aurora.BrightCyan(targetURL).String(),
	)
}

func collectCandidateParts(baseURL string, discovered []katanaDiscoveredURL) (map[string]string, map[string]string, map[string]string) {
	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return nil, nil, nil
	}

	absoluteSet := make(map[string]string)
	firstLevelSet := make(map[string]string)
	relativeSet := make(map[string]string)

	for _, item := range discovered {
		parsedURL, err := url.Parse(strings.TrimSpace(item.URL))
		if err != nil || parsedURL.Host == "" {
			continue
		}
		if !sameHost(parsedBase.Host, parsedURL.Host) {
			continue
		}

		candidatePath := normalizeCandidatePath(parsedURL.Path)
		if candidatePath == "" || candidatePath == "/" || isKnownPath(baseURL, candidatePath) {
			continue
		}
		if isStaticAssetPath(candidatePath) || isKnownStaticDataPath(candidatePath) || containsTemplateMarker(candidatePath) {
			continue
		}
		if !shouldUseDiscoveredPath(candidatePath, item.Evidence) {
			continue
		}

		absoluteSet[candidatePath] = preferredEvidence(absoluteSet[candidatePath], item.Evidence)
		firstLevelDir, relativePath, ok := splitFirstLevelAndRelative(candidatePath)
		if ok {
			firstLevelSet[firstLevelDir] = preferredEvidence(firstLevelSet[firstLevelDir], item.Evidence)
			relativeSet[relativePath] = preferredEvidence(relativeSet[relativePath], item.Evidence)
		}
	}

	return absoluteSet, firstLevelSet, relativeSet
}

func normalizeCandidatePath(rawPath string) string {
	rawPath = strings.TrimSpace(rawPath)
	if rawPath == "" {
		return ""
	}
	cleanPath := path.Clean("/" + strings.TrimPrefix(rawPath, "/"))
	if cleanPath == "." {
		return "/"
	}
	if !strings.HasPrefix(cleanPath, "/") {
		cleanPath = "/" + cleanPath
	}
	return cleanPath
}

func splitFirstLevelAndRelative(candidatePath string) (string, string, bool) {
	trimmed := strings.TrimPrefix(candidatePath, "/")
	if trimmed == "" {
		return "", "", false
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 {
		return "", "", false
	}

	firstLevelDir := "/" + parts[0]
	relativePath := "/" + path.Join(parts[1:]...)
	return firstLevelDir, relativePath, true
}

func joinRelativePath(firstLevelDir, relativePath string) string {
	firstLevelDir = normalizeCandidatePath(firstLevelDir)
	relativePath = normalizeCandidatePath(relativePath)
	if firstLevelDir == "" || relativePath == "" || relativePath == "/" {
		return ""
	}
	return normalizeCandidatePath(firstLevelDir + "/" + strings.TrimPrefix(relativePath, "/"))
}

func isStaticAssetPath(candidatePath string) bool {
	ext := strings.ToLower(path.Ext(candidatePath))
	if ext == "" {
		return false
	}
	_, ok := staticExtensions[ext]
	return ok
}

func containsTemplateMarker(candidatePath string) bool {
	lowerPath := strings.ToLower(candidatePath)
	if strings.ContainsAny(lowerPath, "\"'{}<>`") {
		return true
	}
	for _, marker := range []string{"+", "${", "%7b", "%7d"} {
		if strings.Contains(lowerPath, marker) {
			return true
		}
	}
	return false
}

func isKnownPath(baseURL, candidatePath string) bool {
	structs.GlobalURLMapLock.Lock()
	defer structs.GlobalURLMapLock.Unlock()

	entry, ok := structs.GlobalURLMap[baseURL]
	if !ok {
		return false
	}
	_, ok = entry.WebPaths[candidatePath]
	return ok
}

func joinBaseAndPath(baseURL, candidatePath string) string {
	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	parsedBase.Path = normalizeCandidatePath(candidatePath)
	parsedBase.RawQuery = ""
	parsedBase.Fragment = ""
	return parsedBase.String()
}

func buildBaselines() map[string]baselineProfile {
	structs.GlobalURLMapLock.Lock()
	defer structs.GlobalURLMapLock.Unlock()

	baselines := make(map[string]baselineProfile, len(structs.GlobalURLMap))
	for rootURL, urlEntity := range structs.GlobalURLMap {
		profile := baselineProfile{
			loginHashes: make(map[string]struct{}),
			loginTitles: make(map[string]struct{}),
		}
		for pathValue, pathEntity := range urlEntity.WebPaths {
			if isLoginLike(pathValue, pathEntity.Title) {
				if pathEntity.Hash != "" {
					profile.loginHashes[pathEntity.Hash] = struct{}{}
				}
				if pathEntity.Title != "" {
					profile.loginTitles[strings.ToLower(strings.TrimSpace(pathEntity.Title))] = struct{}{}
				}
			}
		}
		baselines[rootURL] = profile
	}
	return baselines
}

func (d *probeDetector) handleResponse(resp runner.Result) {
	finalURL := resp.URL
	if resp.FinalURL != "" {
		finalURL = resp.FinalURL
	}
	_ = dddhttp.StoreURLResult(resp, finalURL)
	report.AddAPIUnauthScanResult(ddout.OutputMessage{
		Type: "API-Unauth",
		URI:  resp.URL,
		Web: ddout.WebInfo{
			Status: strconv.Itoa(resp.StatusCode),
			Title:  resp.Title,
		},
		AdditionalMsg: d.sources[resp.URL],
	})

	if !d.isPotentialUnauthorized(resp, finalURL) {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.seen[resp.URL]; ok {
		return
	}
	d.seen[resp.URL] = struct{}{}
	d.found++

	source := d.sources[resp.URL]
	if source == "" {
		source = "Katana"
	}
	gologger.Info().Msgf(aurora.BrightRed("[疑似未授权] [%d] %s [%s]").String(), resp.StatusCode, resp.URL, source)
	ddout.FormatOutput(ddout.OutputMessage{
		Type: "API-Unauth",
		URI:  resp.URL,
		Web: ddout.WebInfo{
			Status: strconv.Itoa(resp.StatusCode),
			Title:  resp.Title,
		},
		AdditionalMsg: source,
	})
	report.AddAPIUnauthResult(ddout.OutputMessage{
		Type: "API-Unauth",
		URI:  resp.URL,
		Web: ddout.WebInfo{
			Status: strconv.Itoa(resp.StatusCode),
			Title:  resp.Title,
		},
		AdditionalMsg: source,
	})
}

func (d *probeDetector) isPotentialUnauthorized(resp runner.Result, finalURL string) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return false
	}

	parsedFinalURL, err := url.Parse(finalURL)
	if err != nil {
		return false
	}
	finalPath := normalizeCandidatePath(parsedFinalURL.Path)
	if finalPath == "" || finalPath == "/" || isStaticAssetPath(finalPath) || isKnownStaticDataPath(finalPath) {
		return false
	}
	if isPublicPath(finalPath) || isLoginLike(finalPath, resp.Title) {
		return false
	}

	rootURL := fmt.Sprintf("%s://%s", parsedFinalURL.Scheme, parsedFinalURL.Host)
	if profile, ok := d.baselines[rootURL]; ok {
		if _, matched := profile.loginHashes[safeHash(resp, "body_md5")]; matched {
			return false
		}
		if _, matched := profile.loginTitles[strings.ToLower(strings.TrimSpace(resp.Title))]; matched {
			return false
		}
	}

	if isLikelyAPIResponse(finalPath, resp.ContentType, resp.Body) {
		return true
	}
	return looksAPIPath(finalPath)
}

func isLoginLike(candidatePath, title string) bool {
	lowerPath := strings.ToLower(candidatePath)
	lowerTitle := strings.ToLower(strings.TrimSpace(title))
	for _, keyword := range []string{"login", "signin", "sign-in", "auth", "passport", "sso", "登陆", "登录", "认证"} {
		if strings.Contains(lowerPath, keyword) || strings.Contains(lowerTitle, keyword) {
			return true
		}
	}
	return false
}

func isPublicPath(candidatePath string) bool {
	lowerPath := strings.ToLower(candidatePath)
	for _, keyword := range []string{
		"/sign_up", "/signup", "/register", "/forgot_password", "/reset_password",
		"/explore", "/users/", "/organizations", "/repos", "/stars", "/forks",
		"/assets", "/avatars", "/public", "/css/", "/js/", "/img/", "/images/",
	} {
		if strings.Contains(lowerPath, keyword) {
			return true
		}
	}
	return false
}

func isAPIContentType(contentType string) bool {
	lowerContentType := strings.ToLower(contentType)
	for _, token := range []string{"application/json", "application/problem+json", "application/xml", "text/xml"} {
		if strings.Contains(lowerContentType, token) {
			return true
		}
	}
	return false
}

func looksLikeJSONBody(body string) bool {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return false
	}
	return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}

func isLikelyAPIResponse(candidatePath, contentType, body string) bool {
	if isAPIContentType(contentType) || looksLikeJSONBody(body) {
		return true
	}
	return looksAPIPath(candidatePath)
}

func looksAPIPath(candidatePath string) bool {
	lowerPath := strings.ToLower(candidatePath)
	for _, keyword := range apiPathKeywords {
		if strings.Contains(lowerPath, keyword) {
			return true
		}
	}
	return false
}

func isKnownStaticDataPath(candidatePath string) bool {
	lowerPath := strings.ToLower(candidatePath)
	for _, item := range []string{
		"/version.json", "/manifest.json", "/asset-manifest.json", "/site.webmanifest",
		"/robots.txt", "/sitemap.xml", "/browserconfig.xml", "/humans.txt",
	} {
		if strings.HasSuffix(lowerPath, item) {
			return true
		}
	}
	return false
}

func safeHash(resp runner.Result, key string) string {
	if resp.Hashes == nil {
		return ""
	}
	raw, ok := resp.Hashes[key]
	if !ok {
		return ""
	}
	hashValue, ok := raw.(string)
	if !ok {
		return ""
	}
	return hashValue
}

func resolveKatanaPath(input string) string {
	if strings.TrimSpace(input) != "" {
		return input
	}
	if runtime.GOOS == "windows" {
		if _, err := os.Stat(".\\katana.exe"); err == nil {
			return ".\\katana.exe"
		}
		return "katana.exe"
	}
	if _, err := os.Stat("./katana"); err == nil {
		return "./katana"
	}
	return "katana"
}

func katanaBinaryAvailable(input string) bool {
	_, err := exec.LookPath(resolveKatanaPath(input))
	return err == nil
}

func defaultKatanaDepth() int {
	if structs.GlobalConfig.KatanaDepth > 0 {
		return structs.GlobalConfig.KatanaDepth
	}
	return 3
}

func defaultKatanaTimeout() int {
	if structs.GlobalConfig.KatanaTimeout > 0 {
		return structs.GlobalConfig.KatanaTimeout
	}
	return 10
}

func defaultCrawlDuration() string {
	if strings.TrimSpace(structs.GlobalConfig.KatanaCrawlDuration) != "" {
		return structs.GlobalConfig.KatanaCrawlDuration
	}
	return "15s"
}

func sameHost(left, right string) bool {
	return strings.EqualFold(strings.TrimSpace(left), strings.TrimSpace(right))
}

func removeDuplicates(input []string) []string {
	seen := make(map[string]struct{}, len(input))
	result := make([]string, 0, len(input))
	for _, item := range input {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	return result
}

func hasCandidate(targets []string, candidate string) bool {
	for _, existing := range targets {
		if existing == candidate {
			return true
		}
	}
	return false
}

func setToSortedSlice(input map[string]struct{}) []string {
	result := make([]string, 0, len(input))
	for item := range input {
		result = append(result, item)
	}
	sort.Strings(result)
	return result
}

func setToSortedStringMapKeys(input map[string]string) []string {
	result := make([]string, 0, len(input))
	for item := range input {
		result = append(result, item)
	}
	sort.Strings(result)
	return result
}

func dedupeDiscoveredURLs(input []katanaDiscoveredURL) []katanaDiscoveredURL {
	seen := make(map[string]katanaDiscoveredURL, len(input))
	for _, item := range input {
		item.URL = strings.TrimSpace(item.URL)
		if item.URL == "" {
			continue
		}
		existing, ok := seen[item.URL]
		if !ok {
			seen[item.URL] = item
			continue
		}
		existing.Evidence = preferredEvidence(existing.Evidence, item.Evidence)
		seen[item.URL] = existing
	}
	result := make([]katanaDiscoveredURL, 0, len(seen))
	for _, item := range seen {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].URL < result[j].URL
	})
	return result
}
