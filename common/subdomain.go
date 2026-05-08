package common

import (
	"bufio"
	"bytes"
	"dddd/ddout"
	"dddd/structs"
	"dddd/utils"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	_ "embed"

	"github.com/projectdiscovery/gologger"
)

var ansiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// SubFinder 调用外部 subfinder 命令进行子域名被动收集
func SubFinder(domain string) []string {
	var results []string

	subfinderPath, err := resolveExternalTool("subfinder", "subfinder")
	if err != nil {
		ddout.FormatOutput(ddout.OutputMessage{
			Type:          "DNS-SubFinder",
			AdditionalMsg: "subfinder 未安装，跳过被动子域名收集",
		})
		return results
	}

	args := []string{"-d", domain, "-silent"}
	if structs.GlobalConfig.APIConfigFilePath != "" {
		args = append(args, "-provider-config", structs.GlobalConfig.APIConfigFilePath)
	}

	cmd := exec.Command(subfinderPath, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return results
	}

	if err := cmd.Start(); err != nil {
		return results
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		subdomain := strings.TrimSpace(scanner.Text())
		if subdomain != "" {
			results = append(results, subdomain)
			ddout.FormatOutput(ddout.OutputMessage{
				Type:   "DNS-SubFinder",
				Domain: subdomain,
			})
		}
	}

	_ = cmd.Wait()
	return results
}

func DNSCallback(subdomain string) {
	ddout.FormatOutput(ddout.OutputMessage{
		Type:   "DNS-Brute",
		Domain: subdomain,
	})
}

//go:embed config/subdomains.txt
var EmbedSubdomainDict string

func GetSubDomain(domains []string) []string {
	var results []string

	for _, domain := range domains {
		if !structs.GlobalConfig.NoSubdomainBruteForce {
			results = append(results, bruteSubDomain(domain)...)
		}

		if !structs.GlobalConfig.NoSubFinder {
			results = append(results, SubFinder(domain)...)
		}
	}

	return utils.RemoveDuplicateElement(results)
}

func bruteSubDomain(domain string) []string {
	engine := strings.ToLower(strings.TrimSpace(structs.GlobalConfig.SubdomainEngine))
	if engine == "" {
		engine = "dnsx"
	}

	switch engine {
	case "ksubdomain":
		results, err := callKSubdomain(domain)
		if err != nil {
			gologger.Warning().Msgf("ksubdomain 子域名爆破失败: %v", err)
		}
		return results
	case "auto":
		results, err := callKSubdomain(domain)
		if err == nil {
			return results
		}
		gologger.Warning().Msgf("ksubdomain 不可用，回退 dnsx: %v", err)
		fallback, fallbackErr := callDNSx(domain)
		if fallbackErr != nil {
			gologger.Warning().Msgf("dnsx 子域名爆破失败: %v", fallbackErr)
		}
		return utils.RemoveDuplicateElement(append(results, fallback...))
	default:
		results, err := callDNSx(domain)
		if err != nil {
			gologger.Warning().Msgf("dnsx 子域名爆破失败: %v", err)
		}
		return results
	}
}

func callDNSx(domain string) ([]string, error) {
	dnsxPath, err := resolveExternalTool(structs.GlobalConfig.DNSXPath, "dnsx")
	if err != nil {
		return nil, err
	}

	wordlistPath, cleanup, err := prepareSubdomainWordlist()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	threads := structs.GlobalConfig.SubdomainBruteForceThreads
	if threads <= 0 {
		threads = 1
	}

	args := []string{
		"-d", domain,
		"-w", wordlistPath,
		"-silent",
		"-duc",
		"-t", strconv.Itoa(threads),
	}
	gologger.Info().Msgf("使用外部 dnsx 爆破子域名: %s", domain)
	return runSubdomainCommand("dnsx", dnsxPath, args, domain)
}

func callKSubdomain(domain string) ([]string, error) {
	ksubdomainPath, err := resolveExternalTool(structs.GlobalConfig.KSubdomainPath, "ksubdomain")
	if err != nil {
		return nil, err
	}

	wordlistPath, cleanup, err := prepareSubdomainWordlist()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	band := strings.TrimSpace(structs.GlobalConfig.KSubdomainBand)
	if band == "" {
		band = "3m"
	}
	wildcard := strings.ToLower(strings.TrimSpace(structs.GlobalConfig.KSubdomainWildcard))
	if wildcard == "" {
		wildcard = "basic"
	}

	args := []string{
		"enum",
		"-d", domain,
		"-f", wordlistPath,
		"--silent",
		"--band", band,
		"--wild-filter-mode", wildcard,
	}
	if structs.GlobalConfig.KSubdomainInterface != "" {
		args = append(args, "--eth", structs.GlobalConfig.KSubdomainInterface)
	}

	gologger.Info().Msgf("使用外部 ksubdomain 爆破子域名: %s", domain)
	return runSubdomainCommand("ksubdomain", ksubdomainPath, args, domain)
}

func runSubdomainCommand(toolName, executable string, args []string, rootDomain string) ([]string, error) {
	cmd := exec.Command(executable, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var results []string
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	for scanner.Scan() {
		subdomain := parseSubdomainOutput(scanner.Text(), rootDomain)
		if subdomain == "" {
			continue
		}
		if _, exists := seen[subdomain]; exists {
			continue
		}
		seen[subdomain] = struct{}{}
		results = append(results, subdomain)
		DNSCallback(subdomain)
	}

	scanErr := scanner.Err()
	waitErr := cmd.Wait()
	if scanErr != nil {
		return results, scanErr
	}
	if waitErr != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = waitErr.Error()
		}
		return results, fmt.Errorf("%s 执行失败: %s", toolName, message)
	}

	return results, nil
}

func prepareSubdomainWordlist() (string, func(), error) {
	wordlistPath := strings.TrimSpace(structs.GlobalConfig.SubdomainWordListFile)
	if wordlistPath != "" && strings.ToLower(wordlistPath) != "embedded" {
		return wordlistPath, func() {}, nil
	}

	tmpFile, err := os.CreateTemp("", "dddd-subdomains-*.txt")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.Remove(tmpFile.Name()) }

	dict := strings.ReplaceAll(EmbedSubdomainDict, "\r\n", "\n")
	if _, err := tmpFile.WriteString(dict); err != nil {
		_ = tmpFile.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := tmpFile.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}

	return tmpFile.Name(), cleanup, nil
}

func resolveExternalTool(configured string, names ...string) (string, error) {
	var candidates []string
	if strings.TrimSpace(configured) != "" {
		candidates = append(candidates, strings.TrimSpace(configured))
	}
	candidates = append(candidates, names...)

	for _, candidate := range candidates {
		for _, localPath := range localExecutableCandidates(candidate) {
			if fileExists(localPath) {
				if absPath, err := filepath.Abs(localPath); err == nil {
					return absPath, nil
				}
				return localPath, nil
			}
		}
	}

	for _, candidate := range candidates {
		path, err := exec.LookPath(candidate)
		if err == nil {
			return path, nil
		}
		if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(candidate), ".exe") {
			path, err = exec.LookPath(candidate + ".exe")
			if err == nil {
				return path, nil
			}
		}
	}

	return "", fmt.Errorf("未找到外部程序: %s", strings.Join(candidates, ","))
}

func localExecutableCandidates(name string) []string {
	if name == "" {
		return nil
	}

	var candidates []string
	add := func(path string) {
		if path == "" {
			return
		}
		candidates = append(candidates, path)
		if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(path), ".exe") {
			candidates = append(candidates, path+".exe")
		}
	}

	add(name)
	if !filepath.IsAbs(name) && !strings.ContainsAny(name, `/\`) {
		if wd, err := os.Getwd(); err == nil {
			add(filepath.Join(wd, name))
		}
	}

	return candidates
}

func parseSubdomainOutput(line, rootDomain string) string {
	line = ansiEscapePattern.ReplaceAllString(line, "")
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "[") || strings.HasPrefix(line, "|") || strings.HasPrefix(line, "_") {
		return ""
	}

	if strings.Contains(line, "=>") {
		line = strings.SplitN(line, "=>", 2)[0]
	}

	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}

	candidate := strings.Trim(fields[0], "\"'`,;[]()")
	candidate = strings.TrimSuffix(candidate, ".")
	candidate = strings.ToLower(candidate)
	rootDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rootDomain), "."))
	if candidate == rootDomain {
		return ""
	}
	if strings.HasSuffix(candidate, "."+rootDomain) {
		return candidate
	}

	return ""
}
