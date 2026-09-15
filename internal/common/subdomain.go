package common

import (
	"bufio"
	"bytes"
	"dddd/internal/ddout"
	"dddd/internal/structs"
	"dddd/internal/utils"
	"fmt"
	"net"
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
			gologger.Error().Msgf("ksubdomain 子域名爆破失败: %v", err)
		}
		return results
	case "auto":
		results, err := callKSubdomain(domain)
		if err == nil && len(results) > 0 {
			return results
		}
		if err == nil {
			err = fmt.Errorf("ksubdomain 未返回有效子域名")
		}
		gologger.Info().Msgf("ksubdomain 不可用，回退 dnsx: %v", err)
		fallback, fallbackErr := callDNSx(domain)
		if fallbackErr != nil {
			gologger.Error().Msgf("dnsx 子域名爆破失败: %v", fallbackErr)
		}
		return utils.RemoveDuplicateElement(append(results, fallback...))
	default:
		results, err := callDNSx(domain)
		if err != nil {
			gologger.Error().Msgf("dnsx 子域名爆破失败: %v", err)
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
	gologger.Info().Msgf("使用外部 dnsx 爆破子域名: %s (%s)", domain, dnsxPath)
	return runSubdomainCommand("dnsx", dnsxPath, args, domain)
}

func callKSubdomain(domain string) ([]string, error) {
	ksubdomainPath, err := resolveExternalTool(structs.GlobalConfig.KSubdomainPath, "ksubdomain")
	if err != nil {
		return nil, err
	}
	if err := checkKSubdomainRuntime(); err != nil {
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
	ksubdomainInterface := strings.TrimSpace(structs.GlobalConfig.KSubdomainInterface)
	if ksubdomainInterface == "" {
		ksubdomainInterface = detectKSubdomainInterface()
		if ksubdomainInterface != "" {
			gologger.Info().Msgf("自动选择 ksubdomain 网卡: %s", ksubdomainInterface)
		}
	}
	if ksubdomainInterface != "" {
		args = append(args, "--eth", ksubdomainInterface)
	}

	gologger.Info().Msgf("使用外部 ksubdomain 爆破子域名: %s (%s)", domain, ksubdomainPath)
	results, err := runSubdomainCommand("ksubdomain", ksubdomainPath, args, domain)
	if err != nil {
		return results, err
	}
	if len(results) == 0 {
		return results, fmt.Errorf("ksubdomain 未返回有效子域名，可能需要指定网卡(-ksi)或提升权限；可先执行 ksubdomain device 排查")
	}
	return results, nil
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
	var diagnostics []string
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if diagnostic := cleanSubdomainDiagnosticLine(line); diagnostic != "" {
			diagnostics = append(diagnostics, diagnostic)
		}

		subdomain := parseSubdomainOutput(line, rootDomain)
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
			message = strings.Join(diagnostics, "; ")
		}
		if message == "" {
			message = waitErr.Error()
		}
		return results, fmt.Errorf("%s 执行失败: %s", toolName, message)
	}

	return results, nil
}

func cleanSubdomainDiagnosticLine(line string) string {
	line = ansiEscapePattern.ReplaceAllString(line, "")
	line = strings.TrimSpace(strings.Trim(line, "."))
	if line == "" {
		return ""
	}

	lower := strings.ToLower(line)
	markers := []string{"fatal", "error", "panic", "超时", "权限", "网卡"}
	for _, marker := range markers {
		if strings.Contains(lower, marker) {
			return line
		}
	}
	return ""
}

func detectKSubdomainInterface() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, iface := range interfaces {
		if isKSubdomainInterfaceCandidate(iface, false) {
			return iface.Name
		}
	}
	for _, iface := range interfaces {
		if isKSubdomainInterfaceCandidate(iface, true) {
			return iface.Name
		}
	}
	return ""
}

func isKSubdomainInterfaceCandidate(iface net.Interface, allowPointToPoint bool) bool {
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return false
	}
	if !allowPointToPoint && iface.Flags&net.FlagPointToPoint != 0 {
		return false
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		var ip net.IP
		switch item := addr.(type) {
		case *net.IPNet:
			ip = item.IP
		case *net.IPAddr:
			ip = item.IP
		}
		if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
			return true
		}
	}
	return false
}

func checkKSubdomainRuntime() error {
	if runtime.GOOS != "darwin" {
		return nil
	}

	bpfDevices, err := filepath.Glob("/dev/bpf*")
	if err != nil || len(bpfDevices) == 0 {
		return nil
	}
	permissionDenied := false
	for _, device := range bpfDevices {
		file, err := os.OpenFile(device, os.O_RDWR, 0)
		if err == nil {
			_ = file.Close()
			return nil
		}
		if os.IsPermission(err) {
			permissionDenied = true
		}
	}
	if permissionDenied {
		return fmt.Errorf("macOS 当前用户没有 /dev/bpf* 读写权限，ksubdomain 需要 root/BPF 权限；请使用 sudo 运行 dddd，或先执行 sudo chmod a+rw /dev/bpf*")
	}
	return nil
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
			if executableFileExists(localPath) {
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

func executableFileExists(filePath string) bool {
	info, err := os.Stat(filePath)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func localExecutableCandidates(name string) []string {
	if name == "" {
		return nil
	}

	var candidates []string
	seen := make(map[string]struct{})
	add := func(path string) {
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		key := strings.ToLower(path)
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		candidates = append(candidates, path)
	}
	addExecutable := func(path string) {
		add(path)
		if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(path), ".exe") {
			add(path + ".exe")
		}
	}

	addExecutable(name)
	if filepath.IsAbs(name) {
		return candidates
	}

	var baseDirs []string
	if wd, err := os.Getwd(); err == nil {
		baseDirs = append(baseDirs, wd)
	}
	if exePath, err := os.Executable(); err == nil {
		baseDirs = append(baseDirs, filepath.Dir(exePath))
	}

	for _, baseDir := range baseDirs {
		addExecutable(filepath.Join(baseDir, name))
	}

	if !strings.ContainsAny(name, `/\`) {
		for _, baseDir := range baseDirs {
			addExecutable(filepath.Join(baseDir, name, name))
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
