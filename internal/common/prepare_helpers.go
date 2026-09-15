package common

import (
	"dddd/internal/ddout"
	"dddd/internal/structs"
	"dddd/internal/utils"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/retryablehttp-go"
)

func validatePrepareConfig() {
	if structs.GlobalConfig.ReportName != "" {
		suffix := path.Ext(structs.GlobalConfig.ReportName)
		if suffix != ".html" && suffix != ".htm" {
			gologger.Fatal().Msg("HTML输出参数(-ho/--html-output)必须为 .html 或 .htm 后缀")
		}
	}

	if (structs.GlobalConfig.Fofa || structs.GlobalConfig.Hunter) && structs.GlobalConfig.Quake {
		structs.GlobalConfig.Fofa = false
		structs.GlobalConfig.Quake = false
		gologger.Warning().Msg("quake参数不兼容fofa或hunter参数")
	}

	if !strings.HasSuffix(strings.ToLower(structs.GlobalConfig.APIConfigFilePath), ".yaml") {
		gologger.Fatal().Msg("API配置文件需要以 .yaml 为拓展名。")
	}

	if strings.HasPrefix(structs.GlobalConfig.PortScanType, "-") {
		gologger.Fatal().Msg("端口扫描方式请使用 -st syn 或 -st tcp，不存在 -syn 参数")
	}
	validateEnumString(&structs.GlobalConfig.PortScanType, "tcp", "端口扫描方式(-st/--scan-type)", "tcp", "syn")
	normalizeOutputTypeAndFile()
	validateEnumString(&structs.GlobalConfig.OutputType, "text", "输出格式(-ot/--output-type)", "text", "json")
	validateEnumString(&structs.GlobalConfig.SubdomainEngine, "dnsx", "子域名爆破引擎(-sde/--subdomain-engine)", "dnsx", "ksubdomain", "auto")
	validateEnumString(&structs.GlobalConfig.KSubdomainWildcard, "basic", "ksubdomain泛解析过滤模式(-ksw/--ksubdomain-wildcard)", "none", "basic", "advanced")
	validateSeverities()
	normalizePocHeaderConfig()
	configureInteractshDefault()
	configureBackupScanDefaults()
}

func configureBackupScanDefaults() {
	if structs.GlobalConfig.BackupScanMaxTargets <= 0 {
		structs.GlobalConfig.BackupScanMaxTargets = 2000
	}
	if strings.TrimSpace(structs.GlobalConfig.BackupScanExtensions) == "" {
		structs.GlobalConfig.BackupScanExtensions = "zip,tar.gz,tgz,rar,7z,bak,sql"
	}
}

func configureInteractshDefault() {
	if structs.GlobalConfig.EnableInteractsh || strings.TrimSpace(structs.GlobalConfig.InteractshURL) != "" || strings.TrimSpace(structs.GlobalConfig.InteractshToken) != "" {
		structs.GlobalConfig.NoInteractsh = false
		return
	}
	structs.GlobalConfig.NoInteractsh = true
}

func normalizeOutputTypeAndFile() {
	outputType := strings.TrimSpace(structs.GlobalConfig.OutputType)
	if outputType == "" {
		return
	}

	normalized := strings.ToLower(outputType)
	if normalized == "text" || normalized == "json" {
		return
	}

	if strings.HasSuffix(normalized, ".json") || strings.HasSuffix(normalized, ".jsonl") {
		structs.GlobalConfig.OutputFile = outputType
		structs.GlobalConfig.OutputType = "json"
	}
}

func validateEnumString(value *string, defaultValue, name string, allowed ...string) {
	normalized := strings.ToLower(strings.TrimSpace(*value))
	if normalized == "" {
		normalized = defaultValue
	}
	for _, item := range allowed {
		if normalized == item {
			*value = normalized
			return
		}
	}
	gologger.Fatal().Msgf("%s 仅支持: %s，当前值: %s", name, strings.Join(allowed, ","), *value)
}

func validateSeverities() {
	value := strings.TrimSpace(structs.GlobalConfig.Severities)
	if value == "" {
		return
	}
	allowed := map[string]struct{}{
		"info": {}, "low": {}, "medium": {}, "high": {}, "critical": {}, "unknown": {},
	}
	var valid []string
	for _, item := range strings.Split(value, ",") {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		if _, ok := allowed[item]; !ok {
			gologger.Fatal().Msgf("漏洞等级(-s/--severity)仅支持 info,low,medium,high,critical,unknown，当前值: %s", item)
		}
		valid = append(valid, item)
	}
	structs.GlobalConfig.Severities = strings.Join(valid, ",")
}

func ensureAPIConfigFile() {
	if !(structs.GlobalConfig.Fofa || structs.GlobalConfig.Hunter || structs.GlobalConfig.Quake || (structs.GlobalConfig.Subdomain && !structs.GlobalConfig.NoSubFinder)) {
		return
	}

	if fileExists(structs.GlobalConfig.APIConfigFilePath) || fileExists("config/api-config.yaml") {
		return
	}

	gologger.Info().Msgf("未检测到API配置文件: %v", structs.GlobalConfig.APIConfigFilePath)
	p, _ := splitPathAndFileName(structs.GlobalConfig.APIConfigFilePath)
	if !fileExists(p) {
		if err := os.MkdirAll(p, os.ModePerm); err != nil {
			gologger.Fatal().Msgf("创建文件夹失败: %v", err.Error())
		}
	}

	// 0600: API 配置含 Fofa/Hunter key, 在多用户机器上 0666 会被别的账户读走
	if err := os.WriteFile(structs.GlobalConfig.APIConfigFilePath, []byte(EmbedAPIConfigData), 0600); err != nil {
		gologger.Fatal().Msgf("写出默认API配置文件失败: %v", err.Error())
	}
	gologger.Info().Msgf("已自动生成默认API配置文件: %v", structs.GlobalConfig.APIConfigFilePath)
}

func configureHostDiscovery() {
	if !structs.GlobalConfig.SkipHostDiscovery && !structs.GlobalConfig.TCPPing && structs.GlobalConfig.NoICMPPing {
		gologger.Warning().Msg("未选择TCP或ICMP Ping，跳过存活探测")
		structs.GlobalConfig.SkipHostDiscovery = true
	}
}

func testHTTPProxy() {
	if !structs.GlobalConfig.HTTPProxyTest || structs.GlobalConfig.HTTPProxy == "" {
		return
	}

	proxyURL, parseErr := url.Parse(structs.GlobalConfig.HTTPProxy)
	if parseErr != nil {
		gologger.Fatal().Msgf("代理格式不正确: %v", structs.GlobalConfig.HTTPProxy)
	}

	transport := retryablehttp.DefaultHostSprayingTransport()
	transport.Proxy = http.ProxyURL(proxyURL)

	gologger.Info().Msgf("测试代理中: %s", structs.GlobalConfig.HTTPProxy)
	req, err := retryablehttp.NewRequest("GET", structs.GlobalConfig.HTTPProxyTestURL, nil)
	if err != nil {
		gologger.Fatal().Msg("代理测试失败！")
	}

	client := retryablehttp.NewClient(retryablehttp.DefaultOptionsSpraying)
	client.HTTPClient.Transport = transport

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		gologger.Fatal().Msg("代理测试失败！")
	}
	gologger.Info().Msgf("代理有效！测试URL返回码: %v", resp.StatusCode)
}

func loadTargets() []string {
	var tmpTargets []string
	if utils.IsFileNameValid(TargetString) {
		fileBytes, err := os.ReadFile(TargetString)
		if err == nil && len(fileBytes) > 0 {
			content := strings.ReplaceAll(string(fileBytes), "\r\n", "\n")
			tmpTargets = strings.Split(content, "\n")
		}
	} else {
		for _, each := range strings.Split(TargetString, ",") {
			if each != "" {
				tmpTargets = append(tmpTargets, each)
			}
		}
	}

	return utils.RemoveDuplicateElement(tmpTargets)
}

func applyLowPerceptionMode() {
	if !structs.GlobalConfig.LowPerceptionMode {
		return
	}

	if structs.GlobalConfig.Fofa && structs.GlobalConfig.Hunter {
		gologger.Fatal().Msg("暂不支持在低感知模式下同时使用-fofa与-hunter参数，请使用-hunter参数")
	}
	if structs.GlobalConfig.Fofa {
		gologger.Fatal().Msg("暂不支持基于Fofa的低感知模式，请使用-hunter参数。")
	}
	if !structs.GlobalConfig.Fofa && !structs.GlobalConfig.Hunter {
		structs.GlobalConfig.Hunter = true
	}
	structs.GlobalConfig.NoDirSearch = true
}

func populateTargets(tmpTargets []string) {
	structs.GlobalResultMap = make(map[string][]string)

	for _, tg := range tmpTargets {
		if tg == "" {
			continue
		}

		if acceptsSearchEngineTarget(tg) || acceptsStandardTarget(tg) {
			structs.GlobalConfig.Targets = append(structs.GlobalConfig.Targets, tg)
		}
	}

	if len(structs.GlobalConfig.Targets) == 0 && len(structs.GlobalResultMap) == 0 {
		gologger.Fatal().Msgf("无目标输入")
	}
}

func acceptsSearchEngineTarget(target string) bool {
	if structs.GlobalConfig.Hunter || structs.GlobalConfig.Fofa {
		if !strings.Contains(target, "=") {
			gologger.Error().Msgf("不支持的格式: %s", target)
			return false
		}
		return true
	}

	if structs.GlobalConfig.Quake {
		if !strings.Contains(target, ":") {
			gologger.Error().Msgf("不支持的格式: %s", target)
			return false
		}
		return true
	}

	return false
}

func acceptsStandardTarget(target string) bool {
	if structs.GlobalConfig.Fofa || structs.GlobalConfig.Hunter || structs.GlobalConfig.Quake {
		return false
	}

	if utils.GetInputType(target) != structs.TypeUnSupport {
		return true
	}

	if strings.HasPrefix(target, "[") {
		return parseHistoricalFinger(target)
	}

	if strings.HasPrefix(target, "{") {
		return parseJSONOutput(target)
	}

	if strings.HasSuffix(target, " open") {
		ipPort := strings.ReplaceAll(target, " open", "")
		if utils.IsIPPort(ipPort) {
			structs.GlobalConfig.Targets = append(structs.GlobalConfig.Targets, ipPort)
		}
		return false
	}

	return false
}

func parseHistoricalFinger(target string) bool {
	if !strings.HasPrefix(target, "[Finger") {
		return false
	}

	t := strings.Split(target, " ")
	uri := t[1]
	tf := ""
	if strings.HasPrefix(uri, "http") {
		tf = t[3]
	} else {
		tf = t[2]
	}

	if len(tf) <= 2 {
		return false
	}

	tf = tf[1 : len(tf)-1]
	structs.GlobalResultMap[uri] = strings.Split(tf, ",")
	return false
}

func parseJSONOutput(target string) bool {
	var in ddout.OutputMessage
	if err := json.Unmarshal([]byte(target), &in); err != nil {
		return false
	}
	if in.Type == "Finger" {
		structs.GlobalResultMap[in.URI] = in.Finger
	}
	return false
}

func initLinuxScanThreads() {
	if !IsLinux() {
		return
	}
	if structs.GlobalConfig.TCPPortScanThreads != 1000 {
		return
	}

	structs.GlobalConfig.TCPPortScanThreads = 4000
	if fdlimit := GetFdLimit(); structs.GlobalConfig.TCPPortScanThreads > fdlimit {
		gologger.Warning().Msgf("System fd limit: %d , Please exec 'ulimit -n 65535'", fdlimit)
		gologger.Warning().Msgf("Now set threads to %d", fdlimit-100)
		structs.GlobalConfig.TCPPortScanThreads = fdlimit - 100
	}
}

func initOutputAndPorts() {
	ddout.OutputType = structs.GlobalConfig.OutputType
	ddout.OutputFileName = structs.GlobalConfig.OutputFile

	if PortString != "" {
		structs.GlobalConfig.Ports = PortString
		return
	}
	if PortFileString != "" {
		structs.GlobalConfig.Ports = loadPortsFromFile(PortFileString)
		return
	}
	structs.GlobalConfig.Ports = PortTOP1000
}

// loadPortsFromFile 从文件读取端口列表 (Issue #11)
// 兼容逗号/分号/空格/换行分隔，支持区间写法 (如 8000-8010)
func loadPortsFromFile(filePath string) string {
	data, err := os.ReadFile(filePath)
	if err != nil {
		gologger.Fatal().Msgf("端口文件读取失败: %s (%v)", filePath, err)
	}

	normalized := strings.NewReplacer(
		"\r", ",", "\n", ",", "\t", ",", ";", ",", " ", ",",
	).Replace(string(data))

	var valid []string
	for _, token := range strings.Split(normalized, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if !isValidPortToken(token) {
			gologger.Warning().Msgf("端口文件忽略无效项: %s", token)
			continue
		}
		valid = append(valid, token)
	}
	if len(valid) == 0 {
		gologger.Fatal().Msgf("端口文件 %s 中没有有效端口，格式示例: 21,22,23,3306,6379", filePath)
	}

	ports := strings.Join(valid, ",")
	gologger.Info().Msgf("已从文件加载端口: %s (共 %d 个)", filePath, len(ParsePort(ports)))
	return ports
}

func isValidPortToken(token string) bool {
	parts := strings.Split(token, "-")
	if len(parts) > 2 {
		return false
	}
	for _, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	return true
}

func initHybridMaps() {
	bodyMap, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		gologger.Fatal().Msg("Web响应体缓存数据库初始化失败。")
	}
	structs.GlobalHttpBodyHMap = bodyMap

	headerMap, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		gologger.Fatal().Msg("Web响应头缓存数据库初始化失败。")
	}
	structs.GlobalHttpHeaderHMap = headerMap

	bannerMap, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		gologger.Fatal().Msg("Banner缓存数据库初始化失败。")
	}
	structs.GlobalBannerHMap = bannerMap
}

func initRuntimeState() {
	structs.GlobalIPPortMap = make(map[string]string)
	structs.GlobalIPPortProductMap = make(map[string]string)
	structs.GlobalIPDomainMap = make(map[string][]string)
	structs.GlobalURLMap = make(map[string]structs.URLEntity)
	structs.GlobalActiveFingerMap = make(map[string][]string)
}

func loadFingerDatabases() {
	parseFingerDB()
	if len(structs.FingerprintDB) == 0 {
		gologger.Fatal().Msg("请检查指纹数据库是否正常，是否正确放置config文件夹。")
	}
	gologger.Info().Msgf("YAML指纹数据: %d 条\n", len(structs.FingerprintDB))

	ReadWorkFlowDB()
	if len(structs.WorkFlowDB) == 0 {
		gologger.Fatal().Msg("请检查工作流数据库是否正常。")
	}
	gologger.Info().Msgf("漏洞检测支持指纹: %d 条", len(structs.WorkFlowDB))

	ReadDirDB()
	if len(structs.DirDB) == 0 {
		gologger.Fatal().Msg("请检查主动指纹探测数据库是否正常。")
	}

	InitGlobalBlackFinger()
}

func preparePlatformDefaults() {
	if runtime.GOOS == "linux" {
		initLinuxScanThreads()
	}
}
