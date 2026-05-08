package common

import (
	"dddd/ddout"
	"dddd/structs"
	"dddd/utils"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/retryablehttp-go"
)

func validatePrepareConfig() {
	if structs.GlobalConfig.ReportName != "" {
		suffix := path.Ext(structs.GlobalConfig.ReportName)
		if suffix != ".html" && suffix != ".htm" {
			gologger.Fatal().Msgf("输出参数(-o)必须为html拓展名或htm拓展名")
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

	engine := strings.ToLower(strings.TrimSpace(structs.GlobalConfig.SubdomainEngine))
	if engine == "" {
		structs.GlobalConfig.SubdomainEngine = "dnsx"
		return
	}
	if engine != "dnsx" && engine != "ksubdomain" && engine != "auto" {
		gologger.Fatal().Msg("子域名爆破引擎仅支持 dnsx、ksubdomain、auto")
	}
	structs.GlobalConfig.SubdomainEngine = engine

	wildcardMode := strings.ToLower(strings.TrimSpace(structs.GlobalConfig.KSubdomainWildcard))
	if wildcardMode == "" {
		structs.GlobalConfig.KSubdomainWildcard = "basic"
		return
	}
	if wildcardMode != "none" && wildcardMode != "basic" && wildcardMode != "advanced" {
		gologger.Fatal().Msg("ksubdomain 泛解析过滤模式仅支持 none、basic、advanced")
	}
	structs.GlobalConfig.KSubdomainWildcard = wildcardMode
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

	if PortString == "" {
		structs.GlobalConfig.Ports = PortTOP1000
		return
	}
	structs.GlobalConfig.Ports = PortString
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
