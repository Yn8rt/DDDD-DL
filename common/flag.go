package common

import (
	"dddd/common/progress"
	"dddd/lib/ddfinger"
	"dddd/structs"
	"embed"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"gopkg.in/yaml.v3"
)

// applyMemoryLimitIfConfigured 根据环境变量设置 Go 运行时内存软限制
// 之前的实现直接在 init() 硬编码 2GB，在小内存/大内存机器上都不合适
// 现在改为:
//   - 默认不设置（由 Go 运行时按 GOGC 策略自行决定）
//   - 可通过环境变量 DDDD_MEM_LIMIT_MB 覆盖 (单位 MB)
//   - 额外监控阈值 = 软限制 * 0.75
func applyMemoryLimitIfConfigured() {
	limitMBStr := os.Getenv("DDDD_MEM_LIMIT_MB")
	if limitMBStr == "" {
		return
	}
	limitMB, err := strconv.Atoi(limitMBStr)
	if err != nil || limitMB <= 0 {
		return
	}
	softLimit := int64(limitMB) * 1024 * 1024
	debug.SetMemoryLimit(softLimit)

	// 阈值改为软限制的 75% (原来硬编码 1.5GB 在 2GB 限制下是 75%)
	watermark := int64(float64(softLimit) * 0.75)
	go func() {
		for {
			time.Sleep(30 * time.Second)
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			if int64(m.HeapAlloc) > watermark {
				runtime.GC()
				debug.FreeOSMemory()
			}
		}
	}()
}

var version = "1.0.0"

func showBanner() {
	banner := fmt.Sprintf(`
     _       _       _       _   
  __| |   __| |   __| |   __| |  
 / _`+"`"+` |  / _ `+"`"+`|  / _`+"`"+` |  / _`+"`"+` |  
 \__,_|  \__,_|  \__,_|  \__,_|  
_|"""""|_|"""""|_|"""""|_|"""""| 
"`+"`"+`-0-0-'"`+"`"+`-0-0-'"`+"`"+`-0-0-`+"`"+`"`+"`"+`-0-0-'
dddd-dl.version: %s  by 迷人安全
(重构并通过DLDL赋能增强版)
`, version)
	fmt.Println(banner)
}

var TargetString string
var PortString string

//go:embed config/dir.yaml
var EmbedDirDBData string

//go:embed config/finger.yaml
var EmbedFingerData string

//go:embed config/api-config.yaml
var EmbedAPIConfigData string

//go:embed config/blackfinger.yaml
var EmbedBlackFingerData string

//go:embed config/pocs/*
var EmbedNucleiPocs embed.FS

func fileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func splitPathAndFileName(path string) (string, string) {
	p := strings.ReplaceAll(path, "\\", "/")
	if !strings.Contains(path, "/") {
		return "", p
	}
	t := strings.Split(p, "/")
	return strings.Join(t[:len(t)-1], "/"), t[len(t)-1]
}

func ReadDirDB() {
	// 先读取默认的，再读取文件内的进行补充
	fps := make(map[string]interface{})
	err := yaml.Unmarshal([]byte(EmbedDirDBData), &fps)
	if err != nil {
		return
	}

	structs.DirDB = make(map[string][]string)
	for productName, pathsInterfaces := range fps {
		for _, pathValue := range yamlStringSlice(pathsInterfaces) {
			addDirProductPath(pathValue, productName)
		}
	}

	var data []byte
	if !fileExists(structs.GlobalConfig.DirSearchYaml) {
		return
	}
	data, err = os.ReadFile(structs.GlobalConfig.DirSearchYaml)
	if err != nil {
		return
	}

	fps = make(map[string]interface{})
	err = yaml.Unmarshal(data, &fps)
	if err != nil {
		return
	}
	for productName, pathsInterfaces := range fps {
		for _, pathValue := range yamlStringSlice(pathsInterfaces) {
			addDirProductPath(pathValue, productName)
		}
	}

}

func IsLinux() bool {
	os := runtime.GOOS
	if os == "linux" {
		return true
	}
	return false
}

//go:embed config/workflow.yaml
var EmbedWorkFlowData string

func ReadWorkFlowDB() {
	structs.WorkFlowDB = make(map[string]structs.WorkFlowEntity)
	fps := make(map[string]interface{})
	err := yaml.Unmarshal([]byte(EmbedWorkFlowData), &fps)
	if err == nil {
		for productName, rulesInterface := range fps {
			structs.WorkFlowDB[productName] = buildWorkflowEntity(yamlStringMap(rulesInterface))
		}
	}

	workflowPath := structs.GlobalConfig.WorkflowYamlPath

	var data []byte
	if !fileExists(workflowPath) {
		return
	}
	data, err = os.ReadFile(workflowPath)
	if err != nil {
		return
	}
	fps = make(map[string]interface{})
	err = yaml.Unmarshal(data, &fps)
	if err != nil {
		return
	}

	for productName, rulesInterface := range fps {
		we := structs.WorkFlowDB[productName]
		mergeWorkflowEntity(&we, yamlStringMap(rulesInterface))
		structs.WorkFlowDB[productName] = we
	}
}

func ToInt(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return i
}

func GetFdLimit() int {
	cmd := exec.Command("sh", "-c", "ulimit -n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		println(err.Error())
		return -1
	}
	s := strings.TrimSpace(string(out))
	return ToInt(s)
}

func prepare() {
	validatePrepareConfig()
	structs.GlobalEmbedPocs = EmbedNucleiPocs
	ensureAPIConfigFile()
	configureHostDiscovery()
	testHTTPProxy()
	applyLowPerceptionMode()
	populateTargets(loadTargets())
	preparePlatformDefaults()
	initOutputAndPorts()
	initHybridMaps()
	initRuntimeState()
	loadFingerDatabases()
}

// InitGlobalBlackFinger 初始化全局指纹黑名单
func InitGlobalBlackFinger() {
	structs.GlobalBlackFingerMap = make(map[string]bool)

	type BlackFingerConfig struct {
		Blacklist []string `yaml:"blacklist"`
	}

	var config BlackFingerConfig
	if err := yaml.Unmarshal([]byte(EmbedBlackFingerData), &config); err == nil && len(config.Blacklist) > 0 {
		for _, finger := range config.Blacklist {
			finger = strings.TrimSpace(finger)
			if finger != "" {
				structs.GlobalBlackFingerMap[strings.ToLower(finger)] = true
			}
		}
		gologger.Info().Msgf("[黑名单] 已加载内嵌指纹黑名单 (%d 个)", len(structs.GlobalBlackFingerMap))
		return
	}

	defaultBlacklist := []string{
		"jquery", "jquery-ui", "bootstrap", "ubuntu-system",
		"jsp", "php", "javascript", "asp", "aspx", "java", "python",
		"django", "flask", "node.js", "asp.net",
		"nginx", "iis", "apache-web-server", "apache-http-server-centos", "struts2",
		"windows", "mysql",
		"openssl", "google-webmaster-platform",
		"springboot", "tomcat", "jetty", "react", "vue.js", "angular",
	}
	for _, finger := range defaultBlacklist {
		structs.GlobalBlackFingerMap[strings.ToLower(finger)] = true
	}
	gologger.Info().Msgf("[黑名单] 已加载回退指纹黑名单 (%d 个)", len(structs.GlobalBlackFingerMap))
}

func parseFingerDB() {
	validateEmbeddedFingerData()

	fps := make(map[string]interface{})
	err := yaml.Unmarshal([]byte(EmbedFingerData), &fps)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	m := make(map[string][]string)
	seen := make(map[string]map[string]struct{})
	mergeFingerRules(m, seen, fps)

	fingerPath := structs.GlobalConfig.FingerConfigFilePath

	if fileExists(fingerPath) {
		data, err := os.ReadFile(fingerPath)
		fps = make(map[string]interface{})
		err = yaml.Unmarshal(data, &fps)
		if err == nil {
			mergeFingerRules(m, seen, fps)
		}
	}

	for productName, ruleLs := range m {
		for _, ruleL := range ruleLs {
			structs.FingerprintDB = append(structs.FingerprintDB, structs.FingerPEntity{ProductName: productName, Rule: ddfinger.ParseRule(ruleL), AllString: ruleL})
		}
	}

	if len(structs.FingerprintDB) <= 10 {
		gologger.Warning().Msgf("[指纹库] 当前仅加载到 %d 条指纹，内嵌 finger.yaml 可能异常，请检查 common/config/finger.yaml", len(structs.FingerprintDB))
	}
}

func addDirProductPath(pathValue, productName string) {
	existing := structs.DirDB[pathValue]
	for _, item := range existing {
		if item == productName {
			return
		}
	}
	structs.DirDB[pathValue] = append(existing, productName)
}

func buildWorkflowEntity(ruleInterface map[string]interface{}) structs.WorkFlowEntity {
	var workflowEntity structs.WorkFlowEntity
	mergeWorkflowEntity(&workflowEntity, ruleInterface)
	return workflowEntity
}

func mergeWorkflowEntity(workflowEntity *structs.WorkFlowEntity, ruleInterface map[string]interface{}) {
	for _, value := range yamlStringSlice(ruleInterface["type"]) {
		switch strings.ToLower(value) {
		case "root":
			workflowEntity.RootType = true
		case "dir":
			workflowEntity.DirType = true
		case "base":
			workflowEntity.BaseType = true
		}
	}

	existingPocs := make(map[string]struct{}, len(workflowEntity.PocsName))
	for _, pocName := range workflowEntity.PocsName {
		existingPocs[pocName] = struct{}{}
	}
	for _, pocName := range yamlStringSlice(ruleInterface["pocs"]) {
		if _, exists := existingPocs[pocName]; exists {
			continue
		}
		workflowEntity.PocsName = append(workflowEntity.PocsName, pocName)
		existingPocs[pocName] = struct{}{}
	}
}

func mergeFingerRules(target map[string][]string, seen map[string]map[string]struct{}, fps map[string]interface{}) {
	for productName, rulesInterface := range fps {
		productSeen, ok := seen[productName]
		if !ok {
			productSeen = make(map[string]struct{})
			seen[productName] = productSeen
		}
		for _, ruleL := range yamlStringSlice(rulesInterface) {
			if _, exists := productSeen[ruleL]; exists {
				continue
			}
			productSeen[ruleL] = struct{}{}
			target[productName] = append(target[productName], ruleL)
		}
	}
}

func yamlStringSlice(value interface{}) []string {
	switch typed := value.(type) {
	case nil:
		return nil
	case string:
		if typed == "" {
			return nil
		}
		return []string{typed}
	case []string:
		return typed
	case []interface{}:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			if str, ok := item.(string); ok && str != "" {
				result = append(result, str)
			}
		}
		return result
	default:
		return nil
	}
}

func yamlStringMap(value interface{}) map[string]interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		return typed
	case map[interface{}]interface{}:
		result := make(map[string]interface{}, len(typed))
		for key, item := range typed {
			keyString, ok := key.(string)
			if ok {
				result[keyString] = item
			}
		}
		return result
	default:
		return map[string]interface{}{}
	}
}

func validateEmbeddedFingerData() {
	trimmed := strings.TrimSpace(EmbedFingerData)
	if strings.HasPrefix(trimmed, "{\"error\"") {
		gologger.Warning().Msg("[指纹库] 内嵌 finger.yaml 看起来是错误响应，不是有效指纹库，请检查 common/config/finger.yaml 的生成过程")
	}
}

func Flag() {
	showBanner()
	applyMemoryLimitIfConfigured()

	// 让 gologger 与进度条协同: 写日志前先清 bar 行, 避免残影
	gologger.DefaultLogger.SetWriter(progress.NewBarAwareGoLoggerWriter())

	flagSet := goflags.NewFlagSet()
	flagSet.CaseSensitive = true
	flagSet.SetDescription(`dddd是一款使用简单的批量信息收集,供应链漏洞探测工具。旨在优化红队工作流，减少伤肝、枯燥、乏味的机械性操作。`)

	// 目标设置
	flagSet.CreateGroup("input", "扫描目标",
		flagSet.StringVarP(&TargetString, "target", "t", "", "被扫描的目标。 192.168.0.1 192.168.0.0/16 192.168.0.1:80 baidu.com:80 file.txt(一行一个) result.txt(fscan/dddd)"),
	)

	flagSet.CreateGroup("portscan", "端口扫描",
		flagSet.StringVarP(&PortString, "port", "p", "", "端口设置。 默认扫描Top1000"),
		flagSet.StringVarP(&structs.GlobalConfig.NoPortString, "no-port", "np", "", "禁止扫描的端口 | 如 -np 1-65535 可排除全部端口"),
		flagSet.BoolVarP(&structs.GlobalConfig.NoPortScan, "no-port-scan", "nps", false, "关闭IP端口扫描 | 不影响直接输入的IP:Port或URL"),
		flagSet.StringVarP(&structs.GlobalConfig.PortScanType, "scan-type", "st", "tcp", "端口扫描方式 | \"-st tcp\"设置TCP扫描 | \"-st syn\"设置SYN扫描"),
		flagSet.IntVarP(&structs.GlobalConfig.TCPPortScanThreads, "tcp-scan-threads", "tst", 1000, "TCP扫描线程 | Windows/Mac默认1000线程 Linux默认4000"),
		flagSet.IntVarP(&structs.GlobalConfig.SYNPortScanThreads, "syn-scan-threads", "sst", 10000, "SYN扫描线程"),
		flagSet.StringVarP(&structs.GlobalConfig.MasscanPath, "masscan-path", "mp", "masscan", "指定masscan程序路径 | SYN扫描依赖"),
		flagSet.StringVarP(&structs.GlobalConfig.MasscanInterface, "masscan-interface", "mi", "", "指定masscan使用的网络接口 | 解决混杂模式失败问题"),
		flagSet.IntVarP(&structs.GlobalConfig.PortsThreshold, "ports-max-count", "pmc", 300, "IP端口数量阈值 | 当一个IP的端口数量超过此值，此IP将会被抛弃"),
		flagSet.IntVarP(&structs.GlobalConfig.TCPPortScanTimeout, "port-scan-timeout", "pst", 6, "TCP端口扫描超时(秒)"),
	)

	flagSet.CreateGroup("alive", "主机发现",
		flagSet.BoolVar(&structs.GlobalConfig.SkipHostDiscovery, "Pn", false, "禁用主机发现功能(icmp,tcp)"),
		flagSet.BoolVarP(&structs.GlobalConfig.NoICMPPing, "no-icmp-ping", "nip", false, "当启用主机发现功能时，禁用ICMP主机发现功能"),
		flagSet.BoolVarP(&structs.GlobalConfig.TCPPing, "tcp-ping", "tp", false, "当启用主机发现功能时，启用TCP主机发现功能"),
	)

	flagSet.CreateGroup("nmap", "协议识别",
		flagSet.IntVarP(&structs.GlobalConfig.GetBannerThreads, "nmap-threads", "tc", 500, "Nmap协议识别线程"),
		flagSet.IntVarP(&structs.GlobalConfig.GetBannerTimeout, "nmap-timeout", "nto", 5, "Nmap协议识别超时时间(秒)"),
	)

	flagSet.CreateGroup("subdomain", "探索子域名",
		flagSet.BoolVarP(&structs.GlobalConfig.Subdomain, "subdomain", "sd", false, "开启子域名枚举，默认关闭"),
		flagSet.BoolVarP(&structs.GlobalConfig.NoSubdomainBruteForce, "no-subdomain-brute", "nsb", false, "关闭子域名爆破"),
		flagSet.BoolVarP(&structs.GlobalConfig.NoSubFinder, "no-subfinder", "ns", false, "关闭被动子域名枚举"),
		flagSet.StringVarP(&structs.GlobalConfig.SubdomainEngine, "subdomain-engine", "sde", "dnsx", "子域名爆破外部引擎 | dnsx, ksubdomain, auto"),
		flagSet.IntVarP(&structs.GlobalConfig.SubdomainBruteForceThreads, "subdomain-brute-threads", "sbt", 150, "子域名爆破线程数量"),
		flagSet.StringVarP(&structs.GlobalConfig.DNSXPath, "dnsx-path", "dxp", "dnsx", "dnsx程序路径，默认优先使用当前目录 dnsx/dnsx.exe"),
		flagSet.StringVarP(&structs.GlobalConfig.KSubdomainPath, "ksubdomain-path", "ksp", "ksubdomain", "ksubdomain程序路径，默认优先使用当前目录 ksubdomain/ksubdomain.exe"),
		flagSet.StringVarP(&structs.GlobalConfig.KSubdomainBand, "ksubdomain-band", "ksb", "3m", "ksubdomain带宽限制，如 3m/10m/100m"),
		flagSet.StringVarP(&structs.GlobalConfig.KSubdomainInterface, "ksubdomain-interface", "ksi", "", "ksubdomain指定网卡名称，留空自动选择"),
		flagSet.StringVarP(&structs.GlobalConfig.KSubdomainWildcard, "ksubdomain-wildcard", "ksw", "basic", "ksubdomain泛解析过滤模式 | none, basic, advanced"),
		flagSet.BoolVarP(&structs.GlobalConfig.AllowLocalAreaDomain, "local-domain", "ld", false, "允许域名解析到局域网"),
		flagSet.BoolVarP(&structs.GlobalConfig.AllowCDNAssets, "allow-cdn", "ac", false, "允许扫描带CDN的资产 | 默认略过"),
		flagSet.BoolVarP(&structs.GlobalConfig.NoCDNCheck, "no-cdn-check", "ncc", false, "关闭域名CDN/WAF识别 | 域名仅解析为IP后进入后续流程"),
		flagSet.BoolVarP(&structs.GlobalConfig.NoHostBind, "no-host-bind", "nhb", false, "禁用域名绑定资产探测"),
	)

	flagSet.CreateGroup("web", "Web探针配置",
		flagSet.IntVarP(&structs.GlobalConfig.WebThreads, "web-threads", "wt", 200, "Web探针线程,根据网络环境调整"),
		flagSet.IntVarP(&structs.GlobalConfig.WebTimeout, "web-timeout", "wto", 10, "Web探针超时时间,根据网络环境调整"),
		flagSet.BoolVarP(&structs.GlobalConfig.NoDirSearch, "no-dir", "nd", false, "关闭主动Web指纹探测"),
		flagSet.BoolVarP(&structs.GlobalConfig.EnableJSScan, "js-scan", "js", false, "启用JS目录爆破识别功能 | 爬取JS文件提取一级目录进行指纹识别"),
	)

	flagSet.CreateGroup("api-unauth", "Katana未授权接口探测",
		flagSet.BoolVarP(&structs.GlobalConfig.EnableAPIUnauthScan, "api-unauth", "au", false, "启用基于Katana的未授权接口探测"),
		flagSet.BoolVarP(&structs.GlobalConfig.APIUnauthOnly, "api-unauth-only", "auo", false, "仅进行未授权接口探测阶段，跳过后续指纹/漏洞流程"),
		flagSet.StringVarP(&structs.GlobalConfig.KatanaMode, "katana-mode", "km", "hl", "Katana模式: hl(快速) / hh(详细慢速)"),
		flagSet.StringVarP(&structs.GlobalConfig.KatanaPath, "katana-path", "kp", "", "指定katana程序路径，默认自动选择 katana.exe/katana"),
		flagSet.IntVarP(&structs.GlobalConfig.KatanaDepth, "katana-depth", "kd", 3, "Katana爬取深度"),
		flagSet.StringVarP(&structs.GlobalConfig.KatanaCrawlDuration, "katana-crawl-duration", "kct", "15s", "Katana爬取时长，如 10s/1m"),
		flagSet.IntVarP(&structs.GlobalConfig.KatanaTimeout, "katana-timeout", "kto", 10, "Katana请求超时(秒)"),
		flagSet.IntVarP(&structs.GlobalConfig.APIUnauthMaxTargets, "api-unauth-max", "aum", 500, "未授权接口最大探测目标数"),
	)

	flagSet.CreateGroup("proxy", "HTTP代理配置",
		flagSet.StringVarP(&structs.GlobalConfig.HTTPProxy, "proxy", "", "", "HTTP代理"),
		flagSet.BoolVarP(&structs.GlobalConfig.HTTPProxyTest, "proxy-test", "pt", true, "启动前测试HTTP代理"),
		flagSet.StringVarP(&structs.GlobalConfig.HTTPProxyTestURL, "proxy-test-url", "ptu", "https://www.baidu.com", "测试HTTP代理的url，需要url返回200"),
	)

	flagSet.CreateGroup("uncover", "网络空间搜索引擎",
		flagSet.BoolVar(&structs.GlobalConfig.Hunter, "hunter", false, "从hunter中获取资产,开启此选项后-t参数变更为需要在hunter中搜索的关键词"),
		flagSet.IntVarP(&structs.GlobalConfig.HunterPageSize, "hunter-page-size", "hps", 100, "Hunter查询每页资产条数"),
		flagSet.IntVarP(&structs.GlobalConfig.HunterMaxPageCount, "hunter-max-page-count", "hmpc", 10, "Hunter 最大查询页数"),
		flagSet.BoolVarP(&structs.GlobalConfig.LowPerceptionMode, "low-perception-mode", "lpm", false, "Hunter低感知模式 | 从Hunter直接取响应判断指纹，直接进入漏洞扫描阶段"),
		flagSet.BoolVar(&structs.GlobalConfig.OnlyIPPort, "oip", false, "从网络空间搜索引擎中以IP:Port的形式拉取资产，而不是Domain(IP):Port"),
		flagSet.BoolVar(&structs.GlobalConfig.Fofa, "fofa", false, "从Fofa中获取资产,开启此选项后-t参数变更为需要在fofa中搜索的关键词"),
		flagSet.IntVarP(&structs.GlobalConfig.FofaMaxCount, "fofa-max-count", "fmc", 100, "Fofa 查询资产条数 Max:10000"),
		flagSet.BoolVar(&structs.GlobalConfig.Quake, "quake", false, "从Quake中获取资产,开启此选项后-t参数变更为需要在quake中搜索的关键词"),
		flagSet.IntVarP(&structs.GlobalConfig.QuakeSize, "quake-max-count", "qmc", 100, "Quake 查询资产条数"),
	)

	flagSet.CreateGroup("output", "输出",
		flagSet.StringVarP(&structs.GlobalConfig.OutputFile, "output", "o", "result.txt", "结果输出文件"),
		flagSet.StringVarP(&structs.GlobalConfig.OutputType, "output-type", "ot", "text", "结果输出格式 text,json"),
		flagSet.StringVarP(&structs.GlobalConfig.ReportName, "html-output", "ho", "", "html漏洞报告的名称"),
	)

	flagSet.CreateGroup("vuln-detect", "漏洞探测",
		flagSet.BoolVar(&structs.GlobalConfig.NoPoc, "npoc", false, "关闭漏洞探测,只进行信息收集"),
		flagSet.StringVarP(&structs.GlobalConfig.PocNameForSearch, "poc-name", "poc", "", "模糊匹配Poc名称"),
		flagSet.StringVarP(&structs.GlobalConfig.FingerNameForSearch, "finger", "f", "", "指定 workflow.yaml 中的指纹名称进行强制扫描（支持模糊匹配）"),
		flagSet.StringVarP(&structs.GlobalConfig.PocScanType, "poc-scan-type", "pts", "", "指定POC扫描类型覆盖 workflow.yaml | 可选: root, dir, base | 可组合如: root,dir | root=根URL, dir=目录层级, base=当前URL"),
		flagSet.IntVarP(&structs.GlobalConfig.GoPocThreads, "golang-poc-threads", "gpt", 50, "GoPoc运行线程"),
		flagSet.BoolVarP(&structs.GlobalConfig.NoGolangPoc, "no-golang-poc", "ngp", false, "关闭Golang Poc探测"),
		flagSet.BoolVarP(&structs.GlobalConfig.DisableGeneralPoc, "disable-general-poc", "dgp", false, "禁用无视指纹的漏洞映射"),
		flagSet.StringVarP(&structs.GlobalConfig.ExcludeTags, "exclude-tags", "et", "", "通过tags排除模版 | 多个tags请用,连接"),
		flagSet.StringVarP(&structs.GlobalConfig.Severities, "severity", "s", "", "只允许指定严重程度的模板运行 | 多参数用,连接 | 允许的值: "+strings.ReplaceAll(severity.GetSupportedSeverities().String(), " ", "")),
		flagSet.BoolVarP(&structs.GlobalConfig.NoServiceBruteForce, "no-brute", "nb", false, "禁用服务爆破 | 不包括Shiro Keys"),
	)

	flagSet.CreateGroup("interact-sh", "反连配置",
		flagSet.BoolVarP(&structs.GlobalConfig.NoInteractsh, "no-interactsh", "ni", false, "禁用Interactsh服务器，排除反连模版"),
		flagSet.StringVarP(&structs.GlobalConfig.InteractshURL, "interactsh-server", "iserver", "", "指定Interactsh服务器 | http://xxx.com | 默认使用Nuclei自带的服务"),
		flagSet.StringVarP(&structs.GlobalConfig.InteractshToken, "interactsh-token", "itoken", "", "Interactsh Token"),
	)

	flagSet.CreateGroup("config", "配置文件",
		flagSet.StringVarP(&structs.GlobalConfig.APIConfigFilePath, "api-config-file", "acf", "config/api-config.yaml", "API配置文件"),
		flagSet.StringVarP(&structs.GlobalConfig.NucleiTemplate, "nuclei-template", "nt", "", "指定额外的 Nuclei Poc 文件夹路径，留空仅使用内嵌模板"),
		flagSet.StringVarP(&structs.GlobalConfig.WorkflowYamlPath, "workflow-yaml", "wy", "", "指定外部 workflow.yaml 覆盖内嵌映射"),
		flagSet.StringVarP(&structs.GlobalConfig.FingerConfigFilePath, "finger-yaml", "fy", "", "指定外部 finger.yaml 覆盖内嵌指纹"),
		flagSet.StringVarP(&structs.GlobalConfig.DirSearchYaml, "dir-yaml", "dy", "", "指定外部主动指纹数据库覆盖内嵌配置"),
		flagSet.StringVarP(&structs.GlobalConfig.SubdomainWordListFile, "subdomain-word-list", "swl", "embedded", "指定外部子域名字典文件，默认使用内嵌字典"),
	)

	flagSet.CreateGroup("passwd", "爆破密码配置",
		flagSet.StringVarP(&structs.GlobalConfig.Password, "username-password", "up", "", "设置爆破凭证，设置后将禁用内置字典 | 凭证格式 'admin : password'"),
		flagSet.StringVarP(&structs.GlobalConfig.PasswordFile, "username-password-file", "upf", "", "设置爆破凭证文件(一行一个)，设置后将禁用内置字典 | 凭证格式 'admin : password'"),
	)

	flagSet.CreateGroup("audit", "审计日志 | 敏感环境必备",
		flagSet.BoolVar(&gologger.Audit, "a", false, "开启审计日志，记录程序运行日志，收发包详细信息，避免背黑锅。"),
		flagSet.StringVarP(&gologger.AuditLogFileName, "audit-log-filename", "alf", "audit.log", "审计日志文件名称"),
	)

	_ = flagSet.Parse()

	prepare()
	flagAudit()
}

// 记录启动信息
// 通过反射遍历 GlobalConfig 所有字段，自动包含新增字段
// 避免手写 50 行 AuditLogger + 漏记
func flagAudit() {
	gologger.AuditTimeLogger("dddd启动")
	gologger.AuditLogger("本次启动参数如下:")

	cfg := reflect.ValueOf(structs.GlobalConfig)
	typ := cfg.Type()
	for i := 0; i < cfg.NumField(); i++ {
		name := typ.Field(i).Name
		field := cfg.Field(i)
		switch field.Kind() {
		case reflect.Slice:
			// Targets 等 []string 用 "," 串联
			if field.Type().Elem().Kind() == reflect.String {
				gologger.AuditLogger("%s: %s", name, strings.Join(field.Interface().([]string), ","))
			} else {
				gologger.AuditLogger("%s: %v", name, field.Interface())
			}
		default:
			gologger.AuditLogger("%s: %v", name, field.Interface())
		}
	}

	// 审计日志本身的元信息不在 GlobalConfig 里
	gologger.AuditLogger("Audit: %v", gologger.Audit)
	gologger.AuditLogger("AuditLogFileName: %v", gologger.AuditLogFileName)
}

var PortTOP1000 = "21,22,23,25,53,69,80,81,88,89,110,135,161,445,139,137,143,389,443,512,513,514,548,873,1433,1521,2181,3306,3389,3690,4848,5000,5001,5432,5632,5900,5901,5902,6379,7000,7001,7002,8000,8001,8007,8008,8009,8069,8080,8081,8088,8089,8090,8091,9060,9090,9091,9200,9300,10000,11211,27017,27018,50000,1080,888,1158,2100,2424,2601,2604,3128,5984,7080,8010,8082,8083,8084,8085,8086,8087,8222,8443,8686,8888,9000,9001,9002,9003,9004,9005,9006,9007,9008,9009,9010,9043,9080,9081,9418,9999,50030,50060,50070,82,83,84,85,86,87,7003,7004,7005,7006,7007,7008,7009,7010,7070,7071,7072,7073,7074,7075,7076,7077,7078,7079,8002,8003,8004,8005,8006,8200,90,801,8011,8100,8012,8070,99,7777,8028,808,38888,8181,800,18080,8099,8899,8360,8300,8800,8180,3505,8053,1000,8989,28017,49166,3000,41516,880,8484,6677,8016,7200,9085,5555,8280,1980,8161,7890,8060,6080,8880,8020,889,8881,38501,1010,93,6666,100,6789,7060,8018,8022,3050,8787,2000,10001,8013,6888,8040,10021,2011,6006,4000,8055,4430,1723,6060,7788,8066,9898,6001,8801,10040,9998,803,6688,10080,8050,7011,40310,18090,802,10003,8014,2080,7288,8044,9992,8889,5644,8886,9500,58031,9020,8015,8887,8021,8700,91,9900,9191,3312,8186,8735,8380,1234,38080,9088,9988,2110,21245,3333,2046,9061,2375,9011,8061,8093,9876,8030,8282,60465,2222,98,1100,18081,70,8383,5155,92,8188,2517,8062,11324,2008,9231,999,28214,16080,8092,8987,8038,809,2010,8983,7700,3535,7921,9093,11080,6778,805,9083,8073,10002,114,2012,701,8810,8400,9099,8098,8808,20000,8065,8822,15000,9901,11158,1107,28099,12345,2006,9527,51106,688,25006,8045,8023,8029,9997,7048,8580,8585,2001,8035,10088,20022,4001,2013,20808,8095,106,3580,7742,8119,6868,32766,50075,7272,3380,3220,7801,5256,5255,10086,1300,5200,8096,6198,6889,3503,6088,9991,806,5050,8183,8688,1001,58080,1182,9025,8112,7776,7321,235,8077,8500,11347,7081,8877,8480,9182,58000,8026,11001,10089,5888,8196,8078,9995,2014,5656,8019,5003,8481,6002,9889,9015,8866,8182,8057,8399,10010,8308,511,12881,4016,8042,1039,28080,5678,7500,8051,18801,15018,15888,38443,8123,8144,94,9070,1800,9112,8990,3456,2051,9098,444,9131,97,7100,7711,7180,11000,8037,6988,122,8885,14007,8184,7012,8079,9888,9301,59999,49705,1979,8900,5080,5013,1550,8844,4850,206,5156,8813,3030,1790,8802,9012,5544,3721,8980,10009,8043,8390,7943,8381,8056,7111,1500,7088,5881,9437,5655,8102,6000,65486,4443,10025,8024,8333,8666,103,8,9666,8999,9111,8071,9092,522,11381,20806,8041,1085,8864,7900,1700,8036,8032,8033,8111,60022,955,3080,8788,7443,8192,6969,9909,5002,9990,188,8910,9022,10004,866,8582,4300,9101,6879,8891,4567,4440,10051,10068,50080,8341,30001,6890,8168,8955,16788,8190,18060,7041,42424,8848,15693,2521,19010,18103,6010,8898,9910,9190,9082,8260,8445,1680,8890,8649,30082,3013,30000,2480,7202,9704,5233,8991,11366,7888,8780,7129,6600,9443,47088,7791,18888,50045,15672,9089,2585,60,9494,31945,2060,8610,8860,58060,6118,2348,8097,38000,18880,13382,6611,8064,7101,5081,7380,7942,10016,8027,2093,403,9014,8133,6886,95,8058,9201,6443,5966,27000,7017,6680,8401,9036,8988,8806,6180,421,423,57880,7778,18881,812,15004,9110,8213,8868,1213,8193,8956,1108,778,65000,7020,1122,9031,17000,8039,8600,50090,1863,8191,65,6587,8136,9507,132,200,2070,308,5811,3465,8680,7999,7084,18082,3938,18001,9595,442,4433,7171,9084,7567,811,1128,6003,2125,6090,10007,7022,1949,6565,65001,1301,19244,10087,8025,5098,21080,1200,15801,1005,22343,7086,8601,6259,7102,10333,211,10082,18085,180,40000,7021,7702,66,38086,666,6603,1212,65493,96,9053,7031,23454,30088,6226,8660,6170,8972,9981,48080,9086,10118,40069,28780,20153,20021,20151,58898,10066,1818,9914,55351,8343,18000,6546,3880,8902,22222,19045,5561,7979,5203,8879,50240,49960,2007,1722,8913,8912,9504,8103,8567,1666,8720,8197,3012,8220,9039,5898,925,38517,8382,6842,8895,2808,447,3600,3606,9095,45177,19101,171,133,8189,7108,10154,47078,6800,8122,381,1443,15580,23352,3443,1180,268,2382,43651,10099,65533,7018,60010,60101,6699,2005,18002,2009,59777,591,1933,9013,8477,9696,9030,2015,7925,6510,18803,280,5601,2901,2301,5201,302,610,8031,5552,8809,6869,9212,17095,20001,8781,25024,5280,7909,17003,1088,7117,20052,1900,10038,30551,9980,9180,59009,28280,7028,61999,7915,8384,9918,9919,55858,7215,77,9845,20140,8288,7856,1982,1123,17777,8839,208,2886,877,6101,5100,804,983,5600,8402,5887,8322,770,13333,7330,3216,31188,47583,8710,22580,1042,2020,34440,20,7703,65055,8997,6543,6388,8283,7201,4040,61081,12001,3588,7123,2490,4389,1313,19080,9050,6920,299,20046,8892,9302,7899,30058,7094,6801,321,1356,12333,11362,11372,6602,7709,45149,3668,517,9912,9096,8130,7050,7713,40080,8104,13988,18264,8799,55070,23458,8176,9517,9541,9542,9512,8905,11660,1025,44445,44401,17173,436,560,733,968,602,3133,3398,16580,8488,8901,8512,10443,9113,9119,6606,22080,5560,7,5757,1600,8250,10024,10200,333,73,7547,8054,6372,223,3737,9800,9019,8067,45692,15400,15698,9038,37006,2086,1002,9188,8094,8201,8202,30030,2663,9105,10017,4503,1104,8893,40001,27779,3010,7083,5010,5501,309,1389,10070,10069,10056,3094,10057,10078,10050,10060,10098,4180,10777,270,6365,9801,1046,7140,1004,9198,8465,8548,108,30015,8153,1020,50100,8391,34899,7090,6100,8777,8298,8281,7023,3377,9100"
