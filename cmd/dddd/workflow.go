package main

import (
	"dddd/internal/common"
	"dddd/internal/common/backup"
	"dddd/internal/common/callnuclei"
	dddhttp "dddd/internal/common/http"
	"dddd/internal/common/progress"
	"dddd/internal/common/report"
	"dddd/internal/common/uncover"
	"dddd/internal/gopocs"
	"dddd/internal/structs"
	"dddd/internal/utils"
	"dddd/internal/utils/cdn"
	"dddd/lib/ddfinger"
	"fmt"
	"strings"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

type workflowState struct {
	domains    []string
	urls       []string
	domainPort []string
	ipPort     []string
	ips        []string
}

func workflow() {
	state := &workflowState{}

	defer func() {
		report.FinalizeHTMLReport()
		progress.PrintSummary()
		gologger.Info().Msg(aurora.BrightGreen("Done!").String())
	}()

	runStage("搜索引擎", func() { searchEngine() })
	classifyTargets(state)
	runStage("子域名/CDN", func() { expandDomains(state) })
	runStage("主机/端口扫描", func() { scanHosts(state) })
	runStage("协议识别", func() { identifyProtocols(state) })
	runStage("Web 探针", func() { probeHTTPAssets(state) })

	if !structs.GlobalConfig.NoHostBind {
		runStage("域名绑定探测", func() { common.HostBindCheck() })
	}

	aliveURLs := collectAliveURLs()
	if structs.GlobalConfig.EnableBackupScan {
		runStage("网站备份扫描", func() { backup.Run(aliveURLs) })
	}
	if runNamedPocSearch(aliveURLs) {
		return
	}

	runStage("主动指纹", func() { runDirBrute(aliveURLs) })
	runStage("被动指纹识别", func() { ddfinger.FingerprintIdentification() })

	if structs.GlobalConfig.NoPoc {
		gologger.Info().Msg("跳过漏洞探测")
		return
	}

	runStage("漏洞扫描", func() { runVulnerabilityScans() })
}

// runStage 包装阶段执行, 统一登记耗时
// 空输入/无数据的阶段也会登记一条 "XXs" 便于排查
func runStage(name string, fn func()) {
	gologger.Info().Msg(aurora.BrightBlue(fmt.Sprintf("[阶段开始] %s", name)).String())
	s := progress.StartStage(name)
	startAt := time.Now()
	defer func() {
		s.Done()
		gologger.Info().Msg(aurora.BrightGreen(fmt.Sprintf("[阶段完成] %s (%s)", name, progress.FormatDuration(time.Since(startAt)))).String())
	}()
	fn()
}

func classifyTargets(state *workflowState) {
	for _, input := range structs.GlobalConfig.Targets {
		switch utils.GetInputType(input) {
		case structs.TypeDomain:
			state.domains = append(state.domains, input)
		case structs.TypeDomainPort:
			state.domainPort = append(state.domainPort, input)
		case structs.TypeCIDR:
			for _, ip := range utils.CIDRToIP(input) {
				state.ips = append(state.ips, ip.String())
			}
		case structs.TypeIPRange:
			for _, ip := range utils.RangerToIP(input) {
				state.ips = append(state.ips, ip.String())
			}
		case structs.TypeIP:
			state.ips = append(state.ips, input)
		case structs.TypeIPPort:
			state.ipPort = append(state.ipPort, input)
		case structs.TypeURL:
			state.urls = append(state.urls, input)
		}
	}
}

func expandDomains(state *workflowState) {
	if structs.GlobalConfig.Subdomain && len(state.domains) > 0 {
		state.domains = append(state.domains, common.GetSubDomain(state.domains)...)
	}
	state.domains = utils.RemoveDuplicateElement(state.domains)

	var cdnDomains []string
	if len(state.domains) > 0 {
		cdnDomains, state.ips = resolveDomainIPs(state.domains, state.ips)
	}
	state.ips = utils.RemoveDuplicateElement(state.ips)

	if structs.GlobalConfig.AllowCDNAssets {
		for _, cd := range cdnDomains {
			state.urls = append(state.urls, "http://"+cd, "https://"+cd)
		}
	}
	state.urls = utils.RemoveDuplicateElement(state.urls)
}

func resolveDomainIPs(domains, currentIPs []string) ([]string, []string) {
	var cdnDomains []string
	var resolvedIPs []string
	if structs.GlobalConfig.NoCDNCheck {
		resolvedIPs = cdn.ResolveDomains(domains, structs.GlobalConfig.SubdomainBruteForceThreads)
	} else {
		cdnDomains, _, resolvedIPs = cdn.CheckCDNs(domains, structs.GlobalConfig.SubdomainBruteForceThreads)
	}

	for _, each := range resolvedIPs {
		if !structs.GlobalConfig.AllowLocalAreaDomain && utils.IsLocalIP(each) {
			continue
		}
		currentIPs = append(currentIPs, each)
	}
	return cdnDomains, currentIPs
}

func scanHosts(state *workflowState) {
	if len(state.ips) == 0 {
		return
	}

	if !structs.GlobalConfig.SkipHostDiscovery {
		state.ips = discoverAliveHosts(state.ips)
	}

	state.ipPort = append(state.ipPort, portScan(state.ips)...)
	state.ipPort = utils.RemoveDuplicateElement(state.ipPort)
}

func discoverAliveHosts(ips []string) []string {
	var icmpAlive []string
	if !structs.GlobalConfig.NoICMPPing {
		icmpAlive = common.CheckLive(ips, false)
	}

	var tcpAlive []string
	if structs.GlobalConfig.TCPPing {
		icmpAliveSet := make(map[string]struct{}, len(icmpAlive))
		for _, ip := range icmpAlive {
			icmpAliveSet[ip] = struct{}{}
		}

		var unchecked []string
		for _, ip := range ips {
			if _, ok := icmpAliveSet[ip]; !ok {
				unchecked = append(unchecked, ip)
			}
		}
		gologger.Info().Msg("TCP存活探测")
		common.PortScan = false
		for _, tIPPort := range common.PortScanTCP(unchecked, "80,443,3389,445,22", structs.GlobalConfig.NoPortString, structs.GlobalConfig.TCPPortScanTimeout) {
			t := strings.Split(tIPPort, ":")
			tcpAlive = append(tcpAlive, t[0])
		}
	}

	var alive []string
	alive = append(alive, icmpAlive...)
	alive = append(alive, tcpAlive...)
	if len(alive) == 0 {
		return utils.RemoveDuplicateElement(ips)
	}
	return utils.RemoveDuplicateElement(alive)
}

func portScan(ips []string) []string {
	if structs.GlobalConfig.NoPortScan {
		gologger.Info().Msg("已关闭IP端口扫描，跳过自动端口探测")
		return nil
	}

	if structs.GlobalConfig.PortScanType == "syn" && !common.CheckMasScan() {
		gologger.Error().Msg("降级TCP扫描")
		structs.GlobalConfig.PortScanType = "tcp"
	}

	var ipPorts []string
	if structs.GlobalConfig.PortScanType == "syn" {
		ipPorts = common.PortScanSYN(ips)
	} else {
		common.PortScan = true
		ipPorts = common.PortScanTCP(ips, structs.GlobalConfig.Ports, structs.GlobalConfig.NoPortString, structs.GlobalConfig.TCPPortScanTimeout)
	}

	return common.RemoveFirewall(ipPorts)
}

func identifyProtocols(state *workflowState) {
	inputs := append([]string{}, state.ipPort...)
	inputs = append(inputs, state.domainPort...)
	if len(inputs) == 0 {
		return
	}

	common.GetProtocol(inputs, structs.GlobalConfig.GetBannerThreads, structs.GlobalConfig.GetBannerTimeout)
}

func probeHTTPAssets(state *workflowState) {
	for hostPort, service := range structs.GlobalIPPortMap {
		if strings.Contains(service, "http") {
			state.urls = appendHTTPServiceURLs(state.urls, hostPort)
		}
	}
	state.urls = utils.RemoveDuplicateElement(state.urls)
	if len(state.urls) == 0 {
		return
	}

	// Web 探针进度:
	//   httpx 对超时/失败 URL 不触发 CallBack, 若只按 callback 计数
	//   大量失败场景下 bar 会停在 "X/Y (50%)" 即便已扫完.
	//   改走 OnItemDone 钩子(httpx 每处理完一个 URL 就触发), 保证 bar 到 100%
	bar := progress.New("Web探针", len(state.urls))
	defer bar.Finish()
	onProgress := func(current, total int) { bar.Set(current) }

	httpx.CallHTTPxWithProgress(
		state.urls,
		dddhttp.UrlCallBack,
		onProgress,
		structs.GlobalConfig.HTTPProxy,
		structs.GlobalConfig.WebThreads,
		structs.GlobalConfig.WebTimeout,
	)
}

func appendHTTPServiceURLs(urls []string, hostPort string) []string {
	return append(urls, "http://"+hostPort, "https://"+hostPort)
}

func collectAliveURLs() []string {
	var aliveURLs []string
	for rootURL := range structs.GlobalURLMap {
		aliveURLs = append(aliveURLs, rootURL)
	}
	return aliveURLs
}

func runNamedPocSearch(aliveURLs []string) bool {
	searchName := strings.TrimSpace(structs.GlobalConfig.PocNameForSearch)
	if searchName == "" {
		return false
	}

	workflowPocs := workflowPocsForSearch(searchName)
	gologger.AuditTimeLogger("模糊搜索Poc: %v", searchName)
	if len(workflowPocs) > 0 {
		gologger.AuditLogger(fmt.Sprintf("    - workflow 关联 POC: %d 个", len(workflowPocs)))
	}

	targetAndPocsName := make(map[string][]string)
	for _, url := range aliveURLs {
		// 除了按文件名模糊匹配，还传入匹配产品 workflow 中声明的 POC。
		// 例如 CVE-2026-15907 的文件名不含 H3C，但它由 H3C-F1000 workflow 引用。
		targetAndPocsName[url] = append([]string(nil), workflowPocs...)
	}

	report.GenerateHTMLReportHeader()
	callnuclei.CallNuclei(buildNucleiParams(targetAndPocsName, searchName))
	utils.DeleteReportWithNoResult()
	return true
}

// workflowPocsForSearch returns POCs declared by workflow products whose names
// contain the requested search text. Named POC search normally only examines
// template paths, which misses POCs such as CVE-2026-15907 whose filename does
// not contain the product name that references it.
func workflowPocsForSearch(searchName string) []string {
	searchName = strings.ToLower(strings.TrimSpace(searchName))
	if searchName == "" {
		return nil
	}

	var pocs []string
	for productName, workflowEntity := range structs.WorkFlowDB {
		if !strings.Contains(strings.ToLower(productName), searchName) {
			continue
		}
		pocs = append(pocs, workflowEntity.PocsName...)
	}
	return utils.RemoveDuplicateElement(pocs)
}

func runDirBrute(aliveURLs []string) {
	if structs.GlobalConfig.NoDirSearch {
		return
	}

	checkURLs := buildDirBruteTargets(aliveURLs)

	gologger.Info().Msgf("开始主动指纹探测 (目标 %d)", len(checkURLs))
	bar := progress.New("主动指纹", len(checkURLs))
	defer bar.Finish()
	onProgress := func(current, total int) { bar.Set(current) }

	httpx.DirBruteWithProgress(
		checkURLs,
		dddhttp.DirBruteCallBack,
		onProgress,
		structs.GlobalConfig.HTTPProxy,
		structs.GlobalConfig.WebThreads,
		structs.GlobalConfig.WebTimeout,
	)
	gologger.AuditTimeLogger("主动指纹探测结束")
}

func buildDirBruteTargets(aliveURLs []string) []string {
	var checkURLs []string
	for path := range structs.DirDB {
		for _, aliveURL := range aliveURLs {
			if strings.HasSuffix(aliveURL, "/") && strings.HasPrefix(path, "/") {
				checkURLs = append(checkURLs, aliveURL[:len(aliveURL)-1]+path)
				continue
			}
			checkURLs = append(checkURLs, aliveURL+path)
		}
	}
	return utils.RemoveDuplicateElement(checkURLs)
}

func runVulnerabilityScans() {
	report.GenerateHTMLReportHeader()

	targetAndPocsName, count := dddhttp.GetPocs(structs.WorkFlowDB)
	var nucleiResults []output.ResultEvent
	if count > 0 {
		nucleiResults = callnuclei.CallNuclei(buildNucleiParams(targetAndPocsName, ""))
	}

	if !structs.GlobalConfig.NoGolangPoc {
		gopocs.GoPocsDispatcher(nucleiResults)
	}

	utils.DeleteReportWithNoResult()
}

func buildNucleiParams(targetAndPocsName map[string][]string, nameForSearch string) callnuclei.NucleiParams {
	return callnuclei.NucleiParams{
		TargetAndPocsName: targetAndPocsName,
		Proxy:             structs.GlobalConfig.HTTPProxy,
		CallBack:          report.AddResultByResultEvent,
		NameForSearch:     nameForSearch,
		NoInteractsh:      structs.GlobalConfig.NoInteractsh,
		Fs:                structs.GlobalEmbedPocs,
		NP:                structs.GlobalConfig.NucleiTemplate,
		ExcludeTags:       strings.Split(structs.GlobalConfig.ExcludeTags, ","),
		Severities:        strings.Split(structs.GlobalConfig.Severities, ","),
		InteractshServer:  structs.GlobalConfig.InteractshURL,
		InteractshToken:   structs.GlobalConfig.InteractshToken,
		CustomHeaders:     structs.GlobalConfig.PocHeaders,
	}
}

func searchEngine() {
	if structs.GlobalConfig.Hunter && !structs.GlobalConfig.Fofa {
		structs.GlobalConfig.Targets, _ = uncover.HunterSearch(structs.GlobalConfig.Targets)
		return
	}

	if structs.GlobalConfig.Fofa && !structs.GlobalConfig.Hunter {
		structs.GlobalConfig.Targets = uncover.FOFASearch(structs.GlobalConfig.Targets)
		return
	}

	if structs.GlobalConfig.Fofa && structs.GlobalConfig.Hunter {
		targets, tIPs := uncover.HunterSearch(structs.GlobalConfig.Targets)
		var querys []string
		for _, ip := range tIPs {
			querys = append(querys, "ip=\""+ip+"\"")
		}
		querys = utils.RemoveDuplicateElement(querys)
		structs.GlobalConfig.Targets = uncover.FOFASearch(querys)
		structs.GlobalConfig.Targets = append(structs.GlobalConfig.Targets, targets...)
		structs.GlobalConfig.Targets = utils.RemoveDuplicateElement(structs.GlobalConfig.Targets)
		return
	}

	if structs.GlobalConfig.Quake {
		structs.GlobalConfig.Targets = uncover.QuakeSearch(structs.GlobalConfig.Targets)
	}
}
