package http

import (
	"dddd/ddout"
	"dddd/lib/ddfinger"
	"dddd/structs"
	"dddd/utils"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx"
	"github.com/projectdiscovery/httpx/runner"
	"net/url"
	"strconv"
	"strings"
)

// parseScanType 解析用户指定的扫描类型
// 返回: (scanRoot, scanDir, scanBase)
// 如果 scanType 为空，返回 (false, false, false)，表示使用 workflow.yaml 中的配置
func parseScanType(scanType string) (bool, bool, bool) {
	if scanType == "" {
		return false, false, false
	}

	var scanRoot, scanDir, scanBase bool
	parts := strings.Split(strings.ToLower(scanType), ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		switch part {
		case "root":
			scanRoot = true
		case "dir":
			scanDir = true
		case "base":
			scanBase = true
		}
	}
	return scanRoot, scanDir, scanBase
}

// shouldScanRoot 判断是否应该进行 root 扫描
// 用户参数优先级高于 workflow.yaml
func shouldScanRoot(workflowEntity structs.WorkFlowEntity, scanRoot bool) bool {
	if scanRoot {
		return true // 用户指定了 root，优先使用
	}
	return workflowEntity.RootType // 使用 workflow.yaml 中的配置
}

// shouldScanDir 判断是否应该进行 dir 扫描
func shouldScanDir(workflowEntity structs.WorkFlowEntity, scanDir bool) bool {
	if scanDir {
		return true
	}
	return workflowEntity.DirType
}

// shouldScanBase 判断是否应该进行 base 扫描
func shouldScanBase(workflowEntity structs.WorkFlowEntity, scanBase bool) bool {
	if scanBase {
		return true
	}
	return workflowEntity.BaseType
}

func UrlCallBack(resp runner.Result) {
	finalUrl := ""
	if resp.FinalURL != "" {
		finalUrl = resp.FinalURL
	} else {
		finalUrl = resp.URL
	}

	if resp.StatusCode == 400 && strings.Contains(resp.Title, "plain HTTP request was sent to HTTPS port") {
		if strings.HasPrefix(resp.URL, "http://") {
			httpsURL := strings.Replace(resp.URL, "http://", "https://", 1)
			httpx.AddHTTPSRetryUrl(httpsURL)
			gologger.Debug().Msgf("[HTTPS重试] 检测到HTTP请求发送到HTTPS端口: %s -> %s", resp.URL, httpsURL)
		}
	}

	if upsertURLResult(resp, finalUrl) {
		ddout.FormatOutput(ddout.OutputMessage{
			Type: "Web",
			IP:   "",
			Port: "",
			URI:  resp.URL,
			Web: ddout.WebInfo{
				Status: strconv.Itoa(resp.StatusCode),
				Title:  resp.Title,
			},
		})
	}

}

func getTLSString(resp runner.Result) string {
	result := ""
	if resp.TLSData == nil {
		return result
	}

	result += "SubjectCN: " + resp.TLSData.SubjectCN + "\n"
	result += "SubjectDN: " + resp.TLSData.SubjectDN + "\n"

	result += "IssuerCN: " + resp.TLSData.IssuerCN + "\n"
	result += "IssuerDN: " + resp.TLSData.IssuerDN + "\n"

	result += "IssuerOrg: \n"
	for _, v := range resp.TLSData.IssuerOrg {
		result += "    - " + v + "\n"
	}

	return result

}

func URLParse(URLRaw string) *url.URL {
	URL, _ := url.Parse(URLRaw)
	return URL
}

func AddYamlSuffix(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, ".yaml") {
		return s
	} else {
		return s + ".yaml"
	}
}

func addPocs(target string, result map[string][]string, workflowEntity structs.WorkFlowEntity) {
	existingPocs := result[target]
	existingSet := make(map[string]struct{}, len(existingPocs))
	for _, pocName := range existingPocs {
		existingSet[pocName] = struct{}{}
	}

	for _, pocName := range workflowEntity.PocsName {
		pocWithSuffix := AddYamlSuffix(pocName)
		if _, ok := existingSet[pocWithSuffix]; ok {
			continue
		}
		result[target] = append(result[target], pocWithSuffix)
		existingSet[pocWithSuffix] = struct{}{}
		gologger.AuditLogger("    - " + pocName)
	}
}

func GetPocs(workflowDB map[string]structs.WorkFlowEntity) (map[string][]string, int) {
	return GetPocsWithFilter(workflowDB, structs.GlobalBlackFingerMap)
}

// GetPocsWithFilter 根据指纹选择POC，支持黑名单过滤
func GetPocsWithFilter(workflowDB map[string]structs.WorkFlowEntity, blackFingerMap map[string]bool) (map[string][]string, int) {
	gologger.AuditTimeLogger("根据指纹选择Poc")
	result := make(map[string][]string)
	count := 0

	// 解析用户指定的扫描类型（优先级高于 workflow.yaml）
	scanRoot, scanDir, scanBase := parseScanType(structs.GlobalConfig.PocScanType)
	if structs.GlobalConfig.PocScanType != "" {
		gologger.Info().Msgf(fmt.Sprintf("[POC扫描类型] 用户指定: %s (root=%v, dir=%v, base=%v)", structs.GlobalConfig.PocScanType, scanRoot, scanDir, scanBase))
	}

	// 处理用户指定的指纹名称强制扫描
	count += applyForcedFingerPocs(workflowDB, result)
	generalKeys := getGeneralWorkflowKeys(workflowDB)

	for target, fingerprints := range structs.GlobalResultMap {
		gologger.AuditLogger(target + ":")

		// 蜜罐检测：指纹数量超过10个判定为蜜罐，跳过POC扫描
		if len(fingerprints) > 10 {
			gologger.AuditLogger(fmt.Sprintf("    - 检测到蜜罐（指纹数量：%d），跳过POC扫描", len(fingerprints)))
			ddout.FormatOutput(ddout.OutputMessage{
				Type:          "Honeypot",
				IP:            "",
				IPs:           nil,
				Port:          "",
				Protocol:      "",
				Web:           ddout.WebInfo{},
				Finger:        fingerprints,
				Domain:        "",
				GoPoc:         ddout.GoPocsResultType{},
				URI:           target,
				AdditionalMsg: fmt.Sprintf("检测到蜜罐（指纹数量：%d）", len(fingerprints)),
			})
			continue
		}

		for _, finger := range fingerprints {
			// 检查黑名单
			if blackFingerMap != nil {
				fingerLower := strings.ToLower(finger)
				if blackFingerMap[fingerLower] {
					gologger.AuditLogger("    - 跳过黑名单指纹: " + finger)
					continue
				}
			}

			workflowEntity, ok := workflowDB[finger]
			if !ok || len(workflowEntity.PocsName) == 0 {
				continue
			}

			count += addWorkflowTargets(target, workflowEntity, result, scanRoot, scanDir, scanBase)
		}

		for _, key := range generalKeys {
			workflowEntity, ok := workflowDB[key]
			if !ok || len(workflowEntity.PocsName) == 0 {
				continue
			}
			count += addWorkflowTargets(target, workflowEntity, result, scanRoot, scanDir, scanBase)
		}

	}
	return result, count
}

func applyForcedFingerPocs(workflowDB map[string]structs.WorkFlowEntity, result map[string][]string) int {
	if structs.GlobalConfig.FingerNameForSearch == "" {
		return 0
	}

	gologger.AuditTimeLogger(fmt.Sprintf("强制扫描指纹: %s", structs.GlobalConfig.FingerNameForSearch))
	gologger.Info().Msgf(fmt.Sprintf("[指纹强制扫描] 正在匹配: %s", structs.GlobalConfig.FingerNameForSearch))

	var matchedFingers []string
	var matchedPocs []string
	for fingerName, workflowEntity := range workflowDB {
		if !strings.Contains(strings.ToLower(fingerName), strings.ToLower(structs.GlobalConfig.FingerNameForSearch)) {
			continue
		}

		matchedFingers = append(matchedFingers, fingerName)
		matchedPocs = append(matchedPocs, workflowEntity.PocsName...)
		gologger.AuditLogger(fmt.Sprintf("  匹配到指纹: %s (%d个POC)", fingerName, len(workflowEntity.PocsName)))
		gologger.Print().Msgf(fmt.Sprintf("  ✓ 匹配到指纹: %s (%d个POC)", fingerName, len(workflowEntity.PocsName)))
		for _, poc := range workflowEntity.PocsName {
			gologger.Debug().Msgf(fmt.Sprintf("    - %s", poc))
		}
	}

	if len(matchedFingers) == 0 {
		gologger.Warning().Msgf("未找到匹配的指纹: %s", structs.GlobalConfig.FingerNameForSearch)
		return 0
	}

	gologger.Info().Msgf(fmt.Sprintf("[指纹强制扫描] 共匹配 %d 个指纹，%d 个POC", len(matchedFingers), len(matchedPocs)))
	added := 0
	for target := range structs.GlobalResultMap {
		gologger.AuditLogger(fmt.Sprintf("%s: 强制添加 %d 个POC", target, len(matchedPocs)))
		gologger.Print().Msgf(fmt.Sprintf("  → %s: 强制添加 %d 个POC", target, len(matchedPocs)))
		existingSet := make(map[string]struct{}, len(result[target]))
		for _, existing := range result[target] {
			existingSet[existing] = struct{}{}
		}
		for _, pocName := range matchedPocs {
			pocWithSuffix := AddYamlSuffix(pocName)
			if _, ok := existingSet[pocWithSuffix]; ok {
				continue
			}
			result[target] = append(result[target], pocWithSuffix)
			existingSet[pocWithSuffix] = struct{}{}
		}
		added++
	}
	return added
}

func getGeneralWorkflowKeys(workflowDB map[string]structs.WorkFlowEntity) []string {
	if structs.GlobalConfig.DisableGeneralPoc {
		return nil
	}

	var generalKeys []string
	for key, workflowEntity := range workflowDB {
		if strings.Contains(key, "General-Poc-") && len(workflowEntity.PocsName) > 0 {
			generalKeys = append(generalKeys, key)
		}
	}
	return generalKeys
}

func addWorkflowTargets(target string, workflowEntity structs.WorkFlowEntity, result map[string][]string, scanRoot, scanDir, scanBase bool) int {
	if !strings.Contains(target, "http") {
		if !shouldScanRoot(workflowEntity, scanRoot) {
			return 0
		}
		addPocs(target, result, workflowEntity)
		return 1
	}

	targetURL := URLParse(target)
	targets := buildPOCTargets(targetURL, workflowEntity, scanRoot, scanDir, scanBase)
	for _, pocTarget := range targets {
		addPocs(pocTarget, result, workflowEntity)
	}
	return len(targets)
}

func buildPOCTargets(targetURL *url.URL, workflowEntity structs.WorkFlowEntity, scanRoot, scanDir, scanBase bool) []string {
	var targets []string

	if shouldScanRoot(workflowEntity, scanRoot) {
		targets = append(targets, fmt.Sprintf("%s://%s", targetURL.Scheme, targetURL.Host))
	}

	hasSubPath := targetURL.Path != "" && targetURL.Path != "/"
	if !hasSubPath {
		return utils.RemoveDuplicateElement(targets)
	}

	if shouldScanBase(workflowEntity, scanBase) {
		targets = append(targets, targetURL.String())
	}

	if shouldScanDir(workflowEntity, scanDir) {
		splitPath := strings.Split(targetURL.Path, "/")
		for i := 1; i < len(splitPath); i++ {
			newPath := strings.Join(splitPath[:i], "/")
			targets = append(targets, fmt.Sprintf("%s://%s%s", targetURL.Scheme, targetURL.Host, newPath))
		}
	}

	return utils.RemoveDuplicateElement(targets)
}

func DirBruteCallBack(resp runner.Result) {
	// 软 404 过滤
	// 当主动指纹请求不存在路径时, 部分服务器 (nginx/tengine/iis) 会返回
	// 带有服务器 banner 的 404 页面, 这些页面常含 "tengine"/"nginx" 等关键词
	// 触发指纹库误匹配, 产生大量 false-positive Active-Finger
	// 策略: 4xx/5xx 状态码 + soft-404 body 特征 → 直接跳过指纹匹配
	if isSoft404Response(resp) {
		return
	}

	var Paths []string
	for dbPath, _ := range structs.DirDB {
		if strings.HasSuffix(resp.Path, dbPath) {
			Paths = append(Paths, dbPath)
		}
	}

	for _, path := range Paths {
		productNames := structs.DirDB[path]
		for _, productName := range productNames {
			success := false
			for _, v := range structs.FingerprintDB {
				if success {
					break
				}
				if v.ProductName == productName {
					portInt, err := strconv.Atoi(resp.Port)
					if err != nil {
						portInt = -1
					}
					r := ddfinger.SingleCheck(v, resp.Scheme, resp.Header, resp.Body, resp.WebServer, resp.Title, getTLSString(resp),
						portInt, resp.Path, "0", "0", resp.StatusCode, resp.ContentType, "")
					// 满足这个products的要求
					if r {
						success = true
						// 给对应的urlEntry添加指纹
						Url := URLParse(resp.URL)
						rootURL := fmt.Sprintf("%s://%s", Url.Scheme, Url.Host)
						structs.GlobalURLMapLock.Lock()
						_, rootURLOk := structs.GlobalURLMap[rootURL]
						structs.GlobalURLMapLock.Unlock()
						if rootURLOk {
							upsertURLResult(resp, resp.URL)
							structs.AddActiveFinger(resp.URL, productName)
							ddout.FormatOutput(ddout.OutputMessage{
								Type:          "Active-Finger",
								IP:            "",
								IPs:           nil,
								Port:          "",
								Protocol:      "",
								Web:           ddout.WebInfo{},
								Finger:        []string{productName},
								Domain:        "",
								GoPoc:         ddout.GoPocsResultType{},
								URI:           resp.URL,
								AdditionalMsg: "",
							})
							// gologger.Silent().Msgf("[Active-Finger] %s [%s]", resp.URL, productName)
						}
					}
				}
			}
		}
	}
}

func HostBindHTTPxCallBack(resp runner.Result) {
	if !hasNewHostBindContent(resp) {
		return
	}

	ddout.FormatOutput(ddout.OutputMessage{
		Type:     "Domain-Bind",
		IP:       "",
		IPs:      nil,
		Port:     "",
		Protocol: "",
		Web: ddout.WebInfo{
			Status: strconv.Itoa(resp.StatusCode),
		},
		Finger:        nil,
		Domain:        "",
		GoPoc:         ddout.GoPocsResultType{},
		URI:           resp.URL,
		AdditionalMsg: resp.Title,
	})

	//if resp.Title != "" {
	//	gologger.Silent().Msgf("[Domain-Bind] [%v] %v [%v]", resp.StatusCode, resp.URL, resp.Title)
	//} else {
	//	gologger.Silent().Msgf("[Domain-Bind] [%v] %v", resp.StatusCode, resp.URL)
	//}

	finalUrl := ""
	if resp.FinalURL != "" {
		finalUrl = resp.FinalURL
	} else {
		finalUrl = resp.URL
	}

	urlFinal := URLParse(finalUrl)
	upsertURLResult(resp, urlFinal.String())

}

func hasNewHostBindContent(resp runner.Result) bool {
	path := normalizeURLPath(resp.Path)
	bodyHash := getBodyHash(resp)

	ipSet := make(map[string]struct{}, len(resp.A))
	for _, ip := range resp.A {
		ipSet[ip] = struct{}{}
	}

	structs.GlobalURLMapLock.Lock()
	defer structs.GlobalURLMapLock.Unlock()

	for rootURL, urlEntry := range structs.GlobalURLMap {
		parsedURL, err := url.Parse(rootURL)
		if err != nil {
			continue
		}
		if parsedURL.Scheme != resp.Scheme {
			continue
		}
		if _, ok := ipSet[urlEntry.IP]; !ok {
			continue
		}
		if strconv.Itoa(urlEntry.Port) != resp.Port {
			continue
		}

		existPath, ok := urlEntry.WebPaths[path]
		if !ok {
			continue
		}

		if existPath.StatusCode != resp.StatusCode || existPath.Hash != bodyHash {
			return true
		}
	}

	return false
}
