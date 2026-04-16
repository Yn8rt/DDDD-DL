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

	url := URLParse(finalUrl)
	pth := url.Path
	if pth == "" {
		pth = "/"
	}
	rootURL := fmt.Sprintf("%s://%s", url.Scheme, url.Host)
	structs.GlobalURLMapLock.Lock()
	_, rootURLOK := structs.GlobalURLMap[rootURL]
	structs.GlobalURLMapLock.Unlock()
	if rootURLOK {
		// 有这个root，查看这个path，如果没这个path再加
		structs.GlobalURLMapLock.Lock()
		_, pathOK := structs.GlobalURLMap[rootURL].WebPaths[url.Path]
		structs.GlobalURLMapLock.Unlock()
		if !pathOK {
			// 没有这个path
			md5 := resp.Hashes["body_md5"].(string)
			headerMd5 := resp.Hashes["header_md5"].(string)
			_ = structs.GlobalHttpBodyHMap.Set(md5, []byte(resp.Body))
			_ = structs.GlobalHttpHeaderHMap.Set(headerMd5, []byte(resp.Header))
			structs.GlobalURLMapLock.Lock()
			structs.GlobalURLMap[rootURL].WebPaths[pth] = structs.UrlPathEntity{
				Hash:             md5,
				Title:            resp.Title,
				StatusCode:       resp.StatusCode,
				ContentType:      resp.ContentType,
				Server:           resp.WebServer,
				ContentLength:    resp.ContentLength,
				HeaderHashString: headerMd5,
				IconHash:         resp.FavIconMMH3,
			}
			structs.GlobalURLMapLock.Unlock()

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
	} else {
		// 没有这个url

		port, err := strconv.Atoi(resp.Port)
		if err != nil {
			port = 0
		}

		md5 := resp.Hashes["body_md5"].(string)
		headerMd5 := resp.Hashes["header_md5"].(string)
		_ = structs.GlobalHttpBodyHMap.Set(md5, []byte(resp.Body))
		_ = structs.GlobalHttpHeaderHMap.Set(headerMd5, []byte(resp.Header))

		webPath := structs.UrlPathEntity{
			Hash:             md5,
			Title:            resp.Title,
			StatusCode:       resp.StatusCode,
			ContentType:      resp.ContentType,
			Server:           resp.WebServer,
			ContentLength:    resp.ContentLength,
			HeaderHashString: headerMd5,
			IconHash:         resp.FavIconMMH3,
		}

		urlE := structs.URLEntity{
			IP:       resp.Host,
			Port:     port,
			WebPaths: nil,
			Cert:     getTLSString(resp),
		}

		urlE.WebPaths = make(map[string]structs.UrlPathEntity)
		urlE.WebPaths[pth] = webPath

		structs.GlobalURLMapLock.Lock()
		structs.GlobalURLMap[rootURL] = urlE
		structs.GlobalURLMapLock.Unlock()

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

func addPocs(target string, result *map[string][]string, workflowEntity structs.WorkFlowEntity) {
	// 判断有没有加入过
	_, ok := (*result)[target]
	if !ok { // 没有添加过这个目标
		(*result)[target] = []string{}
		for _, pocName := range workflowEntity.PocsName {
			(*result)[target] = append((*result)[target], AddYamlSuffix(pocName))
			gologger.AuditLogger("    - " + pocName)
		}
	} else { // 添加过就逐个比较
		existPocNames, _ := (*result)[target]
		for _, pocName := range workflowEntity.PocsName {
			// 没有就添加
			if utils.GetItemInArray(existPocNames, pocName) == -1 {
				(*result)[target] = append((*result)[target], AddYamlSuffix(pocName))
				gologger.AuditLogger("    - " + pocName)
			}
		}
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
	if structs.GlobalConfig.FingerNameForSearch != "" {
		gologger.AuditTimeLogger(fmt.Sprintf("强制扫描指纹: %s", structs.GlobalConfig.FingerNameForSearch))
		gologger.Info().Msgf(fmt.Sprintf("[指纹强制扫描] 正在匹配: %s", structs.GlobalConfig.FingerNameForSearch))
		var matchedFingers []string
		var matchedPocs []string

		// 从 workflowDB 中模糊匹配指纹名称
		for fingerName, workflowEntity := range workflowDB {
			if strings.Contains(strings.ToLower(fingerName), strings.ToLower(structs.GlobalConfig.FingerNameForSearch)) {
				matchedFingers = append(matchedFingers, fingerName)
				matchedPocs = append(matchedPocs, workflowEntity.PocsName...)
				gologger.AuditLogger(fmt.Sprintf("  匹配到指纹: %s (%d个POC)", fingerName, len(workflowEntity.PocsName)))
				// 输出到控制台
				gologger.Print().Msgf(fmt.Sprintf("  ✓ 匹配到指纹: %s (%d个POC)", fingerName, len(workflowEntity.PocsName)))
				for _, poc := range workflowEntity.PocsName {
					gologger.Debug().Msgf(fmt.Sprintf("    - %s", poc))
				}
			}
		}

		if len(matchedFingers) == 0 {
			gologger.Warning().Msgf("未找到匹配的指纹: %s", structs.GlobalConfig.FingerNameForSearch)
		} else {
			gologger.Info().Msgf(fmt.Sprintf("[指纹强制扫描] 共匹配 %d 个指纹，%d 个POC", len(matchedFingers), len(matchedPocs)))
		}

		// 对所有目标强制添加匹配到的 POC
		if len(matchedPocs) > 0 {
			for target := range structs.GlobalResultMap {
				gologger.AuditLogger(fmt.Sprintf("%s: 强制添加 %d 个POC", target, len(matchedPocs)))
				gologger.Print().Msgf(fmt.Sprintf("  → %s: 强制添加 %d 个POC", target, len(matchedPocs)))
				for _, pocName := range matchedPocs {
					pocWithSuffix := AddYamlSuffix(pocName)
					if utils.GetItemInArray(result[target], pocWithSuffix) == -1 {
						result[target] = append(result[target], pocWithSuffix)
					}
				}
				count++
			}
		}
	}

	var generalKeys []string
	if !structs.GlobalConfig.DisableGeneralPoc {
		for k, workflowEntity := range workflowDB {
			if strings.Contains(k, "General-Poc-") {
				if len(workflowEntity.PocsName) == 0 {
					continue
				}
				generalKeys = append(generalKeys, k)
			}
		}
	}

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

			if !strings.Contains(target, "http") {
				if !shouldScanRoot(workflowEntity, scanRoot) { // 与Root无关
					continue
				}
				addPocs(target, &result, workflowEntity)
				count++
			} else {
				Url := URLParse(target)

				// Web
				if shouldScanRoot(workflowEntity, scanRoot) {
					rootURL := fmt.Sprintf("%s://%s", Url.Scheme, Url.Host)
					addPocs(rootURL, &result, workflowEntity)
					count++

				}

				if (Url.Path != "/" && Url.Path != "") && shouldScanBase(workflowEntity, scanBase) {
					addPocs(target, &result, workflowEntity)
					count++
				}

				if (Url.Path != "/" && Url.Path != "") && shouldScanDir(workflowEntity, scanDir) {
					splitPath := strings.Split(Url.Path, "/")
					for i := 1; i < len(splitPath); i++ {
						newPath := strings.Join(splitPath[:i], "/")
						t := fmt.Sprintf("%s://%s%s", Url.Scheme, Url.Host, newPath)
						addPocs(t, &result, workflowEntity)
						count++
					}

				}
			}

		}

		for _, key := range generalKeys {
			workflowEntity, ok := workflowDB[key]
			if !ok || len(workflowEntity.PocsName) == 0 {
				continue
			}

			if !strings.Contains(target, "http") {
				if !shouldScanRoot(workflowEntity, scanRoot) { // 与Root无关
					continue
				}
				addPocs(target, &result, workflowEntity)
				count++
			} else {
				Url := URLParse(target)

				// Web
				if shouldScanRoot(workflowEntity, scanRoot) {
					rootURL := fmt.Sprintf("%s://%s", Url.Scheme, Url.Host)
					addPocs(rootURL, &result, workflowEntity)
					count++
				}

				if (Url.Path != "/" && Url.Path != "") && shouldScanBase(workflowEntity, scanBase) {
					addPocs(target, &result, workflowEntity)
					count++
				}

				if (Url.Path != "/" && Url.Path != "") && shouldScanDir(workflowEntity, scanDir) {
					splitPath := strings.Split(Url.Path, "/")
					for i := 1; i < len(splitPath); i++ {
						newPath := strings.Join(splitPath[:i], "/")
						t := fmt.Sprintf("%s://%s%s", Url.Scheme, Url.Host, newPath)
						addPocs(t, &result, workflowEntity)
						count++
					}

				}
			}
		}

	}
	return result, count
}

func DirBruteCallBack(resp runner.Result) {
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
							// 如果爆破来源上一步验活，那这里必然存在rootURL.
							// 有这个root，查看这个path，如果没这个path再加
							structs.GlobalURLMapLock.Lock()
							_, pathOK := structs.GlobalURLMap[rootURL].WebPaths[Url.Path]
							structs.GlobalURLMapLock.Unlock()
							if !pathOK {
								// 没有这个path
								md5 := resp.Hashes["body_md5"].(string)
								headerMd5 := resp.Hashes["header_md5"].(string)
								_ = structs.GlobalHttpBodyHMap.Set(md5, []byte(resp.Body))
								_ = structs.GlobalHttpHeaderHMap.Set(headerMd5, []byte(resp.Header))
								structs.GlobalURLMapLock.Lock()
								structs.GlobalURLMap[rootURL].WebPaths[Url.Path] = structs.UrlPathEntity{
									Hash:             md5,
									Title:            resp.Title,
									StatusCode:       resp.StatusCode,
									ContentType:      resp.ContentType,
									Server:           resp.WebServer,
									ContentLength:    resp.ContentLength,
									HeaderHashString: headerMd5,
									IconHash:         resp.FavIconMMH3,
								}
								structs.GlobalURLMapLock.Unlock()
							}

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
	ips := resp.A
	path := resp.Path
	newWeb := false
	for _, ip := range ips {
		structs.GlobalURLMapLock.Lock()
		for rootURL, urlEntry := range structs.GlobalURLMap {
			URL, err := url.Parse(rootURL)
			if err != nil {
				continue
			}
			if URL.Scheme != resp.Scheme {
				continue
			}
			if urlEntry.IP != ip {
				continue
			}
			port := strconv.Itoa(urlEntry.Port)
			if port != resp.Port {
				continue
			}

			existPath, ok := urlEntry.WebPaths[path]
			if !ok {
				continue
			}

			if existPath.StatusCode != resp.StatusCode || existPath.Hash != resp.Hashes["body_md5"].(string) {
				newWeb = true
			}

		}
		structs.GlobalURLMapLock.Unlock()
	}

	if !newWeb {
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
	rootURL := fmt.Sprintf("%s://%s", urlFinal.Scheme, urlFinal.Host)
	structs.GlobalURLMapLock.Lock()
	_, rootURLOK := structs.GlobalURLMap[rootURL]
	structs.GlobalURLMapLock.Unlock()
	if rootURLOK {
		// 有这个root，查看这个path，如果没这个path再加
		structs.GlobalURLMapLock.Lock()
		_, pathOK := structs.GlobalURLMap[rootURL].WebPaths[urlFinal.Path]
		structs.GlobalURLMapLock.Unlock()
		if !pathOK {
			// 没有这个path
			md5 := resp.Hashes["body_md5"].(string)
			headerMd5 := resp.Hashes["header_md5"].(string)
			_ = structs.GlobalHttpBodyHMap.Set(md5, []byte(resp.Body))
			_ = structs.GlobalHttpHeaderHMap.Set(headerMd5, []byte(resp.Header))
			structs.GlobalURLMapLock.Lock()
			structs.GlobalURLMap[rootURL].WebPaths[urlFinal.Path] = structs.UrlPathEntity{
				Hash:             md5,
				Title:            resp.Title,
				StatusCode:       resp.StatusCode,
				ContentType:      resp.ContentType,
				Server:           resp.WebServer,
				ContentLength:    resp.ContentLength,
				HeaderHashString: headerMd5,
				IconHash:         resp.FavIconMMH3,
			}
			structs.GlobalURLMapLock.Unlock()
		}
	} else {
		// 没有这个url

		port, err := strconv.Atoi(resp.Port)
		if err != nil {
			port = 0
		}

		md5 := resp.Hashes["body_md5"].(string)
		headerMd5 := resp.Hashes["header_md5"].(string)
		_ = structs.GlobalHttpBodyHMap.Set(md5, []byte(resp.Body))
		_ = structs.GlobalHttpHeaderHMap.Set(headerMd5, []byte(resp.Header))

		webPath := structs.UrlPathEntity{
			Hash:             md5,
			Title:            resp.Title,
			StatusCode:       resp.StatusCode,
			ContentType:      resp.ContentType,
			Server:           resp.WebServer,
			ContentLength:    resp.ContentLength,
			HeaderHashString: headerMd5,
			IconHash:         resp.FavIconMMH3,
		}

		urlE := structs.URLEntity{
			IP:       resp.Host,
			Port:     port,
			WebPaths: nil,
			Cert:     getTLSString(resp),
		}

		urlE.WebPaths = make(map[string]structs.UrlPathEntity)
		urlE.WebPaths[urlFinal.Path] = webPath

		structs.GlobalURLMapLock.Lock()
		structs.GlobalURLMap[rootURL] = urlE
		structs.GlobalURLMapLock.Unlock()
	}

}
