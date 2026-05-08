package ddfinger

import (
	"container/list"
	"dddd/ddout"
	"dddd/structs"
	"dddd/utils"
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"net/url"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

type matchContext struct {
	HeaderLower      string
	BodyLower        string
	ServerLower      string
	TitleLower       string
	CertLower        string
	PathLower        string
	HashLower        string
	ContentTypeLower string
	BannerLower      string
	Protocol         string
	Port             int
	IconHash         int
	HasIconHash      bool
	StatusCode       int
}

// 判断优先级 非运算符返回0
func advance(ch int) int {
	// !
	if ch == 33 {
		return 3
	}
	// &
	if ch == 38 {
		return 2
	}
	// |
	if ch == 124 {
		return 1
	}
	return 0
}

// 计算纯bool表达式，支持 ! && & || | ( )
func boolEval(expression string) bool {
	// 左右括号数量相等
	if strings.Count(expression, "(") != strings.Count(expression, ")") {
		gologger.Fatal().Msg(fmt.Sprintf("[-] 纯布尔表达式 [%s] 左右括号不匹配", expression))
	}
	// 去除空格
	for strings.Contains(expression, " ") {
		expression = strings.ReplaceAll(expression, " ", "")
	}
	// 去除空表达式
	for strings.Contains(expression, "()") {
		expression = strings.ReplaceAll(expression, "()", "")
	}
	for strings.Contains(expression, "&&") {
		expression = strings.ReplaceAll(expression, "&&", "&")
	}
	for strings.Contains(expression, "||") {
		expression = strings.ReplaceAll(expression, "||", "|")
	}
	if !strings.Contains(expression, "T") && !strings.Contains(expression, "F") {
		return false
		// panic("纯布尔表达式错误，没有包含T/F")
	}

	expr := list.New()
	operator_stack := list.New()
	for _, ch := range expression {
		// ch 为 T或者F
		if ch == 84 || ch == 70 {
			expr.PushBack(int(ch))
		} else if advance(int(ch)) > 0 {
			if operator_stack.Len() == 0 {
				operator_stack.PushBack(int(ch))
				continue
			}
			// 两个!抵消
			if ch == 33 && operator_stack.Back().Value.(int) == 33 {
				operator_stack.Remove(operator_stack.Back())
				continue
			}
			for operator_stack.Len() != 0 && operator_stack.Back().Value.(int) != 40 && advance(operator_stack.Back().Value.(int)) >= advance(int(ch)) {
				e := operator_stack.Back()
				expr.PushBack(e.Value.(int))
				operator_stack.Remove(e)
			}
			operator_stack.PushBack(int(ch))

		} else if ch == 40 {
			operator_stack.PushBack(int(ch))
		} else if ch == 41 {
			for operator_stack.Back().Value.(int) != 40 {
				e := operator_stack.Back()
				expr.PushBack(e.Value.(int))
				operator_stack.Remove(e)
			}
			operator_stack.Remove(operator_stack.Back())
		}
	}
	for operator_stack.Len() != 0 {
		e := operator_stack.Back()
		expr.PushBack(e.Value.(int))
		operator_stack.Remove(e)
	}

	tf_stack := list.New()
	for expr.Len() != 0 {
		e := expr.Front()
		ch := e.Value.(int)
		expr.Remove(e)
		if ch == 84 || ch == 70 {
			tf_stack.PushBack(int(ch))
		}
		if ch == 38 { // &
			em := tf_stack.Back()
			a := em.Value.(int)
			tf_stack.Remove(em)
			em = tf_stack.Back()
			b := em.Value.(int)
			tf_stack.Remove(em)
			if a == 84 && b == 84 {
				tf_stack.PushBack(84)
			} else {
				tf_stack.PushBack(70)
			}
		}
		if ch == 124 { // |
			em := tf_stack.Back()
			a := em.Value.(int)
			tf_stack.Remove(em)
			em = tf_stack.Back()
			b := em.Value.(int)
			tf_stack.Remove(em)
			if a == 70 && b == 70 {
				tf_stack.PushBack(70)
			} else {
				tf_stack.PushBack(84)
			}
		}
		if ch == 33 { // !
			em := tf_stack.Back()
			a := em.Value.(int)
			tf_stack.Remove(em)
			if a == 70 {
				tf_stack.PushBack(84)
			} else if a == 84 {
				tf_stack.PushBack(70)
			}
		}
	}
	if tf_stack.Front().Value.(int) == 84 {
		return true
	} else {
		return false
	}

}

func getRuleData(rule string) structs.RuleData {
	if !strings.Contains(rule, "=\"") {
		return structs.RuleData{}
	}
	pos := strings.Index(rule, "=\"")
	op := 0
	if rule[pos-1] == 33 {
		op = 1
	} else if rule[pos-1] == 61 {
		op = 2
	} else if rule[pos-1] == 62 {
		op = 3
	} else if rule[pos-1] == 60 {
		op = 4
	} else if rule[pos-1] == 126 {
		op = 5
	}

	start := 0
	ti := 0
	if op > 0 {
		ti = 1
	}
	for i := pos - 1 - ti; i >= 0; i-- {
		if (rule[i] > 122 || rule[i] < 97) && rule[i] != 95 {
			start = i + 1
			break
		}

	}
	key := rule[start : pos-ti]

	end := pos + 2
	found := false
	for i := pos + 2; i < len(rule)-1; i++ {
		if rule[i] != 92 && rule[i+1] == 34 {
			end = i + 2
			found = true
			break
		}
	}
	if !found {
		for i := pos + 2; i < len(rule); i++ {
			if rule[i] == 34 {
				end = i + 1
				found = true
				break
			}
		}
	}
	if !found || end <= pos+2 {
		gologger.Warning().Msgf("[指纹规则解析] 跳过格式错误的规则: %s", rule)
		return structs.RuleData{}
	}
	value := rule[pos+2 : end-1]
	all := rule[start:end]

	return structs.RuleData{Start: start, End: end, Op: int16(op), Key: key, Value: value, All: all}
}

func ParseRule(rule string) []structs.RuleData {
	var result []structs.RuleData
	empty := structs.RuleData{}

	for {
		data := getRuleData(rule)
		if data == empty {
			break
		}
		result = append(result, data)
		rule = rule[:data.Start] + "T" + rule[data.End:]
	}
	return result
}

func regexMatch(pattern string, s string) (bool, error) {
	matched, err := regexp.MatchString(pattern, s)
	if err != nil {
		return false, err
	}
	return matched, nil
}

// body="123"  op=0  dataSource为http.body dataRule=123
func dataCheckString(op int16, dataSource string, dataRule string) bool {
	dataSource = strings.ToLower(dataSource)

	dataRule = strings.ToLower(dataRule)
	dataRule = strings.ReplaceAll(dataRule, "\\\"", "\"")
	if op == 0 {
		if strings.Contains(dataSource, dataRule) {
			return true
		}
	} else if op == 1 {
		if !strings.Contains(dataSource, dataRule) {
			return true
		}
	} else if op == 2 {
		if dataSource == dataRule {
			return true
		}
	} else if op == 5 {
		rs, err := regexMatch(dataRule, dataSource)
		if err == nil && rs {
			return true
		}
	}
	return false
}

func dataCheckInt(op int16, dataSource int, dataRule int) bool {
	if op == 0 { // 数字相等
		if dataSource == dataRule {
			return true
		}
	} else if op == 1 { // 数字不相等
		if dataSource != dataRule {
			return true
		}
	} else if op == 3 { // 大于等于
		if dataSource >= dataRule {
			return true
		}
	} else if op == 4 {
		if dataSource <= dataRule {
			return true
		}
	}
	return false
}

func checkPath(Path string,
	webPath structs.UrlPathEntity,
	Port int, // 所开放的端口
	Protocol string, // 协议
	Banner string, // 响应
	Cert string, // TLS证书
) []string {
	var fingerPrintResults []string

	isWeb := Path != "no#web" && webPath.Hash != ""

	hashString := webPath.Hash
	body := ""
	bodyBytes, ok := structs.GlobalHttpBodyHMap.Get(hashString)
	if !ok {
		body = ""
	} else {
		body = string(bodyBytes)
	}

	headerString := ""
	headerBytes, ok := structs.GlobalHttpHeaderHMap.Get(webPath.HeaderHashString)
	if !ok {
		headerString = ""
	} else {
		headerString = string(headerBytes)
	}

	if isWeb && shouldSkipGenericErrorFingerprint(webPath.StatusCode, webPath.Title, body) {
		return nil
	}

	matchCtx := buildMatchContext(Protocol, headerString, body, webPath.Server, webPath.Title, Cert, Path, webPath.Hash, webPath.IconHash, webPath.StatusCode, webPath.ContentType, Banner, Port)

	workers := runtime.NumCPU() * 2
	inputChan := make(chan structs.FingerPEntity, len(structs.FingerprintDB))
	results := make(chan string, len(structs.FingerprintDB))
	var workerWG sync.WaitGroup
	var resultWG sync.WaitGroup

	resultWG.Add(1)
	go func() {
		defer resultWG.Done()
		for found := range results {
			fingerPrintResults = append(fingerPrintResults, found)
		}
	}()

	//多线程扫描
	for i := 0; i < workers; i++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for finger := range inputChan {
				if matchFinger(finger, isWeb, matchCtx) {
					results <- finger.ProductName
				}
			}
		}()
	}

	//添加扫描目标
	for _, input := range structs.FingerprintDB {
		inputChan <- input
	}
	close(inputChan)
	workerWG.Wait()
	close(results)
	resultWG.Wait()

	return utils.RemoveDuplicateElement(fingerPrintResults)
}

func prioritizeActiveFingers(target string, detected []string) []string {
	activeFingers := structs.GetActiveFingers(target)
	if len(activeFingers) == 0 {
		return detected
	}
	return utils.RemoveDuplicateElement(activeFingers)
}

func FingerprintIdentification() {
	gologger.Info().Msg(aurora.BrightGreen("指纹识别中").String())

	// 先识别非Web
	for hostPort, protocol := range structs.GlobalIPPortMap {
		if protocol == "http" || protocol == "https" || protocol == "" {
			continue
		}
		t := strings.Split(hostPort, ":")
		if len(t) != 2 {
			continue
		}
		// host := t[0]
		port, err := strconv.Atoi(t[1])
		if err != nil {
			continue
		}
		banner := ""
		bodyBytes, ok := structs.GlobalBannerHMap.Get(hostPort)
		if !ok {
			banner = ""
		} else {
			banner = string(bodyBytes)
		}
		results := checkPath("no#web", structs.UrlPathEntity{}, port, protocol, banner, "")
		if len(results) > 0 {
			Url := fmt.Sprintf("%s://%s", protocol, hostPort)
			structs.GlobalResultMap[Url] = results

			//msg := "[Finger] " + Url + " ["
			//for _, r := range results {
			//	msg += aurora.Cyan(r).String() + ","
			//}
			//msg = msg[:len(msg)-1] + "]"
			//gologger.Silent().Msg(msg)

			ddout.FormatOutput(ddout.OutputMessage{
				Type:          "Finger",
				IP:            "",
				IPs:           nil,
				Port:          "",
				Protocol:      "",
				Web:           ddout.WebInfo{},
				Finger:        results,
				Domain:        "",
				GoPoc:         ddout.GoPocsResultType{},
				URI:           Url,
				AdditionalMsg: "",
			})

		}

	}
	for rootURL, urlEntity := range structs.GlobalURLMap {
		banner := ""
		if urlEntity.IP != "" {
			hostPort := fmt.Sprintf("%s:%d", urlEntity.IP, urlEntity.Port)

			bodyBytes, ok := structs.GlobalBannerHMap.Get(hostPort)
			if !ok {
				banner = ""
			} else {
				banner = string(bodyBytes)
			}
		}

		URL, _ := url.Parse(rootURL)

		for path, pathEntity := range urlEntity.WebPaths {
			results := checkPath(path, pathEntity, urlEntity.Port, URL.Scheme, banner, urlEntity.Cert)
			fullURL := rootURL + path
			results = prioritizeActiveFingers(fullURL, results)

			if len(results) > 0 {
				structs.GlobalResultMap[fullURL] = results
				//msg := "[Finger] " + fullURL + " "
				//msg += fmt.Sprintf("[%d] [", pathEntity.StatusCode)
				//for _, r := range results {
				//	msg += aurora.Cyan(r).String() + ","
				//}
				//msg = msg[:len(msg)-1] + "]"
				//if pathEntity.Title != "" {
				//	msg += fmt.Sprintf(" [%s]", pathEntity.Title)
				//}
				//gologger.Silent().Msg(msg)
				ddout.FormatOutput(ddout.OutputMessage{
					Type:     "Finger",
					IP:       "",
					IPs:      nil,
					Port:     "",
					Protocol: "",
					Web: ddout.WebInfo{
						Status: strconv.Itoa(pathEntity.StatusCode),
						Title:  pathEntity.Title,
					},
					Finger:        results,
					Domain:        "",
					GoPoc:         ddout.GoPocsResultType{},
					URI:           fullURL,
					AdditionalMsg: "",
				})
			} else {
				structs.GlobalResultMap[fullURL] = []string{}
			}
		}
	}
	gologger.AuditTimeLogger("指纹识别结束")
}

func SingleCheck(finger structs.FingerPEntity, Protocol string, headerString string, body string,
	Server string, Title string, Cert string, Port int, Path string, Hash string, IconHash string, StatusCode int,
	ContentType string, Banner string) bool {
	matchCtx := buildMatchContext(Protocol, headerString, body, Server, Title, Cert, Path, Hash, IconHash, StatusCode, ContentType, Banner, Port)
	return matchFinger(finger, true, matchCtx)
}

func buildMatchContext(protocol, headerString, body, server, title, cert, path, hash, iconHash string, statusCode int, contentType, banner string, port int) matchContext {
	result := matchContext{
		HeaderLower:      strings.ToLower(headerString),
		BodyLower:        strings.ToLower(body),
		ServerLower:      strings.ToLower(server),
		TitleLower:       strings.ToLower(title),
		CertLower:        strings.ToLower(cert),
		PathLower:        strings.ToLower(path),
		HashLower:        strings.ToLower(hash),
		ContentTypeLower: strings.ToLower(contentType),
		BannerLower:      strings.ToLower(banner),
		Protocol:         protocol,
		Port:             port,
		StatusCode:       statusCode,
	}

	if parsedIconHash, err := strconv.Atoi(iconHash); err == nil {
		result.IconHash = parsedIconHash
		result.HasIconHash = true
	}

	return result
}

func matchFinger(finger structs.FingerPEntity, isWeb bool, ctx matchContext) bool {
	rules := finger.Rule
	expr := finger.AllString

	for _, singleRule := range rules {
		singleRuleResult := evaluateRule(singleRule, isWeb, ctx)
		if singleRuleResult {
			expr = expr[:singleRule.Start] + "T" + expr[singleRule.End:]
		} else {
			expr = expr[:singleRule.Start] + "F" + expr[singleRule.End:]
		}
	}

	return boolEval(expr)
}

func evaluateRule(singleRule structs.RuleData, isWeb bool, ctx matchContext) bool {
	switch singleRule.Key {
	case "header":
		return isWeb && dataCheckString(singleRule.Op, ctx.HeaderLower, singleRule.Value)
	case "body":
		return isWeb && dataCheckString(singleRule.Op, ctx.BodyLower, singleRule.Value)
	case "server":
		return isWeb && dataCheckString(singleRule.Op, ctx.ServerLower, singleRule.Value)
	case "title":
		return isWeb && dataCheckString(singleRule.Op, ctx.TitleLower, singleRule.Value)
	case "cert":
		return dataCheckString(singleRule.Op, ctx.CertLower, singleRule.Value)
	case "port":
		value, err := strconv.Atoi(singleRule.Value)
		return err == nil && dataCheckInt(singleRule.Op, ctx.Port, value)
	case "protocol":
		if singleRule.Op == 0 {
			return ctx.Protocol == singleRule.Value
		}
		if singleRule.Op == 1 {
			return ctx.Protocol != singleRule.Value
		}
		return false
	case "path":
		return isWeb && dataCheckString(singleRule.Op, ctx.PathLower, singleRule.Value)
	case "body_hash":
		return isWeb && dataCheckString(singleRule.Op, ctx.HashLower, singleRule.Value)
	case "icon_hash":
		value, err := strconv.Atoi(singleRule.Value)
		return isWeb && err == nil && ctx.HasIconHash && dataCheckInt(singleRule.Op, ctx.IconHash, value)
	case "status":
		value, err := strconv.Atoi(singleRule.Value)
		return isWeb && err == nil && dataCheckInt(singleRule.Op, ctx.StatusCode, value)
	case "content_type":
		return isWeb && dataCheckString(singleRule.Op, ctx.ContentTypeLower, singleRule.Value)
	case "banner":
		return dataCheckString(singleRule.Op, ctx.BannerLower, singleRule.Value)
	case "type":
		return singleRule.Value == "service"
	default:
		return false
	}
}

// shouldSkipGenericErrorFingerprint 判断响应是否是通用错误页 / 软 404
// 命中时跳过整个指纹匹配流程，避免把 nginx/tengine 等 web server 的错误页
// 误识别为某个具体应用
//
// 覆盖情况:
//  1. 4xx/5xx + title 带 HTTP Status/404 标记
//  2. 状态码 200 但 title 含 "404" / "not found" 等错误词 + body 命中软 404 body 特征
//     (典型案例: tengine/nginx 的自定义 404 页返回 200 状态码)
//  3. 内网常见空 web 服务 (IIS 默认页 / Apache "It works!" 默认页)
// ShouldSkipGenericErrorFingerprint 是 shouldSkipGenericErrorFingerprint 的导出版本
// 供外部包 (如 common/http.DirBruteCallBack) 做一致的软 404 过滤
func ShouldSkipGenericErrorFingerprint(statusCode int, title, body string) bool {
	return shouldSkipGenericErrorFingerprint(statusCode, title, body)
}

func shouldSkipGenericErrorFingerprint(statusCode int, title, body string) bool {
	titleLower := strings.ToLower(strings.TrimSpace(title))
	bodyLower := strings.ToLower(body)

	// === 规则 1: 4xx/5xx 错误页 ===
	if statusCode >= 400 && statusCode < 600 {
		if strings.HasPrefix(titleLower, "http status ") && strings.Contains(bodyLower, "<h1>http status ") {
			return true
		}
		if strings.Contains(titleLower, "404 not found") && len(bodyLower) < 1024 {
			return true
		}
		// title 包含错误标识的短响应
		if isErrorLikeTitle(titleLower) && len(body) < 4096 {
			if isErrorLikeBody(bodyLower) {
				return true
			}
		}
		// 404 状态码无论 title/body 怎样都不产生指纹
		if statusCode == 404 || statusCode == 410 {
			return true
		}
	}

	// === 规则 2: 200 但实际是软 404 ===
	if statusCode == 200 {
		if isErrorLikeTitle(titleLower) && isErrorLikeBody(bodyLower) {
			return true
		}
	}

	return false
}

// isErrorLikeTitle title 是否看起来是错误页
func isErrorLikeTitle(titleLower string) bool {
	if titleLower == "" {
		return false
	}
	markers := []string{
		"404",
		"not found",
		"未找到",
		"找不到",
		"page not found",
		"500 internal",
		"502 bad gateway",
		"503 service",
		"bad gateway",
		"gateway time-out",
		"service unavailable",
	}
	for _, m := range markers {
		if strings.Contains(titleLower, m) {
			return true
		}
	}
	return false
}

// isErrorLikeBody body 是否含常见错误页关键词
func isErrorLikeBody(bodyLower string) bool {
	if bodyLower == "" {
		return false
	}
	markers := []string{
		"sorry for the inconvenience",
		"带来不便敬请谅解",
		"the page you requested",
		"the requested url was not found",
		"找不到您请求的页面",
		"您请求的资源",
		"page not found",
		"404 not found",
		"please report this message",
		"请举报此消息",
		"report this message",
	}
	for _, m := range markers {
		if strings.Contains(bodyLower, m) {
			return true
		}
	}
	return false
}
