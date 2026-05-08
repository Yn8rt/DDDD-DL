package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"dddd/common/callnuclei"
	commonhttp "dddd/common/http"
	"dddd/common/report"
	"dddd/lib/ddfinger"
	structs "dddd/structs"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx"
	"github.com/projectdiscovery/httpx/runner"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"gopkg.in/yaml.v2"
)

// PassiveScanProxy 被动扫描代理服务器
type PassiveScanProxy struct {
	server         *http.Server
	port           int
	targetChan     chan string     // 目标提取通道
	scanned        map[string]bool // 已扫描目标去重
	scannedMux     sync.Mutex
	skipExtensions map[string]bool // 后缀黑名单
	blackFingerMap map[string]bool // 指纹黑名单
}

// NewPassiveScanProxy 创建被动扫描代理实例
func NewPassiveScanProxy(port int) *PassiveScanProxy {
	// 解析后缀黑名单
	skipExts := make(map[string]bool)
	extList := strings.Split(structs.GlobalConfig.ProxySkipExtensions, ",")
	for _, ext := range extList {
		ext = strings.TrimSpace(ext)
		if ext != "" {
			skipExts[strings.ToLower(ext)] = true
		}
	}

	// 创建代理实例
	proxy := &PassiveScanProxy{
		port:           port,
		targetChan:     make(chan string, 100), // 缓冲通道，避免阻塞
		scanned:        make(map[string]bool),
		skipExtensions: skipExts,
		blackFingerMap: make(map[string]bool),
	}

	// 加载指纹黑名单
	proxy.blackFingerMap = proxy.loadBlackFinger()

	return proxy
}

// Start 启动代理服务器
func (p *PassiveScanProxy) Start() error {
	// 创建多路复用 TCP 监听器，监听所有接口
	addr := fmt.Sprintf(":%d", p.port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("无法监听端口 %d: %v", p.port, err)
	}

	gologger.Info().Msgf("被动扫描代理已启动，监听端口: %d", p.port)
	gologger.Info().Msgf("请配置代理: http://127.0.0.1:%d", p.port)
	gologger.Info().Msgf("跳过后缀: %s", structs.GlobalConfig.ProxySkipExtensions)

	// 启动目标处理协程
	go p.processTargets()

	// 接受并处理连接
	for {
		conn, err := listener.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return nil
			}
			continue
		}
		go p.handleConnection(conn)
	}
}

// handleConnection 处理单个连接
func (p *PassiveScanProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// 设置读取超时
	clientConn.SetReadDeadline(time.Now().Add(120 * time.Second))
	clientConn.SetWriteDeadline(time.Now().Add(120 * time.Second))

	// 读取请求
	reader := bufio.NewReader(clientConn)

	// 读取第一行（请求行）
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	// 解析请求行
	parts := strings.Split(requestLine, " ")
	if len(parts) < 3 {
		return
	}

	method := strings.TrimSpace(parts[0])
	requestURI := strings.TrimSpace(parts[1])

	// 读取完整的请求头
	headers := make(map[string]string)
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		idx := strings.Index(line, ":")
		if idx > 0 {
			key := line[:idx]
			value := line[idx+1:]
			headers[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}

	// 处理 CONNECT 方法（HTTPS 隧道）
	if method == "CONNECT" {
		p.handleConnect(clientConn, reader, requestURI)
		return
	}

	// 处理普通 HTTP 请求
	p.handleHTTPRequest(clientConn, reader, method, requestURI, headers)
}

// handleConnect 处理 HTTPS CONNECT 隧道请求（隧道模式，不解密）
func (p *PassiveScanProxy) handleConnect(clientConn net.Conn, reader *bufio.Reader, hostPort string) {
	// 提取主机名
	host := extractHost(hostPort)
	if host == "" {
		clientConn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	// 提取目标并提交扫描（只扫描根URL，不读取具体路径）
	target := extractHost(hostPort)
	if target != "" {
		// 只提交 HTTPS 根 URL 进行扫描
		httpsURL := fmt.Sprintf("https://%s", hostPort)
		p.submitTarget(httpsURL)
	}

	// 解析目标地址
	targetAddr := hostPort
	if !strings.Contains(hostPort, ":") {
		targetAddr = hostPort + ":443"
	}

	// 连接目标服务器
	remoteConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		gologger.Warning().Msgf("[代理] 无法连接到目标 %s: %v", targetAddr, err)
		return
	}
	defer remoteConn.Close()

	// 发送 200 Connection Established 响应
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// 双向转发数据（隧道模式，不解密）
	go p.copyData(remoteConn, clientConn)
	p.copyData(clientConn, remoteConn)
}

// handleHTTPRequest 处理普通 HTTP 请求
func (p *PassiveScanProxy) handleHTTPRequest(clientConn net.Conn, reader *bufio.Reader, method, requestURI string, headers map[string]string) {
	// 提取 Host
	host := headers["Host"]
	if host == "" {
		// 尝试从 requestURI 提取
		if strings.HasPrefix(requestURI, "http://") {
			uri := requestURI[7:]
			idx := strings.Index(uri, "/")
			if idx > 0 {
				host = uri[:idx]
			} else {
				host = uri
			}
		} else if strings.HasPrefix(requestURI, "https://") {
			uri := requestURI[8:]
			idx := strings.Index(uri, "/")
			if idx > 0 {
				host = uri[:idx]
			} else {
				host = uri
			}
		}
	}

	if host == "" {
		clientConn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	// 提取完整 URL 并提交扫描
	var fullURL string
	if strings.HasPrefix(requestURI, "http://") || strings.HasPrefix(requestURI, "https://") {
		fullURL = requestURI
	} else {
		fullURL = fmt.Sprintf("http://%s%s", host, requestURI)
	}
	p.submitTarget(fullURL)

	// 解析目标地址
	targetHost := host
	if !strings.Contains(host, ":") {
		targetHost = host + ":80"
	}

	// 连接目标服务器
	remoteConn, err := net.DialTimeout("tcp", targetHost, 10*time.Second)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		gologger.Warning().Msgf("[代理] 无法连接到目标 %s: %v", targetHost, err)
		return
	}
	defer remoteConn.Close()

	// 设置远程连接超时
	remoteConn.SetDeadline(time.Now().Add(120 * time.Second))

	// 构建并发送 HTTP 请求到目标服务器
	var requestBuf bytes.Buffer

	// 请求行
	fmt.Fprintf(&requestBuf, "%s %s HTTP/1.1\r\n", method, requestURI)

	// 请求头
	for k, v := range headers {
		if strings.ToLower(k) != "proxy-connection" && strings.ToLower(k) != "proxy-authorization" {
			fmt.Fprintf(&requestBuf, "%s: %s\r\n", k, v)
		}
	}
	// 添加 Connection: close 或保持原有
	if headers["Connection"] != "" {
		fmt.Fprintf(&requestBuf, "Connection: %s\r\n", headers["Connection"])
	} else {
		fmt.Fprintf(&requestBuf, "Connection: close\r\n")
	}
	fmt.Fprintf(&requestBuf, "\r\n")

	// 发送请求头
	if _, err := remoteConn.Write(requestBuf.Bytes()); err != nil {
		gologger.Warning().Msgf("[代理] 发送请求头失败: %v", err)
		return
	}

	// 检查是否有请求体
	if contentLength, ok := headers["Content-Length"]; ok {
		// 读取并转发请求体
		body := make([]byte, 1024)
		length := 0
		for {
			n, err := reader.Read(body)
			if n > 0 {
				if _, err := remoteConn.Write(body[:n]); err != nil {
					return
				}
				length += n
			}
			if err != nil || length >= parseInt(contentLength) {
				break
			}
		}
	} else if strings.ToUpper(headers["Transfer-Encoding"]) == "CHUNKED" {
		// 处理分块编码
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if _, err := remoteConn.Write([]byte(line)); err != nil {
				return
			}
			if strings.TrimSpace(line) == "0" {
				// 读取结束标记后的 \r\n
				reader.ReadString('\n')
				remoteConn.Write([]byte("\r\n"))
				break
			}
		}
	}

	// 从目标服务器读取响应并转发给客户端
	p.forwardResponse(remoteConn, clientConn)
}

// forwardResponse 转发HTTP响应
func (p *PassiveScanProxy) forwardResponse(src, dst net.Conn) {
	// 使用bufio按行读取响应
	reader := bufio.NewReader(src)

	// 读取状态行
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	dst.Write([]byte(statusLine))

	// 读取响应头
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" {
			dst.Write([]byte("\r\n"))
			break
		}
		dst.Write([]byte(line))
	}

	// 转发响应体
	io.Copy(dst, reader)
}

// copyData 双向转发数据（用于 HTTPS 隧道）
func (p *PassiveScanProxy) copyData(dst, src net.Conn) {
	defer dst.Close()
	defer src.Close()

	_, _ = io.Copy(dst, src)
}

// shouldSkip 检查URL是否应该被跳过（基于后缀黑名单）
func (p *PassiveScanProxy) shouldSkip(targetURL string) bool {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return false
	}

	// 提取路径后缀
	path := parsedURL.Path
	if path == "" || path == "/" {
		return false
	}

	// 获取文件扩展名
	lastDot := strings.LastIndex(path, ".")
	if lastDot == -1 {
		return false
	}

	// 提取扩展名（从点之后到结尾，不包含路径分隔符）
	ext := path[lastDot+1:]

	// 扩展名不能包含路径分隔符
	if strings.Contains(ext, "/") {
		return false
	}

	ext = strings.ToLower(ext)

	// 检查是否在黑名单中
	skip := p.skipExtensions[ext]
	if skip {
		gologger.Debug().Msgf("[代理] 跳过后缀 %s: %s", ext, targetURL)
	}

	return skip
}

// submitTarget 提交目标到扫描通道
func (p *PassiveScanProxy) submitTarget(target string) {
	// 规范化目标
	target = strings.TrimSpace(target)
	if target == "" {
		return
	}

	// 检查后缀黑名单
	if p.shouldSkip(target) {
		return
	}

	// 检查是否已扫描
	p.scannedMux.Lock()
	if p.scanned[target] {
		p.scannedMux.Unlock()
		return
	}
	p.scanned[target] = true
	p.scannedMux.Unlock()

	// 发送到通道
	select {
	case p.targetChan <- target:
		gologger.Info().Msgf("[代理] 提取目标: %s", target)
	default:
		gologger.Warning().Msgf("目标通道已满，丢弃目标: %s", target)
	}
}

// processTargets 处理提取的目标（异步不阻塞）
func (p *PassiveScanProxy) processTargets() {
	// 限制并发扫描数，避免资源耗尽
	semaphore := make(chan struct{}, 3) // 最多同时扫描3个目标

	for target := range p.targetChan {
		go func(t string) {
			semaphore <- struct{}{}        // 获取信号量
			defer func() { <-semaphore }() // 释放信号量

			// 异步扫描，不阻塞其他目标
			p.scanTarget(t)
		}(target)
	}
}

// scanTarget 扫描单个目标
func (p *PassiveScanProxy) scanTarget(target string) {
	// 添加恢复机制，确保panic不会导致程序崩溃
	defer func() {
		if r := recover(); r != nil {
			gologger.Warning().Msgf("[!] 扫描异常: %v", r)
		}
	}()

	// 解析目标URL
	parsedURL, err := url.Parse(target)
	if err != nil {
		gologger.Warning().Msgf("目标URL解析失败: %v", err)
		return
	}

	// 构造标准化的目标
	normalizedTarget := target
	if parsedURL.Scheme == "" {
		normalizedTarget = "http://" + target
	}

	// 获取根URL
	rootURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	isRootOnly := (normalizedTarget == rootURL)

	gologger.Info().Msgf("")
	gologger.Info().Msgf(aurora.BrightCyan("[-] 开始扫描: %s").String(), normalizedTarget)

	// 1. 使用 httpx 获取HTTP响应
	gologger.Info().Msgf("[*] 正在获取HTTP响应...")
	httpx.CallHTTPx([]string{normalizedTarget}, p.urlCallBack,
		structs.GlobalConfig.HTTPProxy,
		structs.GlobalConfig.WebThreads,
		structs.GlobalConfig.WebTimeout,
	)

	// 如果是HTTPS根目标（隧道模式），需要进行路径探测
	if isRootOnly && parsedURL.Scheme == "https" && !structs.GlobalConfig.NoDirSearch {
		gologger.Info().Msgf("[*] HTTPS根目标，开始路径探测...")

		// 构造路径探测列表（从 DirDB 获取）
		var checkURLs []string
		for dbPath, _ := range structs.DirDB {
			checkURLs = append(checkURLs, rootURL+dbPath)
		}

		if len(checkURLs) > 0 {
			gologger.Info().Msgf("[*] 探测 %d 个常见路径...", len(checkURLs))
			httpx.DirBrute(checkURLs, p.dirBruteCallBack,
				structs.GlobalConfig.HTTPProxy,
				structs.GlobalConfig.WebThreads,
				structs.GlobalConfig.WebTimeout,
			)
		}
	}

	gologger.Info().Msgf("[+] HTTP响应获取完成")

	// 2. 指纹识别
	gologger.Info().Msgf("[*] 正在进行指纹识别...")
	ddfinger.FingerprintIdentification()

	// 展示识别到的指纹
	if fingerprints, ok := structs.GlobalResultMap[normalizedTarget]; ok && len(fingerprints) > 0 {
		gologger.Info().Msgf(aurora.Green("[+] 识别到指纹 (%d): %s").String(), len(fingerprints), strings.Join(fingerprints, ", "))
	} else {
		// 检查是否有子路径的指纹
		hasFingerprint := false
		for key, fingerprints := range structs.GlobalResultMap {
			if strings.HasPrefix(key, normalizedTarget) && len(fingerprints) > 0 {
				gologger.Info().Msgf(aurora.Green("[+] %s 识别到指纹 (%d): %s").String(), key, len(fingerprints), strings.Join(fingerprints, ", "))
				hasFingerprint = true
			}
		}
		if !hasFingerprint {
			gologger.Info().Msgf(aurora.Yellow("[-] 未识别到指纹").String())
		}
	}

	// 3. 漏洞扫描（使用全局黑名单过滤）
	if !structs.GlobalConfig.NoPoc {
		// 使用带黑名单过滤的 GetPocs（现在 GetPocs 内部已经使用全局黑名单）
		TargetAndPocsName, count := commonhttp.GetPocs(structs.WorkFlowDB)

		if count > 0 {
			gologger.Info().Msgf(aurora.BrightCyan("[*] 准备调用 POC (%d 个)").String(), count)

			param := callnuclei.NucleiParams{
				TargetAndPocsName: TargetAndPocsName,
				Proxy:             structs.GlobalConfig.HTTPProxy,
				CallBack: func(result output.ResultEvent) {
					// 结果回调
					if result.Type == "vulnerability" {
						severity := ""
						severityStr := result.Info.SeverityHolder.Severity.String()
						if severityStr != "" && severityStr != "unknown" {
							severity = fmt.Sprintf(" [%s]", severityStr)
						}
						gologger.Info().Msgf("")
						gologger.Info().Msgf(aurora.BrightRed("[!] 发现漏洞!").String())
						gologger.Info().Msgf(aurora.Red("    模板ID: %s%s").String(), result.TemplateID, severity)
						gologger.Info().Msgf(aurora.Red("    目标: %s").String(), result.Host)
						if result.Info.Name != "" {
							gologger.Info().Msgf(aurora.Red("    漏洞名称: %s").String(), result.Info.Name)
						}
						report.AddResultByResultEvent(result)
					}
				},
				NameForSearch:    structs.GlobalConfig.PocNameForSearch,
				NoInteractsh:     structs.GlobalConfig.NoInteractsh,
				Fs:               structs.GlobalEmbedPocs,
				NP:               structs.GlobalConfig.NucleiTemplate,
				ExcludeTags:      strings.Split(structs.GlobalConfig.ExcludeTags, ","),
				Severities:       strings.Split(structs.GlobalConfig.Severities, ","),
				InteractshServer: structs.GlobalConfig.InteractshURL,
				InteractshToken:  structs.GlobalConfig.InteractshToken,
			}

			callnuclei.CallNuclei(param)
		} else {
			gologger.Info().Msgf(aurora.Yellow("[-] 该指纹未配置对应 POC，跳过漏洞扫描").String())
		}
	} else {
		gologger.Info().Msgf(aurora.Yellow("[-] 漏洞扫描已禁用 (-npoc)").String())
	}

	gologger.Info().Msgf(aurora.BrightGreen("[✓] 扫描完成: %s").String(), normalizedTarget)
}

// dirBruteCallBack 路径爆破回调函数
func (p *PassiveScanProxy) dirBruteCallBack(resp runner.Result) {
	// 复用主动扫描的回调逻辑
	p.urlCallBack(resp)
}

// urlCallBack httpx 回调函数，用于填充 GlobalURLMap
func (p *PassiveScanProxy) urlCallBack(resp runner.Result) {
	finalUrl := ""
	if resp.FinalURL != "" {
		finalUrl = resp.FinalURL
	} else {
		finalUrl = resp.URL
	}

	url, err := url.Parse(finalUrl)
	if err != nil {
		return
	}
	commonhttp.StoreURLResult(resp, url.String())
}

// getTLSString 从 TLSData 中提取证书信息
func (p *PassiveScanProxy) getTLSString(resp runner.Result) string {
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

// Stop 停止代理服务器
func (p *PassiveScanProxy) Stop() error {
	// 由于使用的是自定义监听器，不需要调用 server.Close()
	return nil
}

// GetTargetChannel 获取目标通道（供外部使用）
func (p *PassiveScanProxy) GetTargetChannel() <-chan string {
	return p.targetChan
}

// extractHost 从 host 中提取主机名（去除端口和路径）
func extractHost(host string) string {
	host = strings.TrimSpace(host)

	// 去除协议前缀
	if strings.HasPrefix(host, "http://") {
		host = host[7:]
	} else if strings.HasPrefix(host, "https://") {
		host = host[8:]
	}

	// 去除路径
	idx := strings.Index(host, "/")
	if idx > 0 {
		host = host[:idx]
	}

	// 去除端口
	idx = strings.Index(host, ":")
	if idx > 0 {
		host = host[:idx]
	}

	// 去除用户名密码
	idx = strings.Index(host, "@")
	if idx > 0 {
		host = host[idx+1:]
	}

	return host
}

// parseInt 解析整数
func parseInt(s string) int {
	var result int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			result = result*10 + int(c-'0')
		} else {
			break
		}
	}
	return result
}

// loadBlackFinger 加载指纹黑名单
func (p *PassiveScanProxy) loadBlackFinger() map[string]bool {
	blackFingerMap := make(map[string]bool)

	// 如果用户指定了自定义黑名单文件，优先使用
	if structs.GlobalConfig.ProxyBlackFingerFile != "" && structs.GlobalConfig.ProxyBlackFingerFile != "embedded" {
		data, err := os.ReadFile(structs.GlobalConfig.ProxyBlackFingerFile)
		if err == nil {
			// 解析 YAML
			type BlackFingerConfig struct {
				Blacklist []string `yaml:"blacklist"`
			}
			var config BlackFingerConfig
			err = yaml.Unmarshal(data, &config)
			if err == nil {
				for _, finger := range config.Blacklist {
					finger = strings.TrimSpace(finger)
					if finger != "" {
						blackFingerMap[strings.ToLower(finger)] = true
					}
				}
				if len(blackFingerMap) > 0 {
					gologger.Info().Msgf("[代理] 已从自定义文件加载 %d 个指纹黑名单", len(blackFingerMap))
				}
				return blackFingerMap
			}
		}
		gologger.Warning().Msgf("[代理] 无法读取自定义黑名单文件，使用默认黑名单")
	}

	if len(structs.GlobalBlackFingerMap) > 0 {
		for finger := range structs.GlobalBlackFingerMap {
			blackFingerMap[finger] = true
		}
		gologger.Info().Msgf("[代理] 已加载内嵌指纹黑名单 (%d 个)", len(blackFingerMap))
		return blackFingerMap
	}

	// 使用硬编码的默认黑名单
	defaultBlacklist := []string{
		// 常见前端框架
		"jquery", "jquery-ui", "bootstrap", "ubuntu-system",
		// 常见编程语言和框架
		"jsp", "php", "javascript", "asp", "aspx", "java", "python",
		"django", "flask", "node.js", "asp.net",
		// 常见Web服务器
		"nginx", "iis", "apache-web-server", "apache-http-server-centos", "struts2",
		// 操作系统和数据库
		"windows", "mysql",
		// 其他通用组件
		"openssl", "google-webmaster-platform",
		// 其他常见指纹
		"springboot", "tomcat", "jetty", "react", "vue.js", "angular",
	}

	for _, finger := range defaultBlacklist {
		blackFingerMap[strings.ToLower(finger)] = true
	}

	gologger.Info().Msgf("[代理] 已加载默认指纹黑名单 (%d 个)", len(blackFingerMap))
	return blackFingerMap
}
