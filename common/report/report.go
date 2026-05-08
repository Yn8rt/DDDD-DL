package report

import (
	"dddd/ddout"
	"dddd/structs"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

func getSeverity(s severity.Severity) string {
	if s == severity.Info {
		return "Info"
	} else if s == severity.Low {
		return "Low"
	} else if s == severity.Medium {
		return "Medium"
	} else if s == severity.High {
		return "High"
	} else if s == severity.Critical {
		return "Critical"
	} else if s == severity.Unknown {
		return "Unknown"
	}
	return "Unknown"
}

func writeFile(result string, filename string) {
	var text = []byte(result)
	fl, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("Open %s error, %v\n", filename, err)
		return
	}
	_, err = fl.Write(text)
	fl.Close()
	if err != nil {
		fmt.Printf("Write %s error, %v\n", filename, err)
	}
}

var ReportIndex = 1
var nucleiResultSeen map[string]struct{}
var nucleiResultSeenLock sync.Mutex
var reportInitialized bool
var reportFinalized bool
var apiUnauthResults []ddout.OutputMessage
var apiUnauthScanResults []ddout.OutputMessage
var apiUnauthResultsLock sync.Mutex

func GenerateHTMLReportHeader() {
	if structs.GlobalConfig.ReportName == "" {
		structs.GlobalConfig.ReportName = strconv.Itoa(int(time.Now().Unix())) + ".html"
	}
	if reportInitialized {
		return
	}
	nucleiResultSeenLock.Lock()
	nucleiResultSeen = make(map[string]struct{})
	nucleiResultSeenLock.Unlock()
	apiUnauthResultsLock.Lock()
	apiUnauthResults = nil
	apiUnauthScanResults = nil
	apiUnauthResultsLock.Unlock()
	reportInitialized = true
	reportFinalized = false
	_ = os.Remove(structs.GlobalConfig.ReportName)
	showData := defaultHeader()
	writeFile(showData, structs.GlobalConfig.ReportName)
}

func AddAPIUnauthResult(result ddout.OutputMessage) {
	GenerateHTMLReportHeader()

	apiUnauthResultsLock.Lock()
	defer apiUnauthResultsLock.Unlock()
	for _, existing := range apiUnauthResults {
		if existing.URI == result.URI {
			return
		}
	}
	apiUnauthResults = append(apiUnauthResults, result)
}

func AddAPIUnauthScanResult(result ddout.OutputMessage) {
	GenerateHTMLReportHeader()

	apiUnauthResultsLock.Lock()
	defer apiUnauthResultsLock.Unlock()
	for _, existing := range apiUnauthScanResults {
		if existing.URI == result.URI {
			return
		}
	}
	apiUnauthScanResults = append(apiUnauthScanResults, result)
}

func shouldSkipNucleiResult(result output.ResultEvent) bool {
	key := fmt.Sprintf("%s|%s|%s|%s", result.TemplateID, result.Host, result.Matched, strings.Join(result.ExtractedResults, ","))

	nucleiResultSeenLock.Lock()
	defer nucleiResultSeenLock.Unlock()

	if _, ok := nucleiResultSeen[key]; ok {
		return true
	}
	nucleiResultSeen[key] = struct{}{}
	return false
}

func AddResultByResultEvent(result output.ResultEvent) {
	if structs.GlobalConfig.ReportName == "" {
		return
	}
	if shouldSkipNucleiResult(result) {
		return
	}

	severityString := getSeverity(result.Info.SeverityHolder.Severity)

	title := fmt.Sprintf(`<table>
	<thead onclick="$(this).next('tbody').toggle()" style="background:#000000">
		<td class="vuln">%v&nbsp;&nbsp;%s</td>
		<td class="security %s">%s</td>
		<td class="url">%s</td>
	</thead>`, ReportIndex, result.TemplateID, strings.ToLower(severityString), strings.ToUpper(severityString), result.Host)

	info := fmt.Sprintf("<b>name:</b> %s&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<b>author:</b> %s&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<b>security:</b> %s",
		result.Info.Name, result.Info.Authors.String(), severityString,
	)
	if len(result.Info.Description) > 0 {
		info += "<br/><b>description:</b> " + result.Info.Description
	}

	if result.Info.Reference != nil && len(result.Info.Reference.ToSlice()) > 0 {
		info += "<br/><b>reference:</b> "
		for _, rv := range result.Info.Reference.ToSlice() {
			info += "<br/>&nbsp;&nbsp;- <a href='" + rv + "' target='_blank'>" + rv + "</a>"
		}
	}

	header := "<tbody>"

	bodyinfo := fmt.Sprintf(`<tr>
			<td colspan="3">%s</td>
		</tr>`, info)

	fullurl := xssfilter(result.Matched)

	footer := "</tbody></table>"
	d := title + header + bodyinfo

	urlShow := `<tr>
		<td colspan="3"  style="border-top:1px solid #60786F"><a href="` + fullurl + `" target="_blank">` + fullurl + `</a></td>
	</tr><tr>`

	bodyHeader := `
			<td colspan="3" style="background: #1c1b19; color: #048d18;">
				<div class="clr">
				<div class="request w50">
				<div class="toggleR" onclick="$(this).parent().next('.response').toggle();if($(this).text()=='→'){$(this).text('←');$(this).css('background','red');$(this).parent().removeClass('w50').addClass('w100')}else{$(this).text('→');$(this).css('background','black');$(this).parent().removeClass('w100').addClass('w50')}">→</div>
<xmp>%s</xmp>
				</div>
				<div class="response w50">
				<div class="toggleL" onclick="$(this).parent().prev('.request').toggle();if($(this).text()=='←'){$(this).text('→');$(this).css('background','red');$(this).parent().removeClass('w50').addClass('w100')}else{$(this).text('←');$(this).css('background','black');$(this).parent().removeClass('w100').addClass('w50')}">←</div>
<xmp>%s</xmp>
				</div>
			</div>
			</td>
		</tr>
	`

	if len(result.Packet) == 0 {
		body := urlShow + fmt.Sprintf(bodyHeader, result.Request, result.Response)
		d += body
	} else {
		for index, v := range result.Packet {
			if index == 1 {
				d += urlShow
			} else {
				d += "<tr><td colspan=\"3\"  style=\"border-top:1px solid #60786F\"></td></tr>"
			}
			body := fmt.Sprintf(bodyHeader, v.Request, v.Response)
			d += body
		}
	}

	d += footer

	writeFile(d, structs.GlobalConfig.ReportName)

	ReportIndex += 1
}

func AddResultByGoPocResult(result structs.GoPocsResultType) {
	severityString := result.Security

	title := fmt.Sprintf(`<table>
	<thead onclick="$(this).next('tbody').toggle()" style="background:#000000">
		<td class="vuln">%v&nbsp;&nbsp;%s</td>
		<td class="security %s">%s</td>
		<td class="url">%s</td>
	</thead>`, ReportIndex, result.PocName, strings.ToLower(severityString), strings.ToUpper(severityString), result.Target)

	info := ""
	if result.Description != "" {
		info = "<br/><b>description:</b> " + result.Description
	}

	header := "<tbody>"

	bodyinfo := fmt.Sprintf(`<tr>
			<td colspan="3">%s</td>
		</tr>`, info)

	body := fmt.Sprintf(`<tr>
		<td colspan="3"  style="border-top:1px solid #60786F"><a href="%s" target="_blank">%s</a></td>
	</tr><tr>
			<td colspan="3" style="background: #1c1b19; color: #048d18;">
				<div class="clr">
				<div class="request w50">
				<div class="toggleR" onclick="$(this).parent().next('.response').toggle();if($(this).text()=='→'){$(this).text('←');$(this).css('background','red');$(this).parent().removeClass('w50').addClass('w100')}else{$(this).text('→');$(this).css('background','black');$(this).parent().removeClass('w100').addClass('w50')}">→</div>
<xmp>%s</xmp>
				</div>
				<div class="response w50">
				<div class="toggleL" onclick="$(this).parent().prev('.request').toggle();if($(this).text()=='←'){$(this).text('→');$(this).css('background','red');$(this).parent().removeClass('w50').addClass('w100')}else{$(this).text('←');$(this).css('background','black');$(this).parent().removeClass('w100').addClass('w50')}">←</div>
<xmp>%s</xmp>
				</div>
			</div>
			</td>
		</tr>
	`, result.Target, result.Target, xssfilter(result.InfoLeft), xssfilter(result.InfoRight))

	footer := "</tbody></table>"
	d := title + header + bodyinfo + body + footer
	writeFile(d, structs.GlobalConfig.ReportName)

	ReportIndex += 1
}

// AddFingerprintSection 添加指纹分类展示区域
// 将指纹分类内容插入到指纹标签页中
type fingerprintGroup struct {
	Name      string
	URLs      []string
	URLInfos  []urlInfo
	Count     int
	IsUnknown bool
}

type urlInfo struct {
	URL        string
	StatusCode int
	Title      string
}

func AddFingerprintSection() {
	if structs.GlobalConfig.ReportName == "" {
		return
	}
	if reportFinalized {
		return
	}
	if !reportInitialized {
		GenerateHTMLReportHeader()
	}

	apiUnauthResultsLock.Lock()
	apiResults := make([]ddout.OutputMessage, len(apiUnauthResults))
	copy(apiResults, apiUnauthResults)
	apiScanResults := make([]ddout.OutputMessage, len(apiUnauthScanResults))
	copy(apiScanResults, apiUnauthScanResults)
	apiUnauthResultsLock.Unlock()

	fingerprintGroups := make(map[string][]urlInfo)
	identifiedURLs := make(map[string]bool)

	for url, fingerprints := range structs.GlobalResultMap {
		if len(fingerprints) == 0 {
			statusCode, title := getURLInfo(url)
			fingerprintGroups["未识别"] = append(fingerprintGroups["未识别"], urlInfo{
				URL:        url,
				StatusCode: statusCode,
				Title:      title,
			})
		} else {
			for _, fp := range fingerprints {
				fingerprintGroups[fp] = append(fingerprintGroups[fp], urlInfo{URL: url})
			}
			identifiedURLs[url] = true
		}
	}

	var sortedGroups []fingerprintGroup
	for name, urls := range fingerprintGroups {
		isUnknown := name == "未识别"
		sortedGroups = append(sortedGroups, fingerprintGroup{
			Name:      name,
			URLs:      extractURLs(urls),
			URLInfos:  urls,
			Count:     len(urls),
			IsUnknown: isUnknown,
		})
	}

	sort.Slice(sortedGroups, func(i, j int) bool {
		if sortedGroups[i].IsUnknown {
			return false
		}
		if sortedGroups[j].IsUnknown {
			return true
		}
		return sortedGroups[i].Count > sortedGroups[j].Count
	})

	totalURLs := len(structs.GlobalResultMap)
	identifiedCount := len(identifiedURLs)
	unidentifiedCount := totalURLs - identifiedCount
	totalFingerprints := len(fingerprintGroups)
	if _, ok := fingerprintGroups["未识别"]; ok {
		totalFingerprints--
	}

	var html strings.Builder
	html.WriteString(`</div>
		<div id="tab-api-unauth" class="tab-content">
		<div class="fingerprint-section">
		<h2 class="fingerprint-title">API-Unauth 结果分组</h2>
		<div class="fingerprint-stats">
			<div class="stats-row">
				<span class="stats-label">扫描目标：</span><span class="highlight">`)
	html.WriteString(fmt.Sprintf("%d", len(apiScanResults)))
	html.WriteString(`</span>
				<span class="stats-separator">|</span>
				<span class="stats-label">疑似未授权目标：</span><span class="highlight red">`)
	html.WriteString(fmt.Sprintf("%d", len(apiResults)))
	html.WriteString(`</span>
			</div>
		</div>`)

	if len(apiScanResults) > 0 {
		html.WriteString(`<div class="fingerprint-list">
			<h3 class="list-title">未授权扫描明细</h3>
			<div class="fingerprint-item">
				<div class="fingerprint-header" onclick="$(this).next('.fingerprint-urls').toggle();$(this).find('.toggle-icon').toggleClass('rotated')">
					<span class="fingerprint-name">全部扫描目标</span>
					<span class="fingerprint-count">`)
		html.WriteString(fmt.Sprintf("%d", len(apiScanResults)))
		html.WriteString(` 个URL</span>
					<span class="toggle-icon">▼</span>
				</div>
				<div class="fingerprint-urls" style="display:none;">
					<table class="url-table">
						<thead>
							<tr><th>URL</th><th>状态码</th><th>标题</th><th>来源</th></tr>
						</thead>
						<tbody>`)
		for _, result := range apiScanResults {
			statusCode, _ := strconv.Atoi(result.Web.Status)
			statusClass := "status-ok"
			if statusCode >= 400 {
				statusClass = "status-error"
			} else if statusCode >= 300 {
				statusClass = "status-redirect"
			}
			html.WriteString(`<tr>
				<td><a href="`)
			html.WriteString(xssfilter(result.URI))
			html.WriteString(`" target="_blank">`)
			html.WriteString(xssfilter(result.URI))
			html.WriteString(`</a></td>
				<td class="`)
			html.WriteString(statusClass)
			html.WriteString(`">`)
			html.WriteString(xssfilter(result.Web.Status))
			html.WriteString(`</td>
				<td>`)
			html.WriteString(xssfilter(result.Web.Title))
			html.WriteString(`</td>
				<td>`)
			html.WriteString(xssfilter(result.AdditionalMsg))
			html.WriteString(`</td>
			</tr>`)
		}
		html.WriteString(`</tbody></table></div></div></div>`)
	}

	if len(apiResults) == 0 {
		html.WriteString(`<div class="fingerprint-item">
			<div class="fingerprint-header">
				<span class="fingerprint-name">当前无 API-Unauth 命中结果</span>
			</div>
		</div>`)
	} else {
		html.WriteString(`<div class="fingerprint-list"><h3 class="list-title">疑似未授权命中</h3>`)
		sourceGroups := make(map[string][]ddout.OutputMessage)
		for _, result := range apiResults {
			source := result.AdditionalMsg
			if source == "" {
				source = "Katana"
			}
			sourceGroups[source] = append(sourceGroups[source], result)
		}

		type apiGroup struct {
			Name    string
			Results []ddout.OutputMessage
			Count   int
		}

		var sortedAPIGroups []apiGroup
		for name, results := range sourceGroups {
			sortedAPIGroups = append(sortedAPIGroups, apiGroup{
				Name:    name,
				Results: results,
				Count:   len(results),
			})
		}
		sort.Slice(sortedAPIGroups, func(i, j int) bool {
			if sortedAPIGroups[i].Count == sortedAPIGroups[j].Count {
				return sortedAPIGroups[i].Name < sortedAPIGroups[j].Name
			}
			return sortedAPIGroups[i].Count > sortedAPIGroups[j].Count
		})

		html.WriteString(`<div class="fingerprint-list">`)
		for _, group := range sortedAPIGroups {
			html.WriteString(`<div class="fingerprint-item">
				<div class="fingerprint-header" onclick="$(this).next('.fingerprint-urls').toggle();$(this).find('.toggle-icon').toggleClass('rotated')">
					<span class="fingerprint-name">`)
			html.WriteString(xssfilter(group.Name))
			html.WriteString(`</span>
					<span class="fingerprint-count">`)
			html.WriteString(fmt.Sprintf("%d", group.Count))
			html.WriteString(` 个结果</span>
					<span class="toggle-icon">▼</span>
				</div>
				<div class="fingerprint-urls" style="display:none;">
					<table class="url-table">
						<thead>
							<tr><th>URL</th><th>状态码</th><th>标题</th></tr>
						</thead>
						<tbody>`)
			for _, result := range group.Results {
				statusCode, _ := strconv.Atoi(result.Web.Status)
				statusClass := "status-ok"
				if statusCode >= 400 {
					statusClass = "status-error"
				} else if statusCode >= 300 {
					statusClass = "status-redirect"
				}
				html.WriteString(`<tr>
					<td><a href="`)
				html.WriteString(xssfilter(result.URI))
				html.WriteString(`" target="_blank">`)
				html.WriteString(xssfilter(result.URI))
				html.WriteString(`</a></td>
					<td class="`)
				html.WriteString(statusClass)
				html.WriteString(`">`)
				html.WriteString(xssfilter(result.Web.Status))
				html.WriteString(`</td>
					<td>`)
				html.WriteString(xssfilter(result.Web.Title))
				html.WriteString(`</td>
				</tr>`)
			}
			html.WriteString(`</tbody></table></div></div>`)
		}
		html.WriteString(`</div>`)
	}

	html.WriteString(`</div>
		</div>
		<div id="tab-fingerprint" class="tab-content">
		<div class="fingerprint-section">
		<h2 class="fingerprint-title">指纹分类统计</h2>
		<div class="fingerprint-stats">
			<div class="stats-row">
				<span class="stats-label">总URL数：</span><span class="highlight">`)
	html.WriteString(fmt.Sprintf("%d", totalURLs))
	html.WriteString(`</span>
			</div>
			<div class="stats-row">
				<span class="stats-label">已识别：</span><span class="highlight green">`)
	html.WriteString(fmt.Sprintf("%d", identifiedCount))
	html.WriteString(`</span>
				<span class="stats-separator">|</span>
				<span class="stats-label">未识别：</span><span class="highlight yellow">`)
	html.WriteString(fmt.Sprintf("%d", unidentifiedCount))
	html.WriteString(`</span>
			</div>
			<div class="stats-row">
				<span class="stats-label">指纹种类：</span><span class="highlight">`)
	html.WriteString(fmt.Sprintf("%d", totalFingerprints))
	html.WriteString(`</span>
			</div>
		</div>`)

	if len(sortedGroups) > 0 {
		maxCount := sortedGroups[0].Count
		if maxCount > 0 {
			html.WriteString(`<div class="fingerprint-chart">
				<h3 class="chart-title">Top 指纹分布</h3>`)
			topCount := 10
			if len(sortedGroups) < topCount {
				topCount = len(sortedGroups)
			}
			for i := 0; i < topCount; i++ {
				g := sortedGroups[i]
				if g.IsUnknown {
					continue
				}
				percentage := float64(g.Count) / float64(maxCount) * 100
				html.WriteString(`<div class="chart-item">
					<div class="chart-label">`)
				html.WriteString(xssfilter(g.Name))
				html.WriteString(`</div>
					<div class="chart-bar-container">
						<div class="chart-bar" style="width: `)
				html.WriteString(fmt.Sprintf("%.1f%%", percentage))
				html.WriteString(`"></div>
					</div>
					<div class="chart-count">`)
				html.WriteString(fmt.Sprintf("%d", g.Count))
				html.WriteString(`</div>
				</div>`)
			}
			html.WriteString(`</div>`)
		}
	}

	html.WriteString(`<div class="fingerprint-list">
			<h3 class="list-title">指纹详情列表</h3>`)

	for _, g := range sortedGroups {
		html.WriteString(`<div class="fingerprint-item">
			<div class="fingerprint-header" onclick="$(this).next('.fingerprint-urls').toggle();$(this).find('.toggle-icon').toggleClass('rotated')">
				<span class="fingerprint-name">`)
		html.WriteString(xssfilter(g.Name))
		html.WriteString(`</span>
				<span class="fingerprint-count">`)
		html.WriteString(fmt.Sprintf("%d", g.Count))
		html.WriteString(` 个URL</span>
				<span class="toggle-icon">▼</span>
			</div>
			<div class="fingerprint-urls" style="display:none;">`)

		if g.IsUnknown {
			html.WriteString(`<table class="url-table">
				<thead>
					<tr><th>URL</th><th>状态码</th><th>标题</th></tr>
				</thead>
				<tbody>`)
			for _, info := range g.URLInfos {
				statusClass := "status-ok"
				if info.StatusCode >= 400 {
					statusClass = "status-error"
				} else if info.StatusCode >= 300 {
					statusClass = "status-redirect"
				}
				html.WriteString(`<tr>
					<td><a href="`)
				html.WriteString(xssfilter(info.URL))
				html.WriteString(`" target="_blank">`)
				html.WriteString(xssfilter(info.URL))
				html.WriteString(`</a></td>
					<td class="`)
				html.WriteString(statusClass)
				html.WriteString(`">`)
				html.WriteString(fmt.Sprintf("%d", info.StatusCode))
				html.WriteString(`</td>
					<td>`)
				html.WriteString(xssfilter(info.Title))
				html.WriteString(`</td>
				</tr>`)
			}
			html.WriteString(`</tbody></table>`)
		} else {
			html.WriteString(`<ul>`)
			for _, url := range g.URLs {
				html.WriteString(`<li><a href="`)
				html.WriteString(xssfilter(url))
				html.WriteString(`" target="_blank">`)
				html.WriteString(xssfilter(url))
				html.WriteString(`</a></li>`)
			}
			html.WriteString(`</ul>`)
		}

		html.WriteString(`</div>
		</div>`)
	}

	html.WriteString(`</div>
	</div>
	</div>
	</div>
	</body>
	</html>`)

	writeFile(html.String(), structs.GlobalConfig.ReportName)
	reportFinalized = true
}

func FinalizeHTMLReport() {
	if structs.GlobalConfig.ReportName == "" && !structs.GlobalConfig.EnableAPIUnauthScan {
		return
	}
	GenerateHTMLReportHeader()
	AddFingerprintSection()
}

func extractURLs(infos []urlInfo) []string {
	urls := make([]string, len(infos))
	for i, info := range infos {
		urls[i] = info.URL
	}
	return urls
}

func getURLInfo(targetURL string) (int, string) {
	statusCode := 0
	title := ""

	structs.GlobalURLMapLock.Lock()
	defer structs.GlobalURLMapLock.Unlock()

	for rootURL, urlEntity := range structs.GlobalURLMap {
		if targetURL == rootURL {
			for _, pathEntity := range urlEntity.WebPaths {
				return pathEntity.StatusCode, pathEntity.Title
			}
		}
		for path, pathEntity := range urlEntity.WebPaths {
			fullURL := rootURL + path
			if targetURL == fullURL {
				return pathEntity.StatusCode, pathEntity.Title
			}
		}
	}

	return statusCode, title
}
