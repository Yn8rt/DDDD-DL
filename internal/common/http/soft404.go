package http

import (
	"dddd/lib/ddfinger"
	neturl "net/url"
	"strings"

	"github.com/projectdiscovery/httpx/runner"
)

// isActiveFingerConfirmable 基于白名单判断主动指纹探测响应是否足够"像真实页面"，
// 从而避免把软 404 / 通用错误页识别成产品指纹。
//
// 观察发现：绝大多数 Not Found / 路径回显的错误页是静态文本，不含 <script、<link、<img、
// <style、<form 等真实 Web 应用常见的标签；而正常登录页、管理后台、控制台等通常至少
// 包含其中一种。因此把这些标签作为正向证据，可以显著降低主动指纹误报。
func isActiveFingerConfirmable(resp runner.Result) bool {
	bodyLower := strings.ToLower(resp.Body)

	// 如果已有强正常页面证据（favicon、非错误 title），直接放行
	if hasStrongNormalPageEvidence(resp) {
		return true
	}

	// 正向白名单：页面包含常见 Web 应用标签或特征，说明可能是真实页面
	positiveMarkers := []string{
		"<script", "<link ", "<img ", "<style", "<form",
		"<iframe", "<video", "<audio", "<canvas", "<svg",
		"<nav ", "<header", "<footer", "<main>", "<section",
		"class=", "id=", "data-",
		"window.", "document.", "jquery", "vue", "react", "angular",
		"<!--", "<!doctype",
	}
	for _, marker := range positiveMarkers {
		if strings.Contains(bodyLower, marker) {
			return true
		}
	}

	return false
}

// isSoft404Response 判定响应是否是软 404 / 通用错误页
//
// 委托给 ddfinger.ShouldSkipGenericErrorFingerprint 保持与被动指纹识别阶段
// 一致的判定标准, 避免 active-finger 和 passive-finger 对同一响应给出不同结论
func isSoft404Response(resp runner.Result) bool {
	return ddfinger.ShouldSkipGenericErrorFingerprint(resp.StatusCode, resp.Title, resp.Body)
}

// isActivePathEchoError 判断主动探测路径是否被 API 错误响应原样回显。
// 反代/API 网关常把任意路径包装成 JSON 错误返回，body 中带有 path/message/error 字段，
// 容易让仅依赖路径关键词的主动指纹误命中。
func isActivePathEchoError(resp runner.Result) bool {
	path := activeResponsePath(resp)
	if path == "" || path == "/" {
		return false
	}

	bodyLower := strings.ToLower(strings.TrimSpace(resp.Body))
	if bodyLower == "" || len(bodyLower) > 8192 {
		return false
	}
	if !hasRequestPathEcho(bodyLower, path) {
		return false
	}

	if resp.StatusCode >= 400 && resp.StatusCode < 600 {
		return hasAPIErrorMarker(resp.ContentType, bodyLower)
	}

	if resp.StatusCode == 200 && hasJSONLikeContent(resp.ContentType, bodyLower) && !hasStrongNormalPageEvidence(resp) {
		return hasAPIErrorMarker(resp.ContentType, bodyLower)
	}

	return false
}

func activeResponsePath(resp runner.Result) string {
	path := resp.Path
	if path == "" && resp.URL != "" {
		if parsedURL, err := neturl.Parse(resp.URL); err == nil {
			path = parsedURL.EscapedPath()
		}
	}
	return normalizeURLPath(path)
}

func hasRequestPathEcho(bodyLower, path string) bool {
	pathLower := strings.ToLower(strings.TrimSpace(path))
	variants := []string{pathLower, strings.ReplaceAll(pathLower, "/", "\\/")}

	if decodedPath, err := neturl.PathUnescape(pathLower); err == nil && decodedPath != pathLower {
		decodedLower := strings.ToLower(decodedPath)
		variants = append(variants, decodedLower, strings.ReplaceAll(decodedLower, "/", "\\/"))
	}

	for _, variant := range variants {
		if len(variant) < 2 {
			continue
		}
		if strings.Contains(bodyLower, variant) {
			return true
		}
	}
	return false
}

func hasAPIErrorMarker(contentType, bodyLower string) bool {
	if hasJSONLikeContent(contentType, bodyLower) {
		jsonMarkers := []string{
			`"error"`,
			`"errors"`,
			`"message"`,
			`"msg"`,
			`"status"`,
			`"timestamp"`,
			`"success":false`,
		}
		for _, marker := range jsonMarkers {
			if strings.Contains(bodyLower, marker) {
				return true
			}
		}
	}

	textMarkers := []string{
		"not found",
		"no handler found",
		"cannot get ",
		"cannot post ",
		"route not found",
		"request path",
		"invalid path",
		"接口不存在",
		"路径不存在",
		"请求地址",
		"请求路径",
		"资源不存在",
		"未找到",
	}
	for _, marker := range textMarkers {
		if strings.Contains(bodyLower, marker) {
			return true
		}
	}
	return false
}

func hasJSONLikeContent(contentType, bodyLower string) bool {
	contentTypeLower := strings.ToLower(contentType)
	if strings.Contains(contentTypeLower, "json") {
		return true
	}
	return strings.HasPrefix(bodyLower, "{") || strings.HasPrefix(bodyLower, "[")
}

func hasStrongNormalPageEvidence(resp runner.Result) bool {
	if resp.FavIconMMH3 != "" && resp.FavIconMMH3 != "0" {
		return true
	}

	titleLower := strings.ToLower(strings.TrimSpace(resp.Title))
	if titleLower == "" {
		return false
	}
	errorTitleMarkers := []string{"404", "not found", "error", "错误", "未找到", "不存在"}
	for _, marker := range errorTitleMarkers {
		if strings.Contains(titleLower, marker) {
			return false
		}
	}
	return true
}
