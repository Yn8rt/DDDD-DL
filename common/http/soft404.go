package http

import (
	"dddd/lib/ddfinger"

	"github.com/projectdiscovery/httpx/runner"
)

// isSoft404Response 判定响应是否是软 404 / 通用错误页
//
// 委托给 ddfinger.ShouldSkipGenericErrorFingerprint 保持与被动指纹识别阶段
// 一致的判定标准, 避免 active-finger 和 passive-finger 对同一响应给出不同结论
func isSoft404Response(resp runner.Result) bool {
	return ddfinger.ShouldSkipGenericErrorFingerprint(resp.StatusCode, resp.Title, resp.Body)
}
