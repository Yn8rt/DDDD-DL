package httpx

import (
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/runner"
	errorutil "github.com/projectdiscovery/utils/errors"
	"os"
	"strings"
	"sync"
)

var GlobalUsedUrl []string
var GlobalHTTPSRetryUrls []string
var GlobalHTTPSRetryLock sync.Mutex

func AddHTTPSRetryUrl(url string) {
	GlobalHTTPSRetryLock.Lock()
	defer GlobalHTTPSRetryLock.Unlock()
	GlobalHTTPSRetryUrls = append(GlobalHTTPSRetryUrls, url)
}

func GetAndClearHTTPSRetryUrls() []string {
	GlobalHTTPSRetryLock.Lock()
	defer GlobalHTTPSRetryLock.Unlock()
	urls := GlobalHTTPSRetryUrls
	GlobalHTTPSRetryUrls = nil
	return urls
}

func RemoveDuplicateElement(input []string) []string {
	temp := map[string]struct{}{}
	var result []string
	for _, item := range input {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func RemoveUsedUrl(urls []string) []string {
	var result []string
	for _, u := range urls {
		flag := false
		for _, gu := range GlobalUsedUrl {
			if gu == u {
				flag = true
				break
			}
		}
		if !flag {
			result = append(result, u)
		}
	}
	return RemoveDuplicateElement(result)
}

func CallHTTPx(urls []string, callBack func(resp runner.Result), proxy string, threads int, timeout int) {
	CallHTTPxWithProgress(urls, callBack, nil, proxy, threads, timeout)
}

// CallHTTPxWithProgress CallHTTPx 的带进度钩子版本
func CallHTTPxWithProgress(urls []string, callBack func(resp runner.Result), onItemDone ProgressHook, proxy string, threads int, timeout int) {
	gologger.Info().Msg(aurora.BrightBlue("获取Web响应中").String())

	nextUrls := RemoveDuplicateElement(urls)
	gologger.AuditLogger("响应探测目标: %s", strings.Join(nextUrls, ","))

	times := 0
	for len(nextUrls) > 0 && times < 3 {
		options := runner.Options{
			Methods:                   "GET",
			InputTargetHost:           nextUrls,
			Favicon:                   true,
			Hashes:                    "md5",
			OutputServerHeader:        true,
			TLSProbe:                  true,
			MaxResponseBodySizeToRead: 1048576,
			FollowHostRedirects:       true,
			MaxRedirects:              5,
			ExtractTitle:              true,
			Timeout:                   timeout,
			Retries:                   2,
			HTTPProxy:                 proxy,
			NoFallbackScheme:          true,
			RandomAgent:               true,
			Threads:                   threads,
		}

		if err := options.ValidateOptions(); err != nil {
			gologger.Error().Msgf("params error")
		}

		httpxRunner, err := runner.New(&options)
		if err != nil {
			gologger.Error().Msgf("runner.New(&options) error")
		}
		httpxRunner.CallBack = callBack
		if onItemDone != nil {
			httpxRunner.OnItemDone = func(current, total int) { onItemDone(current, total) }
		}

		for _, u := range nextUrls {
			GlobalUsedUrl = append(GlobalUsedUrl, u)
		}
		GlobalUsedUrl = RemoveDuplicateElement(GlobalUsedUrl)

		httpxRunner.RunEnumeration()
		nextUrls = RemoveUsedUrl(httpxRunner.NextCheckUrl)
		
		httpsRetryUrls := GetAndClearHTTPSRetryUrls()
		if len(httpsRetryUrls) > 0 {
			httpsRetryUrls = RemoveUsedUrl(httpsRetryUrls)
			if len(httpsRetryUrls) > 0 {
				gologger.Info().Msgf("检测到HTTP请求发送到HTTPS端口，自动重试HTTPS: %d个URL", len(httpsRetryUrls))
				nextUrls = append(nextUrls, httpsRetryUrls...)
				for _, u := range httpsRetryUrls {
					GlobalUsedUrl = append(GlobalUsedUrl, u)
				}
				GlobalUsedUrl = RemoveDuplicateElement(GlobalUsedUrl)
			}
		}
		
		httpxRunner.Close()
		times += 1

	}
	gologger.AuditTimeLogger("响应探测结束")

}

func init() {
	if os.Getenv("DEBUG") != "" {
		errorutil.ShowStackTrace = true
	}
}

// ProgressHook 每处理完一个输入 URL 触发(包含超时/失败)
// dddd 侧传入用于进度条推进, 避免 callback 只统计成功响应导致 bar 卡在中间
type ProgressHook func(current, total int)

func DirBrute(urls []string, callBack func(resp runner.Result), proxy string, threads int, timeout int) {
	DirBruteWithProgress(urls, callBack, nil, proxy, threads, timeout)
}

// DirBruteWithProgress DirBrute 的带进度钩子版本
func DirBruteWithProgress(urls []string, callBack func(resp runner.Result), onItemDone ProgressHook, proxy string, threads int, timeout int) {
	urls = RemoveDuplicateElement(urls)

	options := runner.Options{
		Methods:                   "GET",
		InputTargetHost:           urls,
		Hashes:                    "md5",
		OutputServerHeader:        true,
		TLSProbe:                  true,
		MaxResponseBodySizeToRead: 1048576,
		FollowHostRedirects:       true,
		MaxRedirects:              5,
		ExtractTitle:              true,
		Timeout:                   timeout,
		IsBrute:                   true,
		Retries:                   2,
		HTTPProxy:                 proxy,
		NoFallbackScheme:          true,
		RandomAgent:               true,
		Threads:                   threads,
	}

	if err := options.ValidateOptions(); err != nil {
		gologger.Error().Msgf("params error")
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		gologger.Error().Msgf("runner.New(&options) error")
	}
	httpxRunner.CallBack = callBack
	if onItemDone != nil {
		httpxRunner.OnItemDone = func(current, total int) { onItemDone(current, total) }
	}

	httpxRunner.RunEnumeration()
	httpxRunner.Close()
}
