package common

import (
	"dddd/common/http"
	"dddd/structs"
	"dddd/utils"
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx"
	"net/url"
	"strings"
)

func HostBindCheck() {
	gologger.Info().Msg(aurora.BrightBlue("域名绑定资产发现").String())

	var urls []string
	urlSet := make(map[string]struct{})
	for rootURL := range structs.GlobalURLMap {
		URL, err := url.Parse(rootURL)
		if err != nil {
			continue
		}

		if strings.Contains(URL.Host, ":") {
			tmp := strings.Split(URL.Host, ":")
			if len(tmp) != 2 {
				continue
			}
			ip, port := tmp[0], tmp[1]
			if !utils.IsIPv4(ip) {
				continue
			}
			domains, ok := structs.GlobalIPDomainMap[ip]
			if !ok {
				continue
			}
			for _, domain := range domains {
				target := fmt.Sprintf("%v://%v:%v", URL.Scheme, domain, port)
				if _, ok := urlSet[target]; ok {
					continue
				}
				urlSet[target] = struct{}{}
				urls = append(urls, target)
			}
		} else {
			ip := URL.Host
			if !utils.IsIPv4(ip) {
				continue
			}
			domains, ok := structs.GlobalIPDomainMap[ip]
			if !ok {
				continue
			}
			for _, domain := range domains {
				target := fmt.Sprintf("%v://%v", URL.Scheme, domain)
				if _, ok := urlSet[target]; ok {
					continue
				}
				urlSet[target] = struct{}{}
				urls = append(urls, target)
			}
		}
	}

	httpx.DirBrute(urls, http.HostBindHTTPxCallBack,
		structs.GlobalConfig.HTTPProxy,
		structs.GlobalConfig.WebThreads,
		structs.GlobalConfig.WebTimeout)
	gologger.AuditTimeLogger("域名绑定资产发现结束")
}
