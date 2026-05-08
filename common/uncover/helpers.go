package uncover

import (
	"dddd/structs"
	"dddd/utils"
	"dddd/utils/cdn"

	"github.com/projectdiscovery/gologger"
)

func buildCDNDomainMap(domains []string) map[string]bool {
	domains = utils.RemoveDuplicateElement(domains)
	domainCDNMap := make(map[string]bool, len(domains))
	if structs.GlobalConfig.NoCDNCheck {
		for _, domain := range domains {
			domainCDNMap[domain] = false
		}
		return domainCDNMap
	}

	if len(domains) != 0 {
		gologger.Info().Msgf("正在查询 [%v] 个域名是否为CDN资产", len(domains))
	}

	cdnDomains, normalDomains, _ := cdn.CheckCDNs(domains, structs.GlobalConfig.SubdomainBruteForceThreads)
	for _, domain := range cdnDomains {
		domainCDNMap[domain] = true
	}
	for _, domain := range normalDomains {
		if _, ok := domainCDNMap[domain]; !ok {
			domainCDNMap[domain] = false
		}
	}

	return domainCDNMap
}

func newStringSet(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		result[value] = struct{}{}
	}
	return result
}

func appendUniqueString(values []string, seen map[string]struct{}, value string) []string {
	if value == "" {
		return values
	}
	if _, ok := seen[value]; ok {
		return values
	}
	seen[value] = struct{}{}
	return append(values, value)
}
