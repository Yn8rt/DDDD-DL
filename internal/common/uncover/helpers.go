package uncover

import (
	"dddd/internal/structs"
	"dddd/internal/utils"
	"dddd/internal/utils/cdn"

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
