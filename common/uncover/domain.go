package uncover

import "dddd/structs"

func AddIPDomainMap(ip string, domain string) {
	structs.AddIPDomain(ip, domain)
}
