package uncover

import "dddd/internal/structs"

func AddIPDomainMap(ip string, domain string) {
	structs.AddIPDomain(ip, domain)
}
