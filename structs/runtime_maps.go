package structs

func AddActiveFinger(target, finger string) bool {
	if target == "" || finger == "" {
		return false
	}

	GlobalActiveFingerMapLock.Lock()
	defer GlobalActiveFingerMapLock.Unlock()

	existing := GlobalActiveFingerMap[target]
	for _, item := range existing {
		if item == finger {
			return false
		}
	}
	GlobalActiveFingerMap[target] = append(existing, finger)
	return true
}

func GetActiveFingers(target string) []string {
	GlobalActiveFingerMapLock.Lock()
	defer GlobalActiveFingerMapLock.Unlock()

	existing := GlobalActiveFingerMap[target]
	if len(existing) == 0 {
		return nil
	}

	result := make([]string, len(existing))
	copy(result, existing)
	return result
}

func AddIPPortService(hostPort, service string, banner []byte) bool {
	GlobalIPPortMapLock.Lock()
	defer GlobalIPPortMapLock.Unlock()

	if _, ok := GlobalIPPortMap[hostPort]; ok {
		return false
	}

	if banner != nil && GlobalBannerHMap != nil {
		_ = GlobalBannerHMap.Set(hostPort, banner)
	}
	GlobalIPPortMap[hostPort] = service
	return true
}

func AddIPDomain(ip, domain string) bool {
	if ip == "" || domain == "" {
		return false
	}

	GlobalIPDomainMapLock.Lock()
	defer GlobalIPDomainMapLock.Unlock()

	domains := GlobalIPDomainMap[ip]
	for _, existing := range domains {
		if existing == domain {
			return false
		}
	}

	GlobalIPDomainMap[ip] = append(domains, domain)
	return true
}
