package common

import (
	"bufio"
	"dddd/ddout"
	"dddd/structs"
	"dddd/utils"
	"os/exec"
	"strings"

	_ "embed"

	"github.com/projectdiscovery/dnsx/calldnsx"
)

// SubFinder 调用外部 subfinder 命令进行子域名被动收集
func SubFinder(domain string) []string {
	var results []string

	// 检查 subfinder 是否存在
	_, err := exec.LookPath("subfinder")
	if err != nil {
		ddout.FormatOutput(ddout.OutputMessage{
			Type:          "DNS-SubFinder",
			AdditionalMsg: "subfinder 未安装，跳过被动子域名收集",
		})
		return results
	}

	// 构建命令参数
	args := []string{"-d", domain, "-silent"}
	if structs.GlobalConfig.APIConfigFilePath != "" {
		args = append(args, "-provider-config", structs.GlobalConfig.APIConfigFilePath)
	}

	cmd := exec.Command("subfinder", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return results
	}

	if err := cmd.Start(); err != nil {
		return results
	}

	// 实时读取输出并回调
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		subdomain := strings.TrimSpace(scanner.Text())
		if subdomain != "" {
			results = append(results, subdomain)
			ddout.FormatOutput(ddout.OutputMessage{
				Type:   "DNS-SubFinder",
				Domain: subdomain,
			})
		}
	}

	cmd.Wait()
	return results
}

func DNSCallback(subdomain string) {
	ddout.FormatOutput(ddout.OutputMessage{
		Type:   "DNS-Brute",
		Domain: subdomain,
	})
}

//go:embed config/subdomains.txt
var EmbedSubdomainDict string

func GetSubDomain(domains []string) []string {
	var results []string

	// 兼容Windows输入
	t := strings.ReplaceAll(EmbedSubdomainDict, "\r\n", "\n")
	dict := strings.Split(t, "\n")

	for _, domain := range domains {

		// 爆破子域名
		if !structs.GlobalConfig.NoSubdomainBruteForce {
			br := calldnsx.CallDNSx(domain,
				structs.GlobalConfig.SubdomainBruteForceThreads,
				DNSCallback, dict, structs.GlobalConfig.SubdomainWordListFile)
			for _, v := range br {
				results = append(results, v)
			}
		}

		// subfinder被动收集
		if !structs.GlobalConfig.NoSubFinder {
			r := SubFinder(domain)
			for _, v := range r {
				results = append(results, v)
			}
		}

	}

	return utils.RemoveDuplicateElement(results)
}
