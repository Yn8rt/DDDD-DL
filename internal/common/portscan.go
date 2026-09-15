package common

import (
	"bytes"
	"dddd/internal/common/progress"
	"dddd/internal/ddout"
	"dddd/internal/structs"
	"dddd/internal/utils"
	"dddd/lib/masscan"
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func ParsePort(ports string) (scanPorts []int) {
	if ports == "" {
		return
	}
	slices := strings.Split(ports, ",")
	for _, port := range slices {
		port = strings.TrimSpace(port)
		if port == "" {
			continue
		}
		startText := port
		endText := port
		if strings.Contains(port, "-") {
			ranges := strings.Split(port, "-")
			if len(ranges) < 2 {
				continue
			}
			startText = strings.TrimSpace(ranges[0])
			endText = strings.TrimSpace(ranges[1])
		}
		start, errStart := strconv.Atoi(startText)
		end, errEnd := strconv.Atoi(endText)
		if errStart != nil || errEnd != nil {
			continue
		}
		if start > end {
			start, end = end, start
		}
		if start < 1 {
			start = 1
		}
		if end > 65535 {
			end = 65535
		}
		if start > end {
			continue
		}
		for i := start; i <= end; i++ {
			scanPorts = append(scanPorts, i)
		}
	}
	scanPorts = utils.RemoveDuplicateElementInt(scanPorts)
	return scanPorts
}

func FilterPorts(ports, noPorts string) []int {
	scanPorts := ParsePort(ports)
	excludePorts := ParsePort(noPorts)
	if len(excludePorts) == 0 {
		return scanPorts
	}

	excludeSet := make(map[int]struct{}, len(excludePorts))
	for _, port := range excludePorts {
		excludeSet[port] = struct{}{}
	}

	probePorts := make([]int, 0, len(scanPorts))
	for _, port := range scanPorts {
		if _, excluded := excludeSet[port]; excluded {
			continue
		}
		probePorts = append(probePorts, port)
	}
	return probePorts
}

func FormatPorts(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	sort.Ints(ports)

	var ranges []string
	start := ports[0]
	previous := ports[0]
	appendRange := func(from, to int) {
		if from == to {
			ranges = append(ranges, strconv.Itoa(from))
			return
		}
		ranges = append(ranges, fmt.Sprintf("%d-%d", from, to))
	}

	for _, port := range ports[1:] {
		if port == previous+1 {
			previous = port
			continue
		}
		appendRange(start, previous)
		start = port
		previous = port
	}
	appendRange(start, previous)

	return strings.Join(ranges, ",")
}

var BackList map[string]struct{}
var BackListLock sync.Mutex

func PortScanTCP(IPs []string, Ports string, NoPorts string, timeout int) []string {
	gologger.AuditTimeLogger("开始TCP端口扫描，端口设置: %s\nTCP端口扫描目标:%s", Ports, strings.Join(IPs, ","))
	probePorts := FilterPorts(Ports, NoPorts)
	if len(probePorts) == 0 {
		gologger.Info().Msg("端口扫描列表为空，跳过TCP端口扫描")
		return nil
	}

	IPs = utils.RemoveDuplicateElement(IPs)
	if len(IPs) == 0 {
		return nil
	}

	workers := structs.GlobalConfig.TCPPortScanThreads
	totalJobs := len(IPs) * len(probePorts)
	if workers <= 0 {
		workers = 1
	}
	if workers > totalJobs {
		workers = totalJobs
	}

	// 端口扫描进度条
	var bar *progress.Bar
	if totalJobs > 0 {
		bar = progress.New("端口扫描", totalJobs)
		defer bar.Finish()
	}

	Addrs := make(chan Addr, workers)
	results := make(chan string, workers)
	schedulerDone := make(chan struct{})
	var workersWG sync.WaitGroup
	tracker := newPortThresholdTracker(structs.GlobalConfig.PortsThreshold)

	// 添加扫描目标。目标达到阈值后，只跳过该目标后续端口，并继续调度其它目标。
	go func() {
		defer close(schedulerDone)
		defer close(Addrs)
		for _, port := range probePorts {
			for _, host := range IPs {
				if tracker.isSkipped(host) {
					if bar != nil {
						bar.Add(1)
					}
					continue
				}
				Addrs <- Addr{host, port}
			}
		}
	}()

	//多线程扫描
	for i := 0; i < workers; i++ {
		workersWG.Add(1)
		go func() {
			defer workersWG.Done()
			for addr := range Addrs {
				if !tracker.isSkipped(addr.ip) && tcpPortProbe(addr, timeout) {
					results <- formatAddr(addr)
				}
				if bar != nil {
					bar.Add(1)
				}
			}
		}()
	}

	go func() {
		workersWG.Wait()
		close(results)
	}()

	var aliveAddress []string
	for found := range results {
		host, _, ok := splitHostPort(found)
		if !ok {
			continue
		}
		if tracker.recordOpen(host) {
			aliveAddress = append(aliveAddress, found)
		}
	}
	<-schedulerDone
	gologger.AuditTimeLogger("TCP端口扫描结束")

	aliveAddress = tracker.filterSkipped(aliveAddress)
	for _, address := range aliveAddress {
		emitPortDiscovery(address)
	}
	return aliveAddress
}

type Addr struct {
	ip   string
	port int
}

var PortScan bool

var tcpPortProbe = func(addr Addr, adjustedTimeout int) bool {
	conn, err := WrapperTcpWithTimeout("tcp4", formatAddr(addr), time.Duration(adjustedTimeout)*time.Second)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	return err == nil
}

type portThresholdTracker struct {
	mu        sync.Mutex
	counts    map[string]int
	skipped   map[string]struct{}
	threshold int
}

func newPortThresholdTracker(threshold int) *portThresholdTracker {
	BackListLock.Lock()
	BackList = make(map[string]struct{})
	BackListLock.Unlock()

	return &portThresholdTracker{
		counts:    make(map[string]int),
		skipped:   make(map[string]struct{}),
		threshold: threshold,
	}
}

func (t *portThresholdTracker) isSkipped(ip string) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.skipped[ip]
	return ok
}

func (t *portThresholdTracker) recordOpen(ip string) bool {
	if t == nil {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.skipped[ip]; ok {
		return false
	}

	t.counts[ip]++
	if t.threshold > 0 && t.counts[ip] >= t.threshold {
		t.skipped[ip] = struct{}{}
		BackListLock.Lock()
		BackList[ip] = struct{}{}
		BackListLock.Unlock()
		gologger.Warning().Msgf("%s 开放端口达到阈值(%d)，跳过该目标剩余端口，继续扫描其他目标", ip, t.threshold)
		return false
	}
	return true
}

func (t *portThresholdTracker) filterSkipped(addresses []string) []string {
	if t == nil {
		return utils.RemoveDuplicateElement(addresses)
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	filtered := make([]string, 0, len(addresses))
	for _, address := range addresses {
		host, _, ok := splitHostPort(address)
		if !ok {
			continue
		}
		if _, skipped := t.skipped[host]; skipped {
			continue
		}
		filtered = append(filtered, address)
	}
	return utils.RemoveDuplicateElement(filtered)
}

func formatAddr(addr Addr) string {
	return net.JoinHostPort(addr.ip, strconv.Itoa(addr.port))
}

func splitHostPort(address string) (string, string, bool) {
	host, port, err := net.SplitHostPort(address)
	if err == nil {
		return host, port, true
	}
	index := strings.LastIndex(address, ":")
	if index <= 0 || index == len(address)-1 {
		return "", "", false
	}
	return address[:index], address[index+1:], true
}

func emitPortDiscovery(address string) {
	host, port, ok := splitHostPort(address)
	if !ok {
		return
	}
	if PortScan {
		ddout.FormatOutput(ddout.OutputMessage{
			Type: "PortScan",
			IP:   host,
			Port: port,
		})
		return
	}
	ddout.FormatOutput(ddout.OutputMessage{
		Type:          "IPAlive",
		IP:            host,
		AdditionalMsg: "TCP:" + port,
	})
}

func PortScanSYN(IPs []string) []string {
	ports := FilterPorts(structs.GlobalConfig.Ports, structs.GlobalConfig.NoPortString)
	if len(ports) == 0 {
		gologger.Info().Msg("端口扫描列表为空，跳过SYN端口扫描")
		return nil
	}

	ips := strings.Join(utils.RemoveDuplicateElement(IPs), "\n")
	err := os.WriteFile("masscan_tmp.txt", []byte(ips), 0666)
	if err != nil {
		return []string{}
	}
	defer os.Remove("masscan_tmp.txt")

	ms := masscan.New(structs.GlobalConfig.MasscanPath)
	ms.SetFileName("masscan_tmp.txt")
	ms.SetPorts(FormatPorts(ports))
	ms.SetRate(strconv.Itoa(structs.GlobalConfig.SYNPortScanThreads))
	if structs.GlobalConfig.MasscanInterface != "" {
		ms.SetInterface(structs.GlobalConfig.MasscanInterface)
	}
	gologger.Info().Msg(aurora.BrightMagenta("调用masscan进行SYN端口扫描").String())
	err = ms.Run()
	gologger.AuditTimeLogger("masscan扫描结束")
	if err != nil {
		gologger.Error().Msgf("masscan执行失败: %v", err)
		return []string{}
	}
	hosts, errParse := ms.Parse()
	if errParse != nil {
		gologger.Error().Msgf("masscan结果解析失败: %v", errParse)
		return []string{}
	}

	if len(hosts) == 0 {
		gologger.Warning().Msgf("masscan未扫描到开放端口")
	}

	var results []string
	for _, each := range hosts {
		for _, port := range each.Ports {
			results = append(results, each.Address.Addr+":"+port.Portid)
		}
	}
	results = utils.RemoveDuplicateElement(results)
	for _, each := range results {
		// gologger.Silent().Msg("[PortScan] " + each)
		t := strings.Split(each, ":")
		ddout.FormatOutput(ddout.OutputMessage{
			Type: "PortScan",
			IP:   t[0],
			Port: t[1],
		})
	}
	return results
}

// CheckMasScan 校验MasScan是否正确安装
func CheckMasScan() bool {
	var bsenv = ""
	if OS != "windows" {
		bsenv = "/bin/bash"
	}

	var command *exec.Cmd
	if OS == "windows" {
		command = exec.Command("cmd", "/c", structs.GlobalConfig.MasscanPath)
	} else if OS == "linux" {
		command = exec.Command(bsenv, "-c", structs.GlobalConfig.MasscanPath)
	} else if OS == "darwin" {
		command = exec.Command(bsenv, "-c", structs.GlobalConfig.MasscanPath)
	}
	outinfo := bytes.Buffer{}
	command.Stdout = &outinfo
	err := command.Start()
	if err != nil {
		gologger.Error().Msgf("未检测到路径 %v 存在masscan", structs.GlobalConfig.MasscanPath)
		return false
	}
	_ = command.Wait()

	// 未检测到masscan的默认banner
	if !strings.Contains(outinfo.String(), "masscan -p80,8000-8100 10.0.0.0/8 --rate=10000") {
		gologger.Error().Msgf("未检测到路径 %v 存在masscan", structs.GlobalConfig.MasscanPath)
		return false
	}

	return true
}

func RemoveFirewall(ipPorts []string) []string {
	var results []string

	gologger.AuditTimeLogger("移除开放端口过多的目标")

	m := make(map[string][]string)
	for _, ipPort := range ipPorts {
		ip, port, ok := splitHostPort(ipPort)
		if !ok {
			continue
		}

		_, ok = m[ip]
		if !ok {
			m[ip] = []string{port}
		} else {
			m[ip] = append(m[ip], port)
		}
	}

	for ip, ports := range m {
		ps := utils.RemoveDuplicateElement(ports)
		if structs.GlobalConfig.PortsThreshold > 0 && len(ps) >= structs.GlobalConfig.PortsThreshold {
			gologger.Warning().Msgf("%s 开放端口达到阈值(%d)，已跳过该目标，继续处理其他目标", ip, structs.GlobalConfig.PortsThreshold)
			continue
		}
		for _, p := range ports {
			results = append(results, net.JoinHostPort(ip, p))
		}
	}
	return utils.RemoveDuplicateElement(results)
}
