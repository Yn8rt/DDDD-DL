package gopocs

import (
	"context"
	"dddd/common/progress"
	"dddd/structs"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

var Mutex = &sync.Mutex{}

// dispatchRule 服务扫描分发规则
// 通过 "协议名或端口命中" 决定是否触发某个 PluginList 下的扫描
type dispatchRule struct {
	Protocol        string // gonmap 识别出的 protocol (可空)
	Port            string // 端口号 (protocol 为空时按端口回退)
	ScanName        string // PluginList 中的 key
	SkipWhenNoBrute bool   // -nb 参数启用时是否跳过
}

// serviceDispatchRules 所有服务→扫描插件映射
// 相比原实现:
//   - 去除 14 个重复 if
//   - 统一以 rule 表驱动，新增服务直接追加一行
//   - 同一端口可对应多条 rule (如 445→SMB-MS17-010 + SMB-Crack + NetBios-GetHostInfo)
var serviceDispatchRules = []dispatchRule{
	{Protocol: "ssh", Port: "22", ScanName: "SSH-Crack"},
	{Protocol: "ftp", Port: "21", ScanName: "FTP-Crack"},
	{Protocol: "mysql", Port: "3306", ScanName: "Mysql-Crack"},
	{Protocol: "mssql", Port: "1433", ScanName: "Mssql-Crack"},
	{Protocol: "oracle", Port: "1521", ScanName: "Oracle-Crack"},
	{Protocol: "mongodb", Port: "27017", ScanName: "MongoDB-Crack"},
	{Protocol: "rdp", Port: "3389", ScanName: "RDP-Crack", SkipWhenNoBrute: true},
	{Protocol: "redis", Port: "6379", ScanName: "Redis-Crack"},
	{Protocol: "smb", Port: "445", ScanName: "SMB-MS17-010"},
	{Protocol: "smb", Port: "445", ScanName: "SMB-Crack"},
	{Protocol: "postgresql", Port: "5432", ScanName: "PostgreSQL-Crack"},
	{Protocol: "telnet", Port: "23", ScanName: "Telnet-Crack"},
	{Protocol: "memcached", Port: "11211", ScanName: "Memcache-Crack"},
	{Protocol: "netbios", Port: "445", ScanName: "NetBios-GetHostInfo"},
	{Protocol: "rpc", ScanName: "RPC-GetHostInfo"},
	{Protocol: "jdwp", ScanName: "JDWP-Scan"},
	{Protocol: "adb", Port: "5555", ScanName: "ADB-Scan"},
}

// 进度追踪，放在扫描器内部以便随 Dispatcher 重置
var (
	scanBar     *progress.Bar
	completed   atomic.Int64
	scheduled   atomic.Int64
	totalPlaced atomic.Int64
)

func AddScan(scantype string, info structs.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	scheduled.Add(1)
	*ch <- struct{}{}
	wg.Add(1)
	go func() {
		Mutex.Lock()
		structs.AddScanNum += 1
		Mutex.Unlock()
		ScanFunc(&scantype, &info)
		Mutex.Lock()
		structs.AddScanEnd += 1
		Mutex.Unlock()
		completed.Add(1)
		if scanBar != nil {
			scanBar.Set(int(completed.Load()))
		}
		wg.Done()
		<-*ch
	}()
}

func ScanFunc(name *string, info *structs.HostInfo) {
	defer func() {
		if err := recover(); err != nil {
			gologger.Error().Msgf("[-] %v:%v %v error: %v\n", info.Host, info.Ports, name, err)
		}
	}()
	plugin, ok := PluginList[*name]
	if !ok {
		gologger.Error().Msgf("[-] 未注册的扫描插件: %v", *name)
		return
	}
	f := reflect.ValueOf(plugin)
	in := []reflect.Value{reflect.ValueOf(info)}
	f.Call(in)
}

// matchRules 根据 (protocol, port) 找出所有匹配的 scan 插件名
// protocol 命中优先; protocol 为空时按 port 回退
func matchRules(protocol, port string, noBrute bool) []string {
	seen := make(map[string]struct{})
	var matched []string
	for _, r := range serviceDispatchRules {
		if r.SkipWhenNoBrute && noBrute {
			continue
		}
		hit := false
		if r.Protocol != "" && r.Protocol == protocol {
			hit = true
		} else if r.Port != "" && r.Port == port {
			hit = true
		}
		if !hit {
			continue
		}
		if _, dup := seen[r.ScanName]; dup {
			continue
		}
		seen[r.ScanName] = struct{}{}
		matched = append(matched, r.ScanName)
	}
	return matched
}

func GoPocsDispatcher(nucleiResults []output.ResultEvent) {
	if len(structs.GlobalIPPortMap) == 0 && len(nucleiResults) == 0 {
		return
	}

	// 复位 mysql tcp dialer: nuclei 初始化时会调用
	// mysql.RegisterDialContext("tcp", fastdialer.Dial) 把所有 mysql 连接
	// 代理到 fastdialer 的 DNS 缓存 (基于 leveldb)
	// 但 nuclei 扫描结束后 fastdialer 的 leveldb 会被关闭,
	// 导致 GoPoc 阶段所有 mysql 爆破都 1ms 内返回 "leveldb: closed"
	// 这里显式恢复为 net.Dialer 保证 GoPoc 能正常建连
	resetMysqlDialer()

	initDic()
	completed.Store(0)
	scheduled.Store(0)
	totalPlaced.Store(0)

	// 第 1 轮: 预估 total，用于进度条
	estimated := estimateGoPocTotal(nucleiResults)
	if estimated == 0 {
		return
	}

	scanBar = progress.New("GoPoc", estimated)
	defer func() {
		if scanBar != nil {
			scanBar.Finish()
			scanBar = nil
		}
	}()

	ch := make(chan struct{}, structs.GlobalConfig.GoPocThreads)
	wg := sync.WaitGroup{}
	gologger.Info().Msgf("%s (目标: %d)", aurora.BrightRed("Golang Poc引擎启动").String(), estimated)

	noBrute := structs.GlobalConfig.NoServiceBruteForce

	// 各类协议
	for hostPort, protocol := range structs.GlobalIPPortMap {
		parts := strings.Split(hostPort, ":")
		if len(parts) < 2 {
			continue
		}
		host, port := parts[0], parts[1]
		for _, scanName := range matchRules(protocol, port, noBrute) {
			AddScan(scanName, structs.HostInfo{Host: host, Ports: port}, &ch, &wg)
		}
	}

	// Nuclei 结果驱动的二次扫描
	for _, result := range nucleiResults {
		if result.TemplateID == "shiro-detect" {
			AddScan("Shiro-Key-Crack", structs.HostInfo{Url: result.Matched}, &ch, &wg)
		}
	}

	wg.Wait()
}

// resetMysqlDialer 把 mysql 驱动的 tcp dialer 复位到标准 net.Dialer
// 修复 nuclei fastdialer 关闭后导致的 "leveldb: closed" 连接错误
func resetMysqlDialer() {
	mysql.RegisterDialContext("tcp", func(ctx context.Context, addr string) (net.Conn, error) {
		d := net.Dialer{Timeout: 6 * time.Second}
		return d.DialContext(ctx, "tcp", addr)
	})
}

// estimateGoPocTotal 预估总任务量，用于进度条
func estimateGoPocTotal(nucleiResults []output.ResultEvent) int {
	total := 0
	noBrute := structs.GlobalConfig.NoServiceBruteForce
	for hostPort, protocol := range structs.GlobalIPPortMap {
		parts := strings.Split(hostPort, ":")
		if len(parts) < 2 {
			continue
		}
		port := parts[1]
		total += len(matchRules(protocol, port, noBrute))
	}
	for _, result := range nucleiResults {
		if result.TemplateID == "shiro-detect" {
			total++
		}
	}
	return total
}
