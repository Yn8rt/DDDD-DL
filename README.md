# dddd-dl

`dddd-dl` 是一款面向授权渗透测试、红队资产梳理和供应链漏洞排查的自动化工具。项目基于 dddd 工作流进行增强，重点优化了低感知扫描、外部子域名引擎、进度统计、被动/主动指纹识别、POC 映射和结果输出。

## 功能特性

- 自动识别输入类型：支持 IP、IP 段、CIDR、IP:Port、URL、域名、历史结果文件。
- 外部子域名引擎：支持 `dnsx`、`ksubdomain`、`auto`，默认不再把 dnsx/subfinder 源码编进主程序。
- CDN/WAF 控制：默认识别并跳过 CDN 资产，可通过参数关闭识别或允许扫描。
- IP 端口扫描控制：支持完全关闭自动端口扫描，也支持排除指定端口范围。
- General POC 控制：可关闭对所有目标默认附加的通用 POC，降低敏感环境触发概率。
- Hunter/Fofa/Quake 支持：支持网络空间搜索引擎导入资产，Hunter 单字段查询会自动规范化。
- Katana 未授权接口探测：可选启用接口发现与未授权探测流程。
- 指纹识别：支持 Web 被动指纹、主动路径指纹和黑名单过滤。
- 漏洞扫描：集成 Nuclei 模板映射与 GoPoc 服务类检测。
- 结果输出：支持文本、JSON、HTML 报告和审计日志。

## 外部依赖

主程序已将部分工具改为外部调用，建议把对应二进制放在 dddd 同目录，或通过参数指定路径。

| 工具 | 用途 | 默认查找 |
| --- | --- | --- |
| `dnsx` / `dnsx.exe` | 默认子域名爆破引擎 | 当前目录、PATH |
| `ksubdomain` / `ksubdomain.exe` | 高速子域名爆破引擎 | 当前目录、PATH |
| `subfinder` / `subfinder.exe` | 被动子域名收集 | 当前目录、PATH |
| `katana` / `katana.exe` | 未授权接口探测 | 当前目录、PATH 或 `-kp` |
| `masscan` | SYN 端口扫描 | PATH 或 `-mp` |

`ksubdomain` 在 Windows 下通常需要管理员权限和 Npcap；Linux 下通常需要 root 或 `CAP_NET_RAW` 权限。

## 快速开始

扫描单个 URL，仅做低影响信息收集：

```bash
dddd -t http://10.10.0.176:8080/login -nps -dgp -npoc -nd -nhb
```

扫描 IP，关闭漏洞探测：

```bash
dddd -t 192.168.1.10 -npoc
```

扫描 IP 段并关闭自动端口扫描：

```bash
dddd -t 192.168.1.0/24 -nps
```

枚举子域名，默认使用外部 `dnsx`：

```bash
dddd -t example.com -sd
```

枚举子域名，使用外部 `ksubdomain`：

```bash
dddd -t example.com -sd -sde ksubdomain -ksb 5m -ksw basic
```

优先使用 `ksubdomain`，失败自动回退 `dnsx`：

```bash
dddd -t example.com -sd -sde auto
```

Hunter 查询域名后缀：

```bash
dddd -t domain.suffix=example.com -hunter
```

上面的 Hunter 查询会自动规范化为：

```text
domain.suffix="example.com"
```

## 常用低感知参数

| 参数 | 说明 |
| --- | --- |
| `-npoc` | 关闭漏洞探测，只做信息收集 |
| `-dgp` | 关闭 `General-Poc-*` 通用 POC 映射 |
| `--nuclei-timeout` | Nuclei 单请求超时时间，默认 `20` 秒，慢跳转/慢响应站点建议调大 |
| `--nuclei-retries` | Nuclei 请求失败重试次数，默认 `2` |
| `--nuclei-max-host-error` | Nuclei 主机错误跳过阈值，默认 `0` 表示不因累计错误跳过已探活目标 |
| `-nps` | 关闭 IP 自动端口扫描 |
| `-nd` | 关闭主动 Web 路径指纹探测 |
| `-nhb` | 关闭域名绑定探测 |
| `-ncc` | 关闭 CDN/WAF 识别，仅做域名解析 |
| `-ni` | 禁用 Interactsh，排除反连模板 |
| `-nb` | 禁用服务爆破，不包括 Shiro Keys |

敏感环境建议组合：

```bash
dddd -t target.txt -npoc -dgp -nps -nd -nhb -ni -a
```

## 子域名参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-sd` | `false` | 开启子域名枚举 |
| `-nsb` | `false` | 关闭子域名爆破 |
| `-ns` | `false` | 关闭被动 subfinder 收集 |
| `-sde` | `dnsx` | 子域名爆破外部引擎：`dnsx`、`ksubdomain`、`auto` |
| `-dxp` | `dnsx` | dnsx 程序路径 |
| `-ksp` | `ksubdomain` | ksubdomain 程序路径 |
| `-ksb` | `3m` | ksubdomain 带宽限制 |
| `-ksi` | 空 | ksubdomain 指定网卡 |
| `-ksw` | `basic` | ksubdomain 泛解析过滤模式：`none`、`basic`、`advanced` |
| `-swl` | `embedded` | 指定子域名字典文件，默认使用内嵌字典临时写出给外部工具 |

## CDN/WAF 与端口扫描控制

默认会对域名资产进行 CDN/WAF 识别，识别为 CDN 的域名默认不继续扫描：

```bash
dddd -t example.com -sd
```

允许扫描 CDN 资产：

```bash
dddd -t example.com -sd -ac
```

关闭 CDN/WAF 识别：

```bash
dddd -t example.com -sd -ncc
```

关闭 IP 自动端口扫描：

```bash
dddd -t 10.10.0.0/24 -nps
```

排除所有端口，等效于 TCP/SYN 端口扫描无可扫端口：

```bash
dddd -t 10.10.0.0/24 -np 1-65535
```

## 输出

| 参数 | 说明 |
| --- | --- |
| `-o` | 指定文本/JSON 结果输出文件，默认 `result.txt` |
| `-ot` | 输出格式：`text` 或 `json` |
| `-ho` | 指定 HTML 漏洞报告文件名 |
| `-a` | 开启审计日志 |
| `-alf` | 指定审计日志文件名 |

## 配置文件

| 参数 | 说明 |
| --- | --- |
| `-acf` | API 配置文件，用于 Hunter/Fofa/Quake/subfinder provider |
| `-nt` | 指定额外 Nuclei POC 目录，留空仅使用内嵌模板 |
| `-wy` | 指定外部 `workflow.yaml` 覆盖内嵌 POC 映射 |
| `-fy` | 指定外部 `finger.yaml` 覆盖内嵌指纹 |
| `-dy` | 指定外部主动指纹数据库 |


## 免责声明

本项目仅面向合法授权的安全测试、企业安全建设和研究场景。使用者必须确保对目标拥有明确授权，并遵守所在地法律法规。任何未经授权的扫描、探测、利用行为均与本项目无关，风险和责任由使用者自行承担。

##联系方式

关注"迷人安全"公众号，点击交流群可获取二维码
