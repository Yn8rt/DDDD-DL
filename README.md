# DDDL

[![Release](https://img.shields.io/github/v/release/Yn8rt/DDDL?display_name=tag&sort=semver)](https://github.com/Yn8rt/DDDL/releases)
[![Go Version](https://img.shields.io/badge/Go-1.21%2B-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/github/license/Yn8rt/DDDL)](LICENSE)

DDDL 是一款面向**授权渗透测试**、红队资产梳理和供应链漏洞排查的自动化信息收集与漏洞探测工具。项目基于 dddd 工作流深度增强，重点优化低感知扫描、外部子域名引擎、进度统计、被动/主动指纹识别、POC 映射和结果输出。

> 仅用于合法授权的安全测试，详见文末免责声明。

## 最新更新 v1.1.2（2026-09-15）

- **端口文件输入**：新增 `-portf`/`--port-file`，从文件读取端口列表，兼容逗号/换行/空格/分号分隔与 `8000-8010` 区间写法（Issue #11）
- **修复** `-nt` 追加自定义 Nuclei 模板后扫描流程被跳过的问题（Issue #10）
- **Shiro/MS17010 错误处理完善**，修复 ADB/ICMP/RDP 等多个高危 panic 与竞态问题
- **工程规范化**：项目结构重排为 Go 社区标准布局（`cmd/` + `internal/`），清理 700+ 行死代码，全量 gofmt
- 完整变更记录见 [update.md](update.md)

<img width="2454" height="1360" alt="POC 更新" src="https://github.com/user-attachments/assets/118fd7e7-5a4d-4dbe-bffd-c918e2bc5c68" />

## 安装

方式一：从 [Releases](https://github.com/Yn8rt/DDDL/releases) 下载对应平台的预编译二进制，开箱即用（POC 映射与指纹库已内嵌）。

| 平台 | 文件 |
| --- | --- |
| Windows amd64 | `dddd64.exe` |
| Linux amd64 / arm64 | `dddd_linux_amd64` / `dddd_linux_arm64` |
| macOS arm64 / Intel | `dddd_darwin_arm64` / `dddd_darwin_amd64` |

方式二：源码编译（Go 1.21+）：

```bash
git clone https://github.com/Yn8rt/DDDL.git && cd DDDL
go build -o dddd ./cmd/dddd
# 或使用交互式交叉编译脚本（输出到 ./outp）
./compile.sh
```

## 功能特性

- 自动识别输入类型：IP、IP 段、CIDR、IP:Port、URL、域名、历史结果文件
- 外部子域名引擎：`dnsx`、`ksubdomain`、`auto` 自动回退，不再把子域名工具源码编进主程序
- CDN/WAF 控制：默认识别并跳过 CDN 资产，可通过参数关闭识别或放行
- 端口扫描控制：支持 `-p` 指定、`-portf` 文件读取、`-nps` 完全关闭、`-np` 排除范围
- General POC 控制：可关闭默认附加的通用 POC，降低敏感环境触发概率
- Hunter/Fofa/Quake 资产导入：Hunter 单字段查询自动规范化
- Katana 未授权接口探测：可选启用接口发现与未授权探测流程
- 网站备份扫描：可选探测 `www_baidu_com.zip` 等常见备份文件
- 指纹识别：Web 被动指纹 + 主动路径指纹 + 黑名单过滤
- 漏洞扫描：Nuclei 模板映射 + GoPoc 服务类检测
- 结果输出：文本、JSON、按需 HTML 报告与审计日志

## 快速开始

扫描单个 URL，仅做低影响信息收集：

```bash
dddd -t http://10.10.0.176:8080/login -nps -dgp -npoc -nd -nhb
```

扫描 IP 段，从文件读取端口并关闭漏洞探测：

```bash
dddd -t 192.168.1.0/24 -portf ports.txt -npoc
```

枚举子域名，优先 `ksubdomain`、失败自动回退 `dnsx`：

```bash
dddd -t example.com -sd -sde auto
```

Hunter 查询域名后缀（自动规范化为 `domain.suffix="example.com"`）：

```bash
dddd -t domain.suffix=example.com -hunter
```

扫描已存活 Web 的常见网站备份文件：

```bash
dddd -t http://www.baidu.com -bs -npoc -nd -nps
```

敏感环境建议组合：

```bash
dddd -t target.txt -npoc -dgp -nps -nd -nhb -a
```

## 外部依赖

主程序已将部分工具改为外部调用，建议把对应二进制放在 dddd 同目录，或通过参数指定路径。

| 工具 | 用途 | 默认查找 |
| --- | --- | --- |
| `dnsx` / `dnsx.exe` | 默认子域名爆破引擎 | 当前目录、PATH |
| `ksubdomain` / `ksubdomain.exe` | 高速子域名爆破引擎 | 当前目录、PATH |
| `subfinder` / `subfinder.exe` | 被动子域名收集 | 当前目录、PATH |
| `masscan` | SYN 端口扫描 | PATH 或 `-mp` |

`ksubdomain` 在 Windows 下通常需要管理员权限和 Npcap；Linux 下通常需要 root 或 `CAP_NET_RAW`；macOS 下通常需要 root 或 `/dev/bpf*` 读写权限。

## 参数说明

### 低感知与扫描开关

| 参数 | 说明 |
| --- | --- |
| `-npoc` | 关闭漏洞探测，只做信息收集 |
| `-dgp` | 关闭 `General-Poc-*` 通用 POC 映射 |
| `-nps` | 关闭 IP 自动端口扫描 |
| `-nd` | 关闭主动 Web 路径指纹探测 |
| `-nhb` | 关闭域名绑定探测 |
| `-ncc` | 关闭 CDN/WAF 识别，仅做域名解析 |
| `-nb` | 禁用服务爆破（不包括 Shiro Keys） |
| `--interactsh` | 启用 Interactsh 反连检测，默认关闭 |
| `--nuclei-timeout` | Nuclei 单请求超时，默认 `20` 秒，慢站点建议调大 |
| `--nuclei-retries` | Nuclei 失败重试次数，默认 `2` |
| `--nuclei-max-host-error` | 主机错误跳过阈值，默认 `0` 表示不因累计错误跳过已探活目标 |

### 端口控制

| 参数 | 说明 |
| --- | --- |
| `-p` | 指定端口，如 `22,80,443,8000-8010`（与 `-portf` 同时存在时优先） |
| `-portf` / `--port-file` | 从文件读取端口列表，兼容逗号/换行/空格/分号分隔与区间写法 |
| `-nps` | 完全关闭自动端口扫描 |
| `-np` | 排除端口范围，如 `-np 1-65535` 等效于无可扫端口 |

### 子域名

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-sd` | `false` | 开启子域名枚举 |
| `-nsb` | `false` | 开启 `-sd` 后关闭主动爆破，仅保留被动 subfinder |
| `-ns` | `false` | 关闭被动 subfinder 收集 |
| `-sde` | `dnsx` | 爆破外部引擎：`dnsx`、`ksubdomain`、`auto` |
| `-dxp` | `dnsx` | dnsx 程序路径 |
| `-ksp` | `ksubdomain` | ksubdomain 程序路径 |
| `-ksb` | `3m` | ksubdomain 带宽限制 |
| `-ksi` | 空 | ksubdomain 指定网卡；获取网卡超时可先用 `ksubdomain device` 排查 |
| `-ksw` | `basic` | 泛解析过滤模式：`none`、`basic`、`advanced` |
| `-swl` | `embedded` | 子域名字典文件，默认使用内嵌字典临时写出给外部工具 |

### 网站备份扫描

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-bs` / `--backup-scan` | `false` | 启用网站备份文件扫描 |
| `-bmax` / `--backup-max` | `2000` | 最大候选 URL 数量，防止请求量过大 |
| `-bext` / `--backup-ext` | `zip,tar.gz,tgz,rar,7z,bak,sql` | 备份文件后缀，逗号分隔 |

### CDN/WAF 控制

默认识别为 CDN 的域名不继续扫描；`-ac` 放行 CDN 资产，`-ncc` 关闭识别：

```bash
dddd -t example.com -sd -ac    # 允许扫描 CDN 资产
dddd -t example.com -sd -ncc   # 关闭 CDN/WAF 识别
```

### 输出

| 参数 | 说明 |
| --- | --- |
| `-o` | 文本/JSON 结果输出文件，默认 `result.txt` |
| `-ot` | 输出格式：`text` 或 `json` |
| `-ho` | HTML 漏洞报告文件名；不指定则不输出 |
| `-a` | 开启审计日志 |
| `-alf` | 审计日志文件名 |

### 配置文件

| 参数 | 说明 |
| --- | --- |
| `-acf` | API 配置文件，用于 Hunter/Fofa/Quake/subfinder provider |
| `-nt` | 追加自定义 Nuclei POC 目录，留空仅使用内嵌模板 |
| `-wy` | 外部 `workflow.yaml` 覆盖内嵌 POC 映射 |
| `-fy` | 外部 `finger.yaml` 覆盖内嵌指纹 |
| `-dy` | 外部主动指纹数据库 |

## 项目结构

遵循 Go 社区标准项目布局：

```text
├── cmd/dddd/        # 程序入口与工作流
├── internal/        # 内部业务包（common/structs/utils/gopocs/ddout）
├── lib/             # 本地化第三方依赖（go.mod replace）
├── assets/          # 内嵌资源
├── outp/            # 编译输出目录
└── compile.sh       # 交互式交叉编译脚本（compile.bat 为 Windows 版）
```

## 免责声明

本项目仅面向合法授权的安全测试、企业安全建设和研究场景。使用者必须确保对目标拥有明确授权，并遵守所在地法律法规。任何未经授权的扫描、探测、利用行为均与本项目无关，风险和责任由使用者自行承担。

## 联系方式

关注"迷人安全"公众号，点击交流群可获取二维码
