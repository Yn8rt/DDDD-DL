# v1.1.2 - 2026-09-15 CST

- 修复 Issue #11: 新增 `-portf`/`--port-file` 参数，支持从文件读取端口列表
  - 文件内端口支持逗号/换行/空格/分号分隔，兼容 `8000-8010` 区间写法
  - 与 `-p` 同时存在时优先使用 `-p`；文件不存在或无有效端口时给出明确报错
  - 无效端口项逐条告警并忽略，附带端口总数日志
- Go 代码规范整理
  - 删除不可达死代码：common/proxy 被动扫描代理包（724 行，全包无引用）、ArrayCountValueTop、PortConnect、StoreURLResult、Bar.AddTotal、ResetStages、newStringSet、AesEncrypt、PKCS7Padding、GetItemInArray
  - 全量 gofmt 规范化，统一 CRLF 为 LF
  - 公开发布版本号统一为 1.1.2（对齐公开仓库 Release 编号）
- 项目结构按 Go 社区标准布局重排
  - 入口移至 `cmd/dddd/`，业务包收拢至 `internal/`（common/structs/utils/gopocs/ddout）
  - `lib/` 保持第三方本地化依赖（go.mod replace 路径不变）
  - compile.sh/compile.bat 构建路径同步调整为 `./cmd/dddd`
- 安全与仓库卫生
  - .gitignore 补充 result.txt、ksubdomain.yaml（含本机网络配置，避免误提交）
  - 补充 common/backup 源码与 workflow_test.go 到版本控制（此前漏提交，克隆后无法构建）

# v1.1.4 - 2026-08-12 CST

- 修复 Issue #10: -nt 追加自定义 Nuclei 模板后扫描流程被跳过
  - 根因为 SetTemplatesDir 选择了第一个模板目录（外部POC目录）但该目录可能不满足 nuclei 内部路径解析要求
  - Issue #7 修复已通过遍历所有模板目录选择第一个存在目录解决此问题
  - 新增防御性检查：当所有模板目录均不可用时记录告警日志

# v1.1.3 - 2026-07-28 CST

- 修复代码审查发现的多个高危和中危问题
  - ADB 扫描器 slice bounds panic 修复 (adb.go): `buf[24:n]` 增加 `n > 24` 边界检查
  - ICMP genIdentifier panic 修复 (icmp.go): 增加 `len(host) < 2` 边界检查
  - URLParse 返回 nil 修复 (http.go): 解析失败时返回空 `url.URL{}` 而非 nil
  - AES 加解密 nil pointer 修复 (base.go): 检查 `aes.NewCipher` 和 `base64.DecodeString` 错误
  - RDP 扫描器 busy-wait 竞态条件修复 (rdp.go): 移除 `for !signal {}` 循环，改用 `wg.Wait()`
  - FTP Logout 取消注释 (ftp.go): 恢复 `defer conn.Logout()` 防止服务端连接耗尽
  - Signal handler goroutine 泄漏修复 (callnuclei.go): 添加 `signal.Stop(c)` 清理
  - 移除未使用的 `incrNum` 函数 (rdp.go)

# v1.1.2 - 2026-07-28 CST

- 修复 Issue #6: GoPoc Telnet 扫描耗时过长和审计日志标签错误
  - Telnet 连接初始化休眠从 3s 降至 1s
  - loginForOnlyPassword 等待从 3s 降至 1s
  - loginForUsernameAndPassword 等待从 3s+5s 降至 1s+2s
  - 修正 Telnet 扫描审计日志标签从 "RDP-Brute" 改为 "Telnet-Brute"
  - 改进 Telnet 爆破超时计算，基于实际尝试次数而非字典大小

- 修复 Issue #7: 外部 Nuclei POC 目录选择优化
  - Nuclei 默认模板目录选择改为遍历所有目录，选择第一个实际存在的目录

- 修复 Issue #8: RDP 扫描 nil pointer dereference 崩溃
  - 将 grdp 依赖库本地化到 lib/grdp 并添加 nil 检查
  - ServerSecurityData() 增加 c.serverData 为 nil 或长度不足的保护
  - sendClientRandom() 增加 srvData 为 nil 时安全返回
  - sendClientNewLicenseRequest() 增加 srvData nil 检查
  - serverCoreData() 增加 c.serverData nil 保护

- 修复 Issue #9: 端口扫描目标过多
  - discoverAliveHosts() 修复为仅返回存活的 IP 列表，而非原始全量 IP
  - 无人存活的回退：ICMP 和 TCP Ping 均无结果时返回原始 IP 列表

# v1.1.1 - 2026-07-24 11:28 CST

- 版本号升级至 `1.1.1`，作为当前一轮功能整理后的正式版本。
- 整合网站备份扫描、主动指纹软 404 过滤、子域名引擎自动回退、POC 全局 Header 和 workflow POC 关联等更新。
- 完善 Nuclei/GoPoc 日志统计、密码文件追加模式、Interactsh 默认关闭和数据库认证结果确认。

# v1.0.11 - 2026-07-24 08:45 CST

- 修复 `-poc` 模糊搜索只按 POC 文件名匹配的问题：现在会合并匹配产品 workflow 中声明的 POC，文件名不含产品名的漏洞模板也能执行。
- 修正 Nuclei 逐目标日志，统计实际加载的模板数量，并展示 workflow 关联 POC 数量。

# v1.0.10 - 2026-07-23 15:50 CST

- 增加 POC 请求全局 Header 覆盖参数：`-pua/--poc-user-agent` 可强制覆盖 POC 请求 User-Agent，`-ph/--poc-header` 可重复设置任意请求 Header。
- Nuclei POC 透传全局 `CustomHeaders`，覆盖默认随机 User-Agent 和模板内同名 Header。
- GoPoc 手写 HTTP 请求统一应用 POC Header 配置，确保 Shiro、RabbitMQ、Elasticsearch 等 GoPoc 与 Nuclei POC 行为一致。

# v1.0.9 - 2026-07-12 17:31 CST

- 删除已废弃的 `-f/-finger` 指纹强制扫描参数及相关 POC 强制追加逻辑。
- 删除已废弃的 `-pts/--poc-scan-type` POC 扫描类型覆盖参数，漏洞目标选择统一回归 `workflow.yaml` 映射。
- 清理对应配置字段、参数校验和测试断言，减少 CLI 与运行时冗余代码。

# v1.0.8 - 2026-07-04 16:39 CST

- 优化编译脚本体积：增加 `-buildid=` 链接标志，消除 Go build ID；构建完成后自动检测并使用 UPX 压缩可执行文件。
- UPX 压缩策略：Linux/Windows 目标默认启用 UPX，体积可降低约 65%（例如 Linux amd64 从 94M 压缩到 31M）；macOS 目标默认跳过 UPX，避免 `--force-macos` 压缩后的二进制被 Gatekeeper/SIGKILL 拦截。
- 支持环境变量 `DDDD_UPX_FORCE=1` 强制对 macOS 使用 UPX（需自行承担运行兼容性风险），`DDDD_NO_UPX=1` 完全禁用 UPX。
- 统一 Linux amd64 输出文件名为 `dddd_linux_amd64`，与脚本提示一致。

# v1.0.7 - 2026-06-25 23:10 CST

- 优化 Nuclei 逐目标扫描日志：将原来的“加载模板数”改为“加载 workflow 数”，避免与“匹配 POC 数”重复显示相同数值。

# v1.0.6 - 2026-06-25 22:46 CST

- 增加漏洞扫描阶段的 Nuclei 执行计划摘要，展示目标数量、目标-POC 关联数量和去重 POC 数量。
- 增加 Nuclei 逐目标扫描日志，输出当前目标序号、目标地址、匹配 POC 数和实际加载模板数，便于判断正在扫描哪个站点以及用了多少漏洞模板。
- 明确 Nuclei 主机错误跳过提示的含义：目标连续无响应达到阈值后会被跳过，扫描会继续处理其他目标。

# v1.0.5 - 2026-06-23 10:06 CST

- 调整进度条默认策略：默认只输出阶段开始/完成摘要，不再在 Web 探针、主动指纹、端口扫描等阶段按百分比持续刷行。
- 保留显式动态模式：仅当设置 `DDDD_PROGRESS=bar`、`DDDD_PROGRESS=tty` 或 `DDDD_PROGRESS=force` 且 stderr 是 TTY 时才渲染动态进度条。
- 按要求删除上次新增的测试文件，不在项目中保留。

# v1.0.4 - 2026-06-22 17:58 CST

- 优化进度条输出：在 `TERM=dumb`、CI/Codex 等日志式环境默认关闭动态百分比刷新，避免 Web 探针、主动指纹、CDN 识别等阶段刷出大量重复进度行。
- 进度条动画模式减少相同进度的重复渲染，并支持 `DDDD_PROGRESS=bar` 强制动画或 `DDDD_PROGRESS=plain` 强制简洁输出。
- 修复 TCP 端口扫描阈值处理：单个目标开放端口达到阈值后只跳过该目标剩余端口，并继续扫描后续目标。
- 调整端口阈值提示为 warning，并同步修复 SYN 结果过滤时的阈值边界处理。
