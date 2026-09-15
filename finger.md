dddd 指纹规则语法完全由 lib/ddfinger/parse.go 控制，总结如下：
1. 原子条件格式
key="value"
ParseRule 以 =" 为分隔符提取 key、value 和整个 token，并将每个匹配到的 token 替换为 T/F，剩余部分按布尔表达式求值。
2. 支持的 key
key	含义
body	HTTP body
header	HTTP 响应头
server	Server 头值
title	页面 title
cert	TLS 证书内容
path	请求路径
body_hash	响应 body 的 hash
icon_hash	favicon hash（FOFA mmh3 signed int）
status	HTTP 状态码
port	端口
protocol	协议（http/https/...）
content_type	Content-Type 头
banner	TCP banner
type	服务类型，仅支持 type="service"
其他 key 一律 return false。
3. 操作符
操作符	编码	作用
=	0	字符串包含 / 整数等于
!=	1	字符串不包含 / 整数不等于
==	2	字符串完全相等
>=	3	整数大于等于（仅数字 key）
<=	4	整数小于等于（仅数字 key）
~=	5	字符串正则匹配（regexp.MatchString）
数字 key 仅支持 port、status、icon_hash；>=/<= 只在 dataCheckInt 中实现，对字符串 key 无效。
4. 字符串匹配处理
- 比较前全部转小写。
- value 中的 \" 会替换为 "。
- = 使用 strings.Contains。
- == 使用完全相等。
- ~= 使用 Go 正则，语法错误则匹配失败。
5. 布尔表达式
支持 &&、&、||、|、!、()，优先级：
1. !（最高）
2. && / &
3. || / |
4. ()
逻辑执行流程：
1. ParseRule 提取所有原子条件并替换为 T 或 F。
2. boolEval 将表达式转换为后缀表达式并求值。
3. 括号不匹配会 Fatal。
6. 特殊处理
- 所有空格会被 boolEval 去除。
- 空表达式 () 会被去除。
- 如果表达式中没有任何 T/F，直接返回 false。
- 双 !! 会互相抵消。
- 字符串 key 只接受小写 a-z 和下划线 _ 组成；遇到其他字符即截断作为 key 起点。
- icon_hash 值必须是可被 strconv.Atoi 解析的整数，否则条件直接为 false。
7. Web 与非 Web
- body、header、server、title、path、body_hash、icon_hash、status、content_type 只在 isWeb == true 时有效，否则为 false。
- cert、port、protocol、banner、type 不依赖 isWeb。
