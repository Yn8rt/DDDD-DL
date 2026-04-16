# Nuclei Templates for HW 2025

## 仓库简介

这个仓库专门收集2025年HVV期间公开披露的漏洞POC和漏洞检测模板，使用Nuclei框架格式编写。

## Nuclei简介

Nuclei是一款快速、可定制的漏洞扫描工具，基于YAML模板系统工作。它能够帮助安全研究人员快速识别目标系统中的已知漏洞。

## 安装Nuclei

### 二进制安装（推荐）

1. 下载最新版Nuclei：
   ```bash
   go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
   ```

2. 或者从发布页面下载预编译二进制文件：
   https://github.com/projectdiscovery/nuclei/releases

### 源码编译

```bash
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

## 使用方法

### 基本扫描

```bash
nuclei -u https://example.com -t hw2025/
```

### 批量扫描URL列表

```bash
nuclei -list urls.txt -t hw2025/
```

### 使用特定模板

```bash
nuclei -u https://example.com -t hw2025/cves/CVE-2025-XXXX.yaml
```

### 常用参数

- `-severity`：按严重程度过滤（critical,high,medium,low,info）
- `-tags`：按标签过滤
- `-rate-limit`：限制请求速率（默认150/秒）
- `-timeout`：超时设置（默认10秒）
- `-retries`：重试次数（默认1）
- `-proxy`：使用代理

## 模板更新

建议定期更新Nuclei和模板：

```bash
nuclei -update
nuclei -ut
```

## 免责声明

本仓库仅用于合法安全测试和研究目的。使用者应遵守所有适用法律，并确保获得适当的授权后再进行扫描测试。仓库维护者对任何滥用行为概不负责。

## 贡献指南

欢迎提交HW期间发现的漏洞POC模板！请确保：

1. 模板格式符合Nuclei规范
2. 包含详细的漏洞描述和参考链接
3. 经过测试验证可用
4. 不包含敏感信息或攻击性payload

提交PR时请说明漏洞影响和验证方法。

## 许可证

本仓库采用MIT许可证，详见LICENSE文件。
