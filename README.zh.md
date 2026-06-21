<p align="center">
  <h1>surge2egern</h1>
  <p>将 Surge 规则集转换为 Egern YAML 格式 — 零依赖，单一二进制。</p>
</p>

<p align="center">
  <a href="README.md">English</a>
</p>

<p align="center">
  <a href="#安装">安装</a> ·
  <a href="#用法">用法</a> ·
  <a href="#类型映射">类型映射</a> ·
  <a href="#特殊行为">特殊行为</a> ·
  <a href="LICENSE">许可证</a>
</p>

---

## 特性

- **零依赖** — Go 编写，编译为单一静态二进制文件
- **DOMAIN-SET** 与 **RULE-SET** 支持，格式自动检测
- **逻辑规则** — AND/OR/NOT 完整嵌套支持，输出 Egern 原生 `key: value` 格式
- **远程 URL** — 直接从网络获取规则集（HTTP/2 原生支持）
- **禁用规则保留** — 被注释的规则（`#` 前缀）保留为 YAML 注释，方便手动启用
- **安全的 YAML 输出** — 自动为会破坏 YAML 解析器的值加引号
- **去重** — 重复的值和逻辑块自动合并

## 安装

```bash
go build -ldflags="-s -w" -o surge2egern .
```

或从 [Releases](https://github.com/love4taylor/surge2egern/releases) 下载预编译二进制（macOS / Linux / Windows）。

## 用法

### 基础

```bash
# 转换本地文件（格式自动检测）
surge2egern input.list

# 指定输出路径
surge2egern input.list egern.yaml

# 从 URL 转换
surge2egern https://ruleset.skk.moe/List/domainset/cdn.conf

# 强制指定格式
surge2egern -t rule-set https://ruleset.skk.moe/List/non_ip/cdn.conf cdn.yaml
```

### CLI 参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `-t`, `--type` | 自动 | 强制输入格式：`domain-set` 或 `rule-set` |
| `--timeout` | 30 | HTTP 请求超时（秒） |
| `<input>` | — | 文件路径或 `https://` URL |
| `[output]` | 自动 | 输出 `.yaml` 路径（省略时从输入名派生） |

### 示例

**DOMAIN-SET**（每行一个域名，点前缀为后缀匹配）：

```bash
surge2egern https://ruleset.skk.moe/List/domainset/cdn.conf
```

```yaml
domain_set:
  - cdn.arcade.software
  - static.ada.support
domain_suffix_set:
  - static.microsoft
  - replicate.delivery
  
# ── Disabled rules (commented out in source) ──
# domain_suffix_set:
#   - disabled-suffix.com
```

**RULE-SET** 含逻辑规则：

```bash
surge2egern https://ruleset.skk.moe/List/non_ip/cdn.conf cdn.yaml
```

```yaml
domain_set:
  - cdn.example.com
domain_wildcard_set:
  - "cdn.*.office.net"
  - "*.kuaikan-cdn?.com"
domain_keyword_set:
  - "-files.gitbook.io"
```

## 类型映射

### DOMAIN-SET

| Surge | Egern |
|---|---|
| `domain.com` | `domain_set` |
| `.suffix.com` | `domain_suffix_set`（去除前导 `.`） |

### RULE-SET

| Surge 类型 | Egern 字段 | 备注 |
|---|---|---|
| `DOMAIN` | `domain_set` | |
| `DOMAIN-SUFFIX` | `domain_suffix_set` | |
| `DOMAIN-KEYWORD` | `domain_keyword_set` | |
| `DOMAIN-WILDCARD` | `domain_wildcard_set` | 始终加引号 |
| `IP-CIDR` | `ip_cidr_set` | |
| `IP-CIDR6` | `ip_cidr6_set` | 始终加引号 |
| `GEOIP` | `geoip_set` | 自动去重 |
| `IP-ASN` | `asn_set` | 自动补 `AS` 前缀 |
| `USER-AGENT` | `user_agent_set` | 始终加引号 |
| `URL-REGEX` | `url_regex_set` | 始终加引号 |
| `DEST-PORT` | `dest_port_set` | 始终加引号 |
| `PROTOCOL` | `protocol_set` | 转为小写 |
| `AND`, `OR`, `NOT` | `and_set`, `or_set`, `not_set` | Egern 原生嵌套格式 |
| `SUBNET,SSID:…` | `ssid_set` | |
| `SUBNET,BSSID:…` | `bssid_set` | |
| `SUBNET,TYPE:CELLULAR` | `cellular_set` | |

> [!NOTE]
> `PROCESS-NAME`、`SRC-IP`、`SRC-PORT`、`IN-PORT`、`SUBNET:TYPE:WIFI/WIRED`、`SUBNET:ROUTER` 在 Egern 中**无对应类型**，会跳过并打印警告。

## 特殊行为

### `no_resolve`

任意规则含 `no-resolve` 参数时，输出顶层 `no_resolve: true`：

```
IP-CIDR,172.16.0.0/12,no-resolve
```
```yaml
ip_cidr_set:
  - 172.16.0.0/12
no_resolve: true
```

### 禁用规则

以 `#` 开头且内容像规则的会被保留为 YAML 注释 — 去掉 `# ` 前缀即可启用：

```
#DOMAIN-KEYWORD,-files.gitbook.io
```
```yaml
# domain_keyword_set:
#   - "-files.gitbook.io"
```

纯文本注释和分隔线（`#####`）会被丢弃。

### 逻辑规则

子规则使用 Egern 原生 `key: value` 格式。Egern 不支持的子规则类型（如 `SRC-IP`）会从逻辑块中移除并提示：

```
AND,((SRC-IP,192.168.1.110), (DOMAIN,example.com))
```
```yaml
and_set:
  - and:
    - domain: example.com
```

### YAML 引号

会让 YAML 解析器出错的值会自动加双引号：
- 正则表达式、通配符、IPv6 地址
- ASN 标识符、端口列表
- 以 YAML 标记字符（`-`、`?`、`:`、`[`、`{`、`#`、`&`、`*`、`!` 等）开头的值

## 许可证

MIT © [love4taylor](mailto:i@love4taylor.com)
