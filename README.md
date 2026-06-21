<p align="center">
  <h1>surge2egern</h1>
  <p>Convert Surge rule sets to Egern YAML format — zero deps, single binary.</p>
</p>

<p align="center">
  <a href="README.zh.md">中文</a>
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#usage">Usage</a> ·
  <a href="#type-mapping">Type Mapping</a> ·
  <a href="#special-behaviors">Behaviors</a> ·
  <a href="LICENSE">License</a>
</p>

---

## Features

- **Zero dependencies** — written in Go, compiles to a single static binary
- **DOMAIN-SET** and **RULE-SET** support with auto-detection
- **Logical rules** — AND/OR/NOT with full nesting support, output in Egern-native `key: value` format
- **Remote URLs** — fetch rule sets directly from the web (HTTP/2 native)
- **Disabled rule preservation** — commented-out rules (`#` prefix) are kept as YAML comments for easy re-enabling
- **Safe YAML output** — automatic quoting for values that would break YAML parsers
- **Deduplication** — duplicate values and logical blocks are merged

## Install

```bash
go build -ldflags="-s -w" -o surge2egern .
```

Or grab a [prebuilt binary](https://github.com/love4taylor/surge2egern/releases) for macOS / Linux / Windows.

## Usage

### Basic

```bash
# Convert a local file (format auto-detected)
surge2egern input.list

# Specify output path
surge2egern input.list egern.yaml

# Convert from URL
surge2egern https://ruleset.skk.moe/List/domainset/cdn.conf

# Force format if detection fails
surge2egern -t rule-set https://ruleset.skk.moe/List/non_ip/cdn.conf cdn.yaml
```

### CLI reference

| Flag | Default | Description |
|---|---|---|
| `-t`, `--type` | auto | Force input format: `domain-set` or `rule-set` |
| `--timeout` | 30 | HTTP request timeout in seconds |
| `<input>` | — | File path or `https://` URL |
| `[output]` | auto | Output `.yaml` path (derived from input name if omitted) |

### Examples

**DOMAIN-SET** (one domain per line, dot-prefix for suffix match):

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

**RULE-SET** with logical rules:

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

## Type mapping

### DOMAIN-SET

| Surge | Egern |
|---|---|
| `domain.com` | `domain_set` |
| `.suffix.com` | `domain_suffix_set` (leading `.` stripped) |

### RULE-SET

| Surge type | Egern field | Notes |
|---|---|---|
| `DOMAIN` | `domain_set` | |
| `DOMAIN-SUFFIX` | `domain_suffix_set` | |
| `DOMAIN-KEYWORD` | `domain_keyword_set` | |
| `DOMAIN-WILDCARD` | `domain_wildcard_set` | always quoted |
| `IP-CIDR` | `ip_cidr_set` | |
| `IP-CIDR6` | `ip_cidr6_set` | always quoted |
| `GEOIP` | `geoip_set` | deduplicated |
| `IP-ASN` | `asn_set` | `AS` prefix auto‑added |
| `USER-AGENT` | `user_agent_set` | always quoted |
| `URL-REGEX` | `url_regex_set` | always quoted |
| `DEST-PORT` | `dest_port_set` | always quoted |
| `PROTOCOL` | `protocol_set` | lowercased |
| `AND`, `OR`, `NOT` | `and_set`, `or_set`, `not_set` | nested Egern-native format |
| `SUBNET,SSID:…` | `ssid_set` | |
| `SUBNET,BSSID:…` | `bssid_set` | |
| `SUBNET,TYPE:CELLULAR` | `cellular_set` | |

> [!NOTE]
> `PROCESS-NAME`, `SRC-IP`, `SRC-PORT`, `IN-PORT`, `SUBNET:TYPE:WIFI/WIRED`, and `SUBNET:ROUTER` have **no Egern equivalent** and are skipped with a warning.

## Special behaviors

### `no_resolve`

If any rule carries the `no-resolve` parameter, the output gets a top-level `no_resolve: true`:

```
IP-CIDR,172.16.0.0/12,no-resolve
```
```yaml
ip_cidr_set:
  - 172.16.0.0/12
no_resolve: true
```

### Disabled rules

Lines starting with `#` that look like actual rules are preserved as YAML comments — remove the `# ` prefix to enable them:

```
#DOMAIN-KEYWORD,-files.gitbook.io
```
```yaml
# domain_keyword_set:
#   - "-files.gitbook.io"
```

Plain text comments and separators (`#####`) are discarded.

### Logical rules

Sub-rules use Egern-native `key: value` format. Types without an Egern equivalent (like `SRC-IP`) are dropped from logical blocks with a warning:

```
AND,((SRC-IP,192.168.1.110), (DOMAIN,example.com))
```
```yaml
and_set:
  - and:
    - domain: example.com
```

### YAML quoting

Values that would break YAML parsers are automatically double-quoted:
- Regex patterns, wildcards, IPv6 addresses
- ASN identifiers, port lists
- Values starting with YAML indicator characters (`-`, `?`, `:`, `[`, `{`, `#`, `&`, `*`, `!`, etc.)

## License

MIT © [love4taylor](mailto:i@love4taylor.com)
