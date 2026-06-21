package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ── Data model ────────────────────────────────────────────────────────────

// yVal is either a plain string value or a logical-block.
type yVal any // string | *logicalBlock

// logicalBlock is one entry inside and_set / or_set / not_set.
// e.g. {op:"and", items:[{key:"domain",val:"example.com"}, {op:"not",items:[...]}]}
type logicalBlock struct {
	op    string   // "and", "or", "not"
	items []logItem // sub-items
}

type logItem struct {
	key, val string        // for simple key:value sub-rules
	block    *logicalBlock // for nested logical sub-rules
}

// ── Mappings ──────────────────────────────────────────────────────────────

var surgeToEgern = map[string]string{
	"DOMAIN": "domain_set", "DOMAIN-SUFFIX": "domain_suffix_set",
	"DOMAIN-KEYWORD": "domain_keyword_set", "DOMAIN-WILDCARD": "domain_wildcard_set",
	"IP-CIDR": "ip_cidr_set", "IP-CIDR6": "ip_cidr6_set",
	"GEOIP": "geoip_set", "IP-ASN": "asn_set",
	"USER-AGENT": "user_agent_set", "URL-REGEX": "url_regex_set",
	"DEST-PORT": "dest_port_set", "PROTOCOL": "protocol_set",
}

var surgeToEgernSub = map[string]string{
	"DOMAIN": "domain", "DOMAIN-SUFFIX": "domain_suffix",
	"DOMAIN-KEYWORD": "domain_keyword", "DOMAIN-WILDCARD": "domain_wildcard",
	"IP-CIDR": "ip_cidr", "IP-CIDR6": "ip_cidr6",
	"GEOIP": "geoip", "IP-ASN": "asn",
	"USER-AGENT": "user_agent", "URL-REGEX": "url_regex",
	"DEST-PORT": "dest_port", "PROTOCOL": "protocol",
}

var protocolMap = map[string]string{
	"HTTP": "http", "HTTPS": "https", "TCP": "tcp", "UDP": "udp",
	"DOH": "doh", "DOH3": "doh3", "DOQ": "doq", "QUIC": "quic", "STUN": "stun",
}

var alwaysQuoteKeys = map[string]bool{
	"domain_regex_set": true, "domain_wildcard_set": true,
	"ip_cidr6_set": true, "ip_cidr6": true,
	"asn_set": true, "asn": true,
	"user_agent_set": true, "user_agent": true,
	"url_regex_set": true, "url_regex": true,
	"dest_port_set": true, "dest_port": true,
	"domain_regex": true, "domain_wildcard": true,
}

var yamlIndStart = regexp.MustCompile(`^[-?:,\[\]{}#&*!|>'\"%@` + "`" + `]`)
var yamlNeedQuote = regexp.MustCompile(`[*?|:\\[\]{}!&><=%#@` + "`" + `]|::|\bAS\d`)

// ── Helpers ───────────────────────────────────────────────────────────────

func warn(msg string) { fmt.Fprintln(os.Stderr, "⚠ ", msg) }
func isURL(s string) bool  { return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") }

func guessFilename(rawURL, suffix string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "ruleset" + suffix
	}
	stem := strings.TrimSuffix(path.Base(u.Path), path.Ext(u.Path))
	if stem == "" || stem == "/" || stem == "." {
		stem = "ruleset"
	}
	return stem + suffix
}

func stripComment(line string) (content string, disabled bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", false
	}
	if strings.HasPrefix(line, "#") {
		content := strings.TrimSpace(line[1:])
		if content == "" {
			return "", false
		}
		// Only treat as disabled rule if content looks like a rule or domain.
		// Plain comments (text, separators like "#####") are discarded.
		if looksLikeRuleOrDomain(content) {
			return content, true
		}
		return "", false
	}
	if strings.HasPrefix(line, ";") {
		return "", false
	}
	if strings.HasPrefix(line, "//") && !strings.Contains(line, "://") {
		return "", false
	}
	if idx := strings.Index(line, ";"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	if idx := strings.Index(line, "//"); idx >= 0 {
		// Not a comment if preceded by ':' — part of :// (http://, etc.)
		if idx == 0 || line[idx-1] != ':' {
			line = strings.TrimSpace(line[:idx])
		}
	}
	return line, false
}

func parseSurgeRule(line string) (string, []string) {
	idx := strings.Index(line, ",")
	if idx < 0 {
		return "", nil
	}
	rt := strings.ToUpper(strings.TrimSpace(line[:idx]))
	rest := line[idx+1:]
	if rt == "AND" || rt == "OR" || rt == "NOT" {
		return rt, []string{rest}
	}
	var vals []string
	for _, p := range strings.Split(rest, ",") {
		vals = append(vals, strings.TrimSpace(p))
	}
	return rt, vals
}

func popParam(vals *[]string, param string) bool {
	for i, v := range *vals {
		if strings.EqualFold(v, param) {
			*vals = append((*vals)[:i], (*vals)[i+1:]...)
			return true
		}
	}
	return false
}

func normalizeASN(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(strings.ToUpper(v), "AS") {
		if _, err := strconv.Atoi(v[2:]); err == nil {
			return "AS" + v[2:]
		}
		return v
	}
	if _, err := strconv.Atoi(v); err == nil {
		return "AS" + v
	}
	return v
}

// looksLikeRuleOrDomain returns true if content after "#" resembles a
// disabled Surge rule rather than a plain comment.
func looksLikeRuleOrDomain(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	// Check if it starts with a known rule type
	firstWord := strings.ToUpper(strings.SplitN(s, ",", 2)[0])
	if _, ok := surgeToEgern[firstWord]; ok {
		return true
	}
	if firstWord == "AND" || firstWord == "OR" || firstWord == "NOT" || firstWord == "SUBNET" {
		return true
	}
	// DOMAIN-SET style: starts with "." or looks like a domain name
	if strings.HasPrefix(s, ".") {
		return true
	}
	// Looks like a domain: contains dot, no spaces, not just repeated chars
	if strings.Contains(s, ".") && !strings.Contains(s, " ") {
		// Reject strings that are just repeated same character (e.g. "#####")
		if len(s) > 3 && allSameChar(s) {
			return false
		}
		return true
	}
	return false
}

func allSameChar(s string) bool {
	if len(s) == 0 {
		return false
	}
	first := s[0]
	for i := 1; i < len(s); i++ {
		if s[i] != first {
			return false
		}
	}
	return true
}

func dedup(vals []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func needsQuoting(value, keyHint string) bool {
	if value == "" {
		return false
	}
	if alwaysQuoteKeys[keyHint] {
		return true
	}
	if yamlIndStart.MatchString(value) {
		return true
	}
	if yamlNeedQuote.MatchString(value) {
		return true
	}
	return false
}

func yamlScalar(value, keyHint string) string {
	if needsQuoting(value, keyHint) {
		return strconv.Quote(value)
	}
	return value
}

// ── Logical body parser ───────────────────────────────────────────────────

func parseLogicalBody(expr string) [][2]any { // returns []{type: string, vals: []string}
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") {
		expr = strings.TrimSpace(expr[1 : len(expr)-1])
	}
	var out [][2]any
	depth := 0
	var buf strings.Builder

	for _, ch := range expr {
		switch ch {
		case '(':
			if depth == 0 {
				buf.Reset()
			} else {
				buf.WriteRune(ch)
			}
			depth++
		case ')':
			depth--
			if depth == 0 {
				rt, vals := parseSurgeRule(strings.TrimSpace(buf.String()))
				if rt != "" {
					out = append(out, [2]any{rt, vals})
				}
				buf.Reset()
			} else {
				buf.WriteRune(ch)
			}
		default:
			if depth > 0 {
				buf.WriteRune(ch)
			}
		}
	}
	return out
}

// ── Convert sub-rule → logItem ────────────────────────────────────────────

func convertSubruleItem(rt string, vals []string) *logItem {
	ek, ok := surgeToEgernSub[rt]
	if !ok {
		warn(fmt.Sprintf("Skipping sub-rule '%s' — no Egern equivalent in logical rules", rt))
		return nil
	}
	val := ""
	if len(vals) > 0 {
		val = vals[0]
	}

	// SUBNET decomposition
	if rt == "SUBNET" && strings.Contains(val, ":") {
		parts := strings.SplitN(val, ":", 2)
		pfx, body := strings.ToUpper(parts[0]), parts[1]
		switch pfx {
		case "SSID":
			return &logItem{key: "ssid", val: body}
		case "BSSID":
			return &logItem{key: "bssid", val: body}
		case "TYPE":
			if strings.EqualFold(body, "CELLULAR") {
				return &logItem{key: "cellular", val: "*"}
			}
			warn(fmt.Sprintf("Skipping SUBNET TYPE:%s sub-rule", body))
			return nil
		case "ROUTER":
			warn("Skipping SUBNET ROUTER sub-rule")
			return nil
		}
		return nil
	}

	// Normalize
	switch rt {
	case "IP-ASN":
		val = normalizeASN(val)
	case "PROTOCOL":
		if m, ok := protocolMap[strings.ToUpper(val)]; ok {
			val = m
		} else {
			val = strings.ToLower(val)
		}
	}
	return &logItem{key: ek, val: val}
}

// ── Converters ────────────────────────────────────────────────────────────

type resultData struct {
	sets      map[string][]yVal // set-name → values (string or *logicalBlock)
	noResolve bool
	disabled  map[string][]string
}

func newResult() *resultData {
	return &resultData{sets: map[string][]yVal{}, disabled: map[string][]string{}}
}

func (r *resultData) add(setName, value string) {
	r.sets[setName] = append(r.sets[setName], value)
}

func (r *resultData) addDisabled(setName, value string) {
	r.disabled[setName] = append(r.disabled[setName], value)
}

func (r *resultData) addLogical(setName string, block *logicalBlock) {
	r.sets[setName] = append(r.sets[setName], block)
}

func (r *resultData) dedupSets() {
	for k, vals := range r.sets {
		seen := map[string]bool{}
		uniq := make([]yVal, 0, len(vals))
		for _, v := range vals {
			if s, ok := v.(string); ok {
				if !seen[s] {
					seen[s] = true
					uniq = append(uniq, s)
				}
			} else if b, ok := v.(*logicalBlock); ok {
				// Dedup logical blocks by their YAML representation
				key := logicalBlockKey(b)
				if !seen[key] {
					seen[key] = true
					uniq = append(uniq, b)
				}
			} else {
				uniq = append(uniq, v)
			}
		}
		r.sets[k] = uniq
	}
	for k, vals := range r.disabled {
		r.disabled[k] = dedup(vals)
	}
}

func logicalBlockKey(b *logicalBlock) string {
	// Build a deterministic string key for dedup (no indentation).
	// Don't use writeLogicalBlock because it includes indentation.
	return logicalBlockSig(b)
}

func logicalBlockSig(b *logicalBlock) string {
	var sb strings.Builder
	sb.WriteString(b.op)
	sb.WriteString(":")
	for _, item := range b.items {
		sb.WriteString("|")
		if item.block != nil {
			sb.WriteString(logicalBlockSig(item.block))
		} else {
			sb.WriteString(item.key)
			sb.WriteString("=")
			sb.WriteString(item.val)
		}
	}
	return sb.String()
}

func convertDomainSet(lines []string) *resultData {
	r := newResult()
	for _, raw := range lines {
		line, dis := stripComment(raw)
		if line == "" {
			continue
		}
		// Skip metadata headers
		if !strings.Contains(line, ",") && !strings.HasPrefix(line, ".") && !strings.HasPrefix(line, "+") {
			if strings.Contains(line, " ") || strings.Contains(line, "_") || len(line) > 60 {
				continue
			}
		}
		var setName, val string
		if strings.HasPrefix(line, ".") {
			setName = "domain_suffix_set"
			val = line[1:]
		} else {
			setName = "domain_set"
			val = line
		}
		if val == "" {
			continue
		}
		if dis {
			r.addDisabled(setName, val)
		} else {
			r.add(setName, val)
		}
	}
	r.dedupSets()
	return r
}

func convertRuleSet(lines []string) *resultData {
	r := newResult()
	for _, raw := range lines {
		line, dis := stripComment(raw)
		if line == "" {
			continue
		}
		rt, vals := parseSurgeRule(line)
		if rt == "" {
			continue
		}
		if popParam(&vals, "no-resolve") {
			r.noResolve = true
		}
		switch {
		case rt == "AND" || rt == "OR" || rt == "NOT":
			block := buildLogicalBlock(rt, vals)
			if block != nil {
				r.addLogical(strings.ToLower(rt)+"_set", block)
			}
		case rt == "SUBNET":
			handleSubnetResult(r, vals, dis)
		default:
			egernKey, ok := surgeToEgern[rt]
			if !ok {
				warn(fmt.Sprintf("Skipping (no Egern equivalent): %s", line))
				continue
			}
			val := ""
			if len(vals) > 0 {
				val = vals[0]
			}
			switch rt {
			case "IP-ASN":
				val = normalizeASN(val)
			case "PROTOCOL":
				if m, ok := protocolMap[strings.ToUpper(val)]; ok {
					val = m
				} else {
					val = strings.ToLower(val)
				}
			}
			if dis {
				r.addDisabled(egernKey, val)
			} else {
				r.add(egernKey, val)
			}
		}
	}
	r.dedupSets()
	return r
}

func handleSubnetResult(r *resultData, vals []string, dis bool) {
	if len(vals) == 0 {
		return
	}
	expr := vals[0]
	if !strings.Contains(expr, ":") {
		warn("Skipping SUBNET without prefix")
		return
	}
	parts := strings.SplitN(expr, ":", 2)
	pfx, body := strings.ToUpper(parts[0]), parts[1]
	var setName, val string
	switch pfx {
	case "SSID":
		setName, val = "ssid_set", body
	case "BSSID":
		setName, val = "bssid_set", body
	case "TYPE":
		if strings.EqualFold(body, "CELLULAR") {
			setName, val = "cellular_set", "*"
		} else {
			warn(fmt.Sprintf("Skipping SUBNET TYPE:%s", body))
			return
		}
	case "ROUTER":
		warn("Skipping SUBNET ROUTER")
		return
	default:
		warn(fmt.Sprintf("Skipping unrecognized SUBNET prefix: %s", pfx))
		return
	}
	if dis {
		r.addDisabled(setName, val)
	} else {
		r.add(setName, val)
	}
}

func buildLogicalBlock(rt string, vals []string) *logicalBlock {
	expr := ""
	if len(vals) > 0 {
		expr = vals[0]
	}
	subs := parseLogicalBody(expr)
	if len(subs) == 0 {
		return nil
	}
	var items []logItem
	for _, sr := range subs {
		st := sr[0].(string)
		sv := sr[1].([]string)
		switch st {
		case "AND", "OR", "NOT":
			nested := buildLogicalBlock(st, sv)
			if nested != nil {
				items = append(items, logItem{block: nested})
			}
		default:
			li := convertSubruleItem(st, sv)
			if li != nil {
				items = append(items, *li)
			}
		}
	}
	if len(items) == 0 {
		return nil
	}
	return &logicalBlock{op: strings.ToLower(rt), items: items}
}

// ── Format detection ──────────────────────────────────────────────────────

func detectFormat(lines []string) string {
	for _, raw := range lines {
		line, _ := stripComment(raw)
		if line == "" {
			continue
		}
		first := strings.ToUpper(strings.SplitN(line, ",", 2)[0])
		if _, ok := surgeToEgern[first]; ok {
			return "rule-set"
		}
		if first == "AND" || first == "OR" || first == "NOT" || first == "SUBNET" {
			return "rule-set"
		}
	}
	return "domain-set"
}

// ── YAML generator ────────────────────────────────────────────────────────

func generateYAML(r *resultData) string {
	var sb strings.Builder

	keyOrder := []string{
		"domain_set", "domain_suffix_set", "domain_keyword_set",
		"domain_regex_set", "domain_wildcard_set",
		"ip_cidr_set", "ip_cidr6_set", "geoip_set", "asn_set",
		"user_agent_set", "url_regex_set",
		"and_set", "or_set", "not_set",
		"ssid_set", "bssid_set", "cellular_set",
		"dest_port_set", "protocol_set",
	}

	seen := map[string]bool{}
	first := true

	for _, k := range keyOrder {
		if vals, ok := r.sets[k]; ok && len(vals) > 0 {
			if first {
				first = false
			} else {
				sb.WriteString("\n")
			}
			writeSetYAML(&sb, k, vals)
			seen[k] = true
		}
	}
	for k, vals := range r.sets {
		if !seen[k] && len(vals) > 0 {
			if first {
				first = false
			} else {
				sb.WriteString("\n")
			}
			writeSetYAML(&sb, k, vals)
		}
	}

	if r.noResolve {
		sb.WriteString("\nno_resolve: true")
	}

	// Disabled rules
	writeDisabledYAML(&sb, r.disabled)

	if !strings.HasSuffix(sb.String(), "\n") {
		sb.WriteString("\n")
	}
	return sb.String()
}

func writeSetYAML(sb *strings.Builder, name string, vals []yVal) {
	sb.WriteString(name)
	sb.WriteString(":")
	for _, v := range vals {
		switch x := v.(type) {
		case string:
			sb.WriteString("\n  - ")
			sb.WriteString(yamlScalar(x, name))
		case *logicalBlock:
			writeLogicalBlock(sb, x, 2)
		}
	}
}

func writeLogicalBlock(sb *strings.Builder, b *logicalBlock, indent int) {
	pad := strings.Repeat("  ", indent)
	sb.WriteString("\n")
	if len(pad) >= 2 {
		sb.WriteString(pad[:len(pad)-2]) // un-indent the "- "
	}
	sb.WriteString("- ")
	sb.WriteString(b.op)
	sb.WriteString(":")
	for _, item := range b.items {
		sb.WriteString("\n")
		sb.WriteString(pad)
		sb.WriteString("- ")
		if item.block != nil {
			writeLogicalNested(sb, item.block, indent+2)
		} else {
			sb.WriteString(item.key)
			sb.WriteString(": ")
			sb.WriteString(yamlScalar(item.val, item.key))
		}
	}
}

func writeLogicalNested(sb *strings.Builder, b *logicalBlock, indent int) {
	pad := strings.Repeat("  ", indent)
	sb.WriteString(b.op)
	sb.WriteString(":")
	for _, item := range b.items {
		sb.WriteString("\n")
		sb.WriteString(pad)
		sb.WriteString("- ")
		if item.block != nil {
			writeLogicalNested(sb, item.block, indent+2)
		} else {
			sb.WriteString(item.key)
			sb.WriteString(": ")
			sb.WriteString(yamlScalar(item.val, item.key))
		}
	}
}

func writeDisabledYAML(sb *strings.Builder, disabled map[string][]string) {
	if len(disabled) == 0 {
		return
	}
	sb.WriteString("\n\n# ── Disabled rules (commented out in source) ──")

	keys := make([]string, 0, len(disabled))
	for k := range disabled {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, setName := range keys {
		vals := disabled[setName]
		if len(vals) == 0 {
			continue
		}
		sb.WriteString("\n# ")
		sb.WriteString(setName)
		sb.WriteString(":")
		for _, v := range vals {
			sb.WriteString("\n#   - ")
			sb.WriteString(yamlScalar(v, setName))
		}
	}
	sb.WriteString("\n")
}

// ── HTTP fetch ────────────────────────────────────────────────────────────

func fetchURL(rawURL string, timeout int) (string, []string, error) {
	fmt.Fprintf(os.Stderr, "⬇  Fetching %s …\n", rawURL)

	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
	}
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return "", nil, fmt.Errorf("bad URL: %w", err)
	}
	req.Header.Set("User-Agent", "surge2egern/2.0")
	req.Header.Set("Accept", "text/plain,*/*")

	// Retry on transient errors (max 3 attempts)
	var resp *http.Response
	for attempt := 1; attempt <= 3; attempt++ {
		resp, err = client.Do(req)
		if err == nil {
			break
		}
		if attempt < 3 {
			wait := time.Duration(attempt) * time.Second
			fmt.Fprintf(os.Stderr, "   ↳ retry %d/3 after %v: %v\n", attempt, wait, err)
			time.Sleep(wait)
		}
	}
	if err != nil {
		return "", nil, fmt.Errorf("request failed after retries: %w", err)
	}
	defer resp.Body.Close()

	// Reject non-200 status
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("HTTP %d (%s)", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	// Reject non-text content types (HTML error pages, etc.)
	ct := resp.Header.Get("Content-Type")
	if ct != "" {
		mediaType := strings.SplitN(ct, ";", 2)[0]
		if mediaType != "text/plain" && !strings.HasPrefix(mediaType, "text/") {
			return "", nil, fmt.Errorf("unexpected Content-Type: %s (expected text/plain)", ct)
		}
	}

	finalURL := resp.Request.URL.String()
	if finalURL != rawURL {
		fmt.Fprintf(os.Stderr, "   ↳ redirected to %s\n", finalURL)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10 MB limit
	if err != nil {
		return "", nil, fmt.Errorf("read body: %w", err)
	}

	text := string(body)
	if len(body) == 0 {
		return "", nil, fmt.Errorf("empty response body")
	}

	// Heuristic: reject responses that look like HTML error pages
	if looksLikeHTML(text) {
		return "", nil, fmt.Errorf("response looks like HTML, not a rule set (server may be down)")
	}

	lines := strings.Split(text, "\n")
	fmt.Fprintf(os.Stderr, "   ✓ %d lines, %d bytes\n", len(lines), len(body))
	return finalURL, lines, nil
}

func looksLikeHTML(text string) bool {
	// Trim leading whitespace (Cloudflare error pages often start with blank lines)
	trimmed := strings.TrimSpace(text)
	if len(trimmed) == 0 {
		return false
	}
	// Check for HTML signatures in the first 512 bytes
	head := trimmed
	if len(head) > 512 {
		head = head[:512]
	}
	lower := strings.ToLower(head)
	return strings.Contains(lower, "<!doctype") ||
		strings.Contains(lower, "<html") ||
		strings.Contains(lower, "<head") ||
		strings.Contains(lower, "<body")
}

// ── Main ──────────────────────────────────────────────────────────────────

func main() {
	format := flag.String("t", "", "Force input format: domain-set or rule-set")
	formatLong := flag.String("type", "", "Force input format: domain-set or rule-set")
	timeout := flag.Int("timeout", 30, "HTTP request timeout in seconds")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: surge2egern [options] <input> [output]

Convert Surge rule sets to Egern YAML rule set format.

Arguments:
  input    File path or HTTP(S) URL to the Surge rule set
  output   Output YAML file path (default: auto-generated from input name)

Options:
  -t, --type FORMAT   Force input format: domain-set or rule-set
  --timeout SECONDS   HTTP request timeout (default: 30)

Examples:
  surge2egern input.list
  surge2egern input.list output.yaml
  surge2egern -t domain-set https://ruleset.skk.moe/List/domainset/cdn.conf
  surge2egern https://ruleset.skk.moe/List/non_ip/cdn.conf cdn.yaml
`)
	}

	flag.Parse()

	// Resolve format (-t takes precedence over --type)
	fmtArg := *format
	if fmtArg == "" {
		fmtArg = *formatLong
	}

	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(1)
	}

	input := args[0]
	var outputPath string
	if len(args) >= 2 {
		outputPath = args[1]
	}

	if fmtArg != "" && fmtArg != "domain-set" && fmtArg != "rule-set" {
		fmt.Fprintf(os.Stderr, "❌ Invalid format: %s (use domain-set or rule-set)\n", fmtArg)
		os.Exit(1)
	}

	// Fetch input
	var lines []string
	if isURL(input) {
		finalURL, fetchedLines, err := fetchURL(input, *timeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ %v\n", err)
			os.Exit(1)
		}
		lines = fetchedLines
		if outputPath == "" {
			outputPath = guessFilename(finalURL, ".yaml")
		}
	} else {
		data, err := os.ReadFile(input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Cannot read file: %v\n", err)
			os.Exit(1)
		}
		lines = strings.Split(string(data), "\n")
		if outputPath == "" {
			ext := path.Ext(input)
			if ext != "" {
				outputPath = input[:len(input)-len(ext)] + ".yaml"
			} else {
				outputPath = input + ".yaml"
			}
		}
	}

	// Detect format
	if fmtArg == "" {
		fmtArg = detectFormat(lines)
		fmt.Fprintf(os.Stderr, "ℹ  Detected format: %s\n", fmtArg)
	}

	// Convert
	var r *resultData
	switch fmtArg {
	case "domain-set":
		r = convertDomainSet(lines)
	case "rule-set":
		r = convertRuleSet(lines)
	default:
		fmt.Fprintf(os.Stderr, "❌ Unknown format: %s\n", fmtArg)
		os.Exit(1)
	}

	if len(r.sets) == 0 && len(r.disabled) == 0 {
		warn("Output is empty — no rules were converted.")
	}

	// Generate YAML
	yamlText := generateYAML(r)

	// Write output
	if err := os.WriteFile(outputPath, []byte(yamlText), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Cannot write output: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "✅ Converted → %s\n", outputPath)
}
