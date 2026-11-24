package ninja

// Ninja subscription deobfuscation, originally reconstructed by AirportR from
// the mihomo-ninja reference core, hardened with:
//   - strict field allowlists for #!PASS-INFO set/replace injection
//   - support for both node_password and node-password keys
//   - explicit nil/empty guards on BaseN decoding
//   - reusable entry point for both main config and per-provider parsing

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/log"
)

const (
	ninjaAlpha36 = "0123456789abcdefghijklmnopqrstuvwxyz"
	ninjaAlpha69 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@#$%^&*"
	ninjaPassKey = "ninja-pass-info"
)

// passInfoSetAllowlist restricts which proxy keys #!PASS-INFO "set" may write.
// Keys are normalized to lowercase with '_' replaced by '-'.
var passInfoSetAllowlist = map[string]struct{}{
	"tls":                {},
	"servername":         {},
	"sni":                {},
	"skip-cert-verify":   {},
	"client-fingerprint": {},
	"network":            {},
	"ws-opts":            {},
	"pass":               {},
	"pass-opts":          {},
	"method":             {},
	"udp":                {},
	"password":           {},
	"node-password":      {},
}

// passInfoReplaceAllowlist allows "replace" rules (which match a specific
// server) to also update server/port in addition to transport/pass fields, while
// still blocking unrelated fields such as type, name, dialer-proxy,
// interface-name, or routing-mark.
var passInfoReplaceAllowlist = map[string]struct{}{
	"server":             {},
	"port":               {},
	"tls":                {},
	"servername":         {},
	"sni":                {},
	"skip-cert-verify":   {},
	"client-fingerprint": {},
	"network":            {},
	"ws-opts":            {},
	"pass":               {},
	"pass-opts":          {},
	"method":             {},
	"udp":                {},
	"password":           {},
	"node-password":      {},
}

func normalizeKey(k string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(k)), "_", "-")
}

func ninjaSaltShuffle(alpha, salt string) []byte {
	type pair struct {
		ch  byte
		sum [32]byte
	}
	ps := make([]pair, 0, len(alpha))
	for i := 0; i < len(alpha); i++ {
		ps = append(ps, pair{ch: alpha[i], sum: sha256.Sum256([]byte(salt + "|" + string(alpha[i])))})
	}
	sort.SliceStable(ps, func(i, j int) bool { return bytes.Compare(ps[i].sum[:], ps[j].sum[:]) < 0 })
	out := make([]byte, len(ps))
	for i, p := range ps {
		out[i] = p.ch
	}
	return out
}

// ninjaBaseNDecode decodes s as a big endian integer over alpha.
func ninjaBaseNDecode(s string, alpha []byte) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("empty baseN input")
	}
	idx := make(map[byte]int, len(alpha))
	for i, c := range alpha {
		idx[c] = i
	}
	n := len(alpha)
	acc := []byte{0}
	for i := 0; i < len(s); i++ {
		d, ok := idx[s[i]]
		if !ok {
			return nil, fmt.Errorf("invalid baseN character %q", s[i])
		}
		carry := d
		for j := 0; j < len(acc); j++ {
			v := int(acc[j])*n + carry
			acc[j] = byte(v & 0xff)
			carry = v >> 8
		}
		for carry > 0 {
			acc = append(acc, byte(carry&0xff))
			carry >>= 8
		}
	}
	for len(acc) > 1 && acc[len(acc)-1] == 0 {
		acc = acc[:len(acc)-1]
	}
	out := make([]byte, len(acc))
	for i := range acc {
		out[i] = acc[len(acc)-1-i]
	}
	return out, nil
}

func ninjaStrXor(data []byte, key string) []byte {
	k := sha256.Sum256([]byte(key))
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ k[i&0x1f]
	}
	return out
}

func ninjaInflate(b []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(b))
	defer r.Close()
	return io.ReadAll(r)
}

func ninjaUnmapPort(port int, salt string, lo, hi, mul int) int {
	crc := int(crc32.ChecksumIEEE([]byte(salt)))
	if lo > hi {
		lo, hi = hi, lo
	}
	span := hi - lo + 1
	v := span*mul + (port - lo) - crc
	if v < 0 {
		v = 0
	}
	if v > 0xffff {
		v &= 0xffff
	}
	return v
}

func ninjaStr(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func ninjaNodePasswordKey(m map[string]any) (string, string) {
	if s := ninjaStr(m, "node_password"); s != "" {
		return "node_password", s
	}
	if s := ninjaStr(m, "node-password"); s != "" {
		return "node-password", s
	}
	return "", ""
}

func ninjaInt(m map[string]any, key string) (int, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case string:
		i, err := strconv.Atoi(n)
		if err != nil {
			return 0, false
		}
		return i, true
	}
	return 0, false
}

func ninjaBool(m map[string]any, key string) bool {
	v, ok := m[key]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}

func ninjaDecodeHost(tag, cand string, a36 []byte, xorKey string, pwd string, rawPort int) (string, error) {
	raw, err := ninjaBaseNDecode(cand, a36)
	if err != nil {
		return "", err
	}
	switch tag {
	case "01a", "01b":
		return string(ninjaStrXor(raw, xorKey)), nil
	case "01c":
		h, err := ninjaInflate(ninjaStrXor(raw, xorKey))
		if err != nil {
			return "", err
		}
		return string(h), nil
	case "02a":
		if len(raw) != 4 {
			return "", fmt.Errorf("bad ipv4 payload")
		}
		v := binary.BigEndian.Uint32(raw) ^ crc32.ChecksumIEEE([]byte(pwd)) ^ uint32(rawPort)
		return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v)), nil
	case "02b", "02c":
		return strings.ToLower(string(ninjaStrXor(raw, xorKey))), nil
	}
	return "", fmt.Errorf("bad id")
}

// restoreNinjaNode decodes one obfuscated proxy map in place.
func restoreNinjaNode(m map[string]any) error {
	pwd := ninjaStr(m, "password")
	server := ninjaStr(m, "server")
	if server == "" {
		return fmt.Errorf("missing server")
	}
	rawPort, ok := ninjaInt(m, "port")
	if !ok {
		return fmt.Errorf("missing port")
	}
	nodePwdKey, nodePwdVal := ninjaNodePasswordKey(m)
	if nodePwdKey == "" {
		return fmt.Errorf("missing node-password")
	}
	dot := strings.IndexByte(server, '.')
	if dot < 0 {
		return fmt.Errorf("bad label format")
	}
	label, rest := server[:dot], server[dot+1:]
	if len(label) < 8 {
		return fmt.Errorf("bad label format")
	}
	dash := strings.IndexByte(label, '-')
	if dash < 0 {
		return fmt.Errorf("bad label format")
	}
	key := label[dash+1:]
	tag := label[4:7]

	a36 := ninjaSaltShuffle(ninjaAlpha36, pwd)
	a69 := ninjaSaltShuffle(ninjaAlpha69, pwd)

	decodedPwd, err := ninjaBaseNDecode(nodePwdVal, a69)
	if err != nil {
		return fmt.Errorf("decode node-password: %w", err)
	}
	pt, err := ninjaInflate(ninjaStrXor(decodedPwd, key))
	if err != nil {
		return fmt.Errorf("inflate: %w", err)
	}
	i := bytes.IndexByte(pt, 0x1f)
	if i < 0 {
		return fmt.Errorf("empty payload")
	}
	newPwd := string(pt[:i])
	rest2 := pt[i+1:]
	field2, tail := string(rest2), ""
	if j := bytes.IndexByte(rest2, '#'); j >= 0 {
		field2, tail = string(rest2[:j]), string(rest2[j+1:])
	}
	mul, _ := strconv.Atoi(field2)
	xorKey := pwd + ":" + strconv.Itoa(rawPort)

	host, err := ninjaDecodeHost(tag, key+tail, a36, xorKey, pwd, rawPort)
	if err != nil {
		return err
	}
	if rest != "" {
		host = host + "." + rest
	}
	m["server"] = strings.ToLower(host)
	m["port"] = ninjaUnmapPort(rawPort, pwd, 10000, 20000, mul)
	m[nodePwdKey] = newPwd
	delete(m, "tls")
	return nil
}

type ninjaPassInfo struct {
	Set     map[string]any   `json:"set"`
	Replace []map[string]any `json:"replace"`
}

func extractNinjaPassInfo(raw []byte) (*ninjaPassInfo, bool) {
	for _, line := range strings.Split(string(raw), "\n") {
		idx := strings.Index(line, "#!PASS-INFO")
		if idx < 0 {
			continue
		}
		payload := strings.TrimSpace(line[idx+len("#!PASS-INFO"):])
		if payload == "" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			log.Debugln("[Ninja] ignore malformed #!PASS-INFO base64: %v", err)
			continue
		}
		var info ninjaPassInfo
		if err := json.Unmarshal(ninjaStrXor(decoded, ninjaPassKey), &info); err != nil {
			log.Debugln("[Ninja] ignore malformed #!PASS-INFO json: %v", err)
			continue
		}
		return &info, true
	}
	return nil, false
}

func applyAllowedFields(dst map[string]any, src map[string]any, allowlist map[string]struct{}, phase string) {
	for k, v := range src {
		if _, ok := allowlist[normalizeKey(k)]; !ok {
			log.Debugln("[Ninja] ignore disallowed #!PASS-INFO %s key %q", phase, k)
			continue
		}
		dst[k] = v
	}
}

// ProcessObfuscation restores obfuscated ninja proxies and injects allowlisted
// pass/transport settings carried by the #!PASS-INFO subscription comment.
func ProcessObfuscation(proxies []map[string]any, raw []byte) {
	hasNinja := false
	for _, p := range proxies {
		if ninjaStr(p, "type") != "ninja" {
			continue
		}
		hasNinja = true
		if !ninjaBool(p, "tls") {
			continue
		}
		// Only a successful restore consumes the marker; a failed one leaves
		// transport flags untouched so plain "tls: true" proxies keep TLS.
		if err := restoreNinjaNode(p); err != nil {
			log.Debugln("[Ninja] skip deobfuscation for %q (keeping plain fields): %v", ninjaStr(p, "name"), err)
		}
	}
	if !hasNinja {
		return
	}
	info, ok := extractNinjaPassInfo(raw)
	if !ok {
		return
	}
	for _, p := range proxies {
		if ninjaStr(p, "type") != "ninja" {
			continue
		}
		applyAllowedFields(p, info.Set, passInfoSetAllowlist, "set")
		for _, r := range info.Replace {
			match, _ := r["match"].(map[string]any)
			repl, _ := r["replace"].(map[string]any)
			if match == nil || repl == nil {
				continue
			}
			if ninjaStr(p, "server") != ninjaStr(match, "server") {
				continue
			}
			applyAllowedFields(p, repl, passInfoReplaceAllowlist, "replace")
		}
	}
}
