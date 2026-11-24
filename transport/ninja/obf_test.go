package ninja

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"math/big"
	"strconv"
	"testing"
)

func testBaseNEncode(data []byte, alpha []byte) string {
	n := big.NewInt(int64(len(alpha)))
	x := new(big.Int).SetBytes(data)
	if x.Sign() == 0 {
		return string(alpha[0])
	}
	rem := new(big.Int)
	var out []byte
	for x.Sign() > 0 {
		x.DivMod(x, n, rem)
		out = append(out, alpha[rem.Int64()])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func testDeflate(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func testBuildObfuscatedNode(t *testing.T, pwd, realHostPrefix, domainRest string, realPort int, realNodePwd, nodePwdKey, tag string) map[string]any {
	t.Helper()
	const lo, hi = 10000, 20000
	span := hi - lo + 1
	crc := int(crc32.ChecksumIEEE([]byte(pwd)))
	total := realPort + crc
	mul := total / span
	rawPort := (total % span) + lo

	a36 := ninjaSaltShuffle(ninjaAlpha36, pwd)
	a69 := ninjaSaltShuffle(ninjaAlpha69, pwd)
	xorKey := pwd + ":" + strconv.Itoa(rawPort)

	var hostPayload []byte
	switch tag {
	case "01a":
		hostPayload = ninjaStrXor([]byte(realHostPrefix), xorKey)
	case "01c":
		hostPayload = ninjaStrXor(testDeflate(t, []byte(realHostPrefix)), xorKey)
	case "02a":
		var b [4]byte
		v := uint32(1)<<24 | uint32(2)<<16 | uint32(3)<<8 | uint32(4)
		v ^= crc32.ChecksumIEEE([]byte(pwd)) ^ uint32(rawPort)
		binary.BigEndian.PutUint32(b[:], v)
		hostPayload = b[:]
	default:
		t.Fatalf("unsupported tag %s", tag)
	}
	hostEnc := testBaseNEncode(hostPayload, a36)
	split := len(hostEnc) / 2
	if split == 0 {
		split = len(hostEnc)
	}
	key, tail := hostEnc[:split], hostEnc[split:]

	pt := append([]byte(realNodePwd), 0x1f)
	pt = append(pt, []byte(strconv.Itoa(mul))...)
	if tail != "" {
		pt = append(pt, '#')
		pt = append(pt, []byte(tail)...)
	}
	nodePwdEnc := testBaseNEncode(ninjaStrXor(testDeflate(t, pt), key), a69)

	server := "abcd" + tag + "-" + key
	if domainRest != "" {
		server += "." + domainRest
	} else {
		server += "."
	}
	return map[string]any{
		"name":     "obf-node",
		"type":     "ninja",
		"server":   server,
		"port":     rawPort,
		"password": pwd,
		nodePwdKey: nodePwdEnc,
		"tls":      true,
	}
}

func testEncodePassInfo(t *testing.T, info ninjaPassInfo) []byte {
	t.Helper()
	rawJSON, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(ninjaStrXor(rawJSON, ninjaPassKey))
	return []byte("#!PASS-INFO " + encoded + "\n")
}

func TestProcessObfuscationRoundTripAndAllowlist(t *testing.T) {
	for _, keyName := range []string{"node_password", "node-password"} {
		t.Run(keyName, func(t *testing.T) {
			p := testBuildObfuscatedNode(t, "sub-pass-123", "edge01", "example.com", 443, "real-node-secret", keyName, "01a")
			raw := testEncodePassInfo(t, ninjaPassInfo{
				Set: map[string]any{
					"tls":            true,
					"network":        "ws",
					"pass":           true,
					"ws-opts":        map[string]any{"path": "/ws"},
					"type":           "direct",     // disallowed
					"dialer-proxy":   "evil-chain", // disallowed
					"interface-name": "eth9",       // disallowed
					"server":         "hijack.bad", // disallowed in Set
				},
				Replace: []map[string]any{
					{
						"match": map[string]any{"server": "edge01.example.com"},
						"replace": map[string]any{
							"servername":   "cdn.example.com",
							"port":         8443,
							"dialer-proxy": "still-blocked",
							"type":         "reject",
						},
					},
				},
			})

			ProcessObfuscation([]map[string]any{p}, raw)

			if p["server"] != "edge01.example.com" {
				t.Fatalf("server = %v, want edge01.example.com", p["server"])
			}
			if gotPort, ok := ninjaInt(p, "port"); !ok || gotPort != 8443 {
				t.Fatalf("port = %v (%T), want 8443", p["port"], p["port"])
			}
			if p[keyName] != "real-node-secret" {
				t.Fatalf("%s = %v, want real-node-secret", keyName, p[keyName])
			}
			if p["tls"] != true || p["network"] != "ws" || p["servername"] != "cdn.example.com" {
				t.Fatalf("allowed pass-info fields not applied: %+v", p)
			}
			if p["type"] != "ninja" {
				t.Fatalf("disallowed type overwrite occurred: %v", p["type"])
			}
			if _, ok := p["dialer-proxy"]; ok {
				t.Fatalf("disallowed dialer-proxy overwrite occurred")
			}
			if _, ok := p["interface-name"]; ok {
				t.Fatalf("disallowed interface-name overwrite occurred")
			}
		})
	}
}

func TestProcessObfuscationIPv4AndDeflateHost(t *testing.T) {
	pIPv4 := testBuildObfuscatedNode(t, "pwd-v4", "", "", 8443, "node-v4", "node-password", "02a")
	ProcessObfuscation([]map[string]any{pIPv4}, nil)
	if pIPv4["server"] != "1.2.3.4" || pIPv4["port"] != 8443 || pIPv4["node-password"] != "node-v4" {
		t.Fatalf("unexpected ipv4 restore: %+v", pIPv4)
	}
	if _, hasTLS := pIPv4["tls"]; hasTLS {
		t.Fatalf("expected tls marker to be removed on successful restore")
	}

	pDeflate := testBuildObfuscatedNode(t, "pwd-c", "sub-node-host", "example.org", 2053, "node-c", "node_password", "01c")
	ProcessObfuscation([]map[string]any{pDeflate}, nil)
	if pDeflate["server"] != "sub-node-host.example.org" || pDeflate["port"] != 2053 || pDeflate["node_password"] != "node-c" {
		t.Fatalf("unexpected deflate host restore: %+v", pDeflate)
	}
}

func TestProcessObfuscationPreservesPlainTLSNode(t *testing.T) {
	plain := map[string]any{
		"name":          "plain-ninja",
		"type":          "ninja",
		"server":        "plain-server.example.com",
		"port":          443,
		"password":      "plain-pass",
		"node-password": "plain-node-pass-not-base69-!@#",
		"tls":           true,
	}
	ProcessObfuscation([]map[string]any{plain}, nil)
	if plain["tls"] != true {
		t.Fatalf("plain tls:true proxy lost tls flag")
	}
	if plain["server"] != "plain-server.example.com" || plain["port"] != 443 {
		t.Fatalf("plain proxy modified unexpectedly: %+v", plain)
	}
}
