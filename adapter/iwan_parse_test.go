package adapter

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestParseProxyIwan(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":     "iwan",
		"type":     "iwan",
		"server":   "127.0.0.1",
		"port":     443,
		"username": "myuser",
		"password": "mypassword",
		"mtu":      1400,
		"encrypt":  false,
	})
	if err != nil {
		t.Fatalf("ParseProxy(iwan) failed: %v", err)
	}
	defer proxy.Close()

	if proxy.Type() != C.Iwan {
		t.Fatalf("Type() = %v, want Iwan", proxy.Type())
	}
	if proxy.Name() != "iwan" {
		t.Fatalf("Name() = %q, want iwan", proxy.Name())
	}
	if !proxy.IsL3Protocol(nil) {
		t.Fatal("IsL3Protocol() = false, want true")
	}
}
