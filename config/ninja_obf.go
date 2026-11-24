package config

import "github.com/metacubex/mihomo/transport/ninja"

// ProcessNinjaObfuscation delegates to transport/ninja.ProcessObfuscation so
// both main configs and proxy-providers share the same hardened implementation.
func ProcessNinjaObfuscation(proxies []map[string]any, raw []byte) {
	ninja.ProcessObfuscation(proxies, raw)
}
