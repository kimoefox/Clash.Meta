# mihomo (Custom Alpha Build)

Personal multi-platform build of [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) (`Alpha`), merging the protocol enhancements and Bettbox / FlClash core patches from [AirportR/mihomo](https://github.com/AirportR/mihomo) with full upstream Git histories preserved.

## Credits & Acknowledgements

This repository stands on the work of the following upstream projects and contributors:

- **[MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo)** — Official upstream rule-based proxy core (GPL-3.0).
- **[AirportR/mihomo](https://github.com/AirportR/mihomo)** (by `AirportR`, `wangwei354`, and contributors) — Protocol integrations (`x365`, `miu`, `ninja`) and Bettbox / FlClash core patch set.
- **[MiuProtocol/Miu](https://github.com/MiuProtocol/Miu)** — Miu protocol specification and reference core (`transport/miu/`, MIT License).
- **[SakurakaiCat/x365-core](https://github.com/SakurakaiCat/x365-core)** — X365 protocol specification.
- **[appshubcc/Bettbox](https://github.com/appshubcc/Bettbox)** (`v1.20.0`, `core/Clash.Meta`) — Power-saving and low-memory core patches: idle QUIC/gRPC/Miu connection closer (`CloseIdle`), lazy AnyTLS cleanup routine, deduplicated/batched health checks, TUN IPv6 UDP fast-reject, flat mmap GeoSite & rule-set caches, regex cache, lock-free `runtime/metrics` memory stats, and DoH3/DoQ connection recovery.

> **Note:** This is an unofficial personal build. If you encounter bugs or build issues with binaries from this repository, please report them here rather than opening issues on upstream `MetaCubeX/mihomo` or `AirportR/mihomo`.

## Differences from `AirportR/mihomo`

On top of merging the latest `MetaCubeX/mihomo` (`Alpha`) and `AirportR/mihomo` (`Alpha`) trees, this repository adds the following targeted adjustments:

1. **Restored upstream `mieru` inbound fix (`#3236`)**: Re-applied `inbound.WithInUser` metadata for both TCP and UDP in `listener/mieru/server.go`, which was accidentally overwritten during Bettbox patch vendoring.
2. **Hardened `ninja` subscription deobfuscation**: Restored `AirportR`'s `mihomo-ninja` subscription deobfuscation (`transport/ninja/obf.go`) with strict `#!PASS-INFO` field allowlists (blocking overwrites of `type`, `name`, `dialer-proxy`, `interface-name`, `routing-mark`, etc.), support for both `node_password` and `node-password`, BaseN input validation, and per-provider isolation in `proxy-providers`.
3. **Fixed `ninja` empty `password` fallback**: In `adapter/outbound/ninja.go`, fall back `Password` to `NodePassword` when `password` is omitted (fixes `TestNinjaOutboundEcho` and plain `node-password`-only configs).
4. **Synced Bettbox v1.20.0 power-saving & low-memory patches**: Ported Bettbox's full `v1.20.0` core patch set (`CloseIdle` for Hysteria/Hysteria2/TUIC/gRPC + extended to `Miu`, lazy AnyTLS idle cleanup, healthcheck reuse/dedup/batching, IPv6 UDP fast reject, flat mmap GeoSite & domain rule-set caches, `runtime/metrics`, DoH3/DoQ recovery, compact proxy delay states, and UDP direct source-port collision avoidance) while keeping standalone `updateListeners`/`updateTun` intact.
5. **Multi-platform CI & Releases**: Added `.github/workflows/build.yml` to run protocol/core tests and publish pre-built binaries (with `with_gvisor`) for Linux, macOS, Windows, Android (NDK), and FreeBSD.

## License

This project follows the upstream **GNU General Public License v3.0** (see `LICENSE`). Third-party components retain their respective licenses (e.g. `transport/miu/LICENSE`, MIT).
