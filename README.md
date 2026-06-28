# anon-proxy

A rotating anonymous-proxy gateway for crawlers and automation. The daemon
fetches public proxy lists (default: [iplocate/free-proxy-list]), health-checks
each upstream, classifies anonymity, and exposes a single local HTTP endpoint
that clients point their `HTTP_PROXY` at — no code changes needed.

> PoC (Phase 1). MITM detection, menubar UI, and rate-limiting land in later
> phases — see `docs/roadmap.md` (TBD).

## Architecture

```
[crawler] --HTTP/HTTPS--> 127.0.0.1:8888 (daemon)
                              |
                              |--> pool (round-robin)
                              |        ^
                              |        | health-check results
                              |        |
                              +--> fetcher -- GitHub raw lists
                                     |
                                     +--> cache (~/.anon-proxy/cache/all.txt)

control plane: 127.0.0.1:9099 (REST: /stats /proxies /sources)
```

## Quick start

```bash
go build ./cmd/proxyhubd
./proxyhubd

# in another terminal:
curl http://api.iplocate.io/ip -x http://127.0.0.1:8888
curl http://127.0.0.1:9099/stats | jq
curl 'http://127.0.0.1:9099/proxies?healthy'
```

## Configuration (CLI flags)

| Flag | Default | Description |
| --- | --- | --- |
| `--proxy-listen` | `127.0.0.1:8888` | Local HTTP forward proxy |
| `--api-listen` | `127.0.0.1:9099` | Control-plane REST API |
| `--cache-dir` | `~/.anon-proxy/cache` | Disk cache for fetched lists |
| `--fetch-interval` | `30m` | Proxy list refresh interval |
| `--check-interval` | `5m` | Health-check sweep interval |
| `--check-timeout` | `8s` | Per-proxy probe timeout |
| `--check-workers` | `50` | Concurrent probes |
| `--min-anon` | `elite` | `elite` / `anonymous` / `transparent` |
| `--max-failures` | `5` | Failures before quarantining a proxy |

## Sources

Defaults (overridable via `POST /sources`):

- `https://raw.githubusercontent.com/iplocate/free-proxy-list/main/all-proxies.txt`
- `https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks5.txt`

## Roadmap

- [x] Phase 1: daemon — fetch, health-check, HTTP forward, REST
- [ ] Phase 2: MITM detection (cert pinning, CT log, cross-verify, header-leak)
- [ ] Phase 3: menubar app (Tauri, Linux/Windows/macOS)
- [ ] Phase 4: rate limiter (4-layer: global / target / upstream / source)
- [ ] Phase 5: packaging (Homebrew, Winget, AUR, systemd/launchd units)

[iplocate/free-proxy-list]: https://github.com/iplocate/free-proxy-list
