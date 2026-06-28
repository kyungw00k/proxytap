<p align="center"><img alt="proxytap logo" src="docs/logo.png" width="160"></p>

<h1 align="center">proxytap</h1>

<p align="center">A rotating anonymous-proxy gateway for crawlers and automation.</p>

The daemon fetches public proxy lists (default: [iplocate/free-proxy-list]),
health-checks each upstream, classifies anonymity, and exposes a single local
HTTP endpoint that clients point their `HTTP_PROXY` at — no code changes needed.

> PoC (Phase 1). MITM detection, menubar UI, and rate-limiting land in later
> phases — see `Roadmap` below.

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
                                     +--> cache (~/.proxytap/cache/all.txt)

control plane: 127.0.0.1:9099 (REST: /stats /proxies /sources)
```

## Quick start

```bash
go build ./cmd/proxytapd
./proxytapd

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
| `--cache-dir` | `~/.proxytap/cache` | Disk cache for fetched lists |
| `--fetch-interval` | `30m` | Proxy list refresh interval |
| `--check-interval` | `5m` | Health-check sweep interval |
| `--check-timeout` | `8s` | Per-proxy probe timeout |
| `--check-workers` | `50` | Concurrent probes |
| `--pool-capacity` | `500` | Max proxies held in the pool |
| `--min-anon` | `elite` | `elite` / `anonymous` / `transparent` |
| `--mitm` | `true` | enable MITM detection on healthy proxies |
| `--max-failures` | `5` | Failures before quarantining a proxy |

## Sources

Defaults (overridable via `POST /sources`):

- `https://raw.githubusercontent.com/iplocate/free-proxy-list/main/all-proxies.txt`
- `https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks5.txt`

## Roadmap

- [x] Phase 1: daemon — fetch, health-check, HTTP forward, REST
- [x] Phase 2: MITM detection engine (cert fingerprint pinning, plain-body
      integrity, TLS cipher/version audit; verdicts exposed at `/mitm`)
- [ ] Phase 2.1: cut false-positive rate — SPKI pinning, pin against stable
      leaf-cert hosts (e.g. `example.com`) instead of global CDNs
- [ ] Phase 3: menubar app (Tauri, Linux/Windows/macOS)
- [ ] Phase 4: rate limiter (4-layer: global / target / upstream / source)
- [ ] Phase 5: packaging (Homebrew, Winget, AUR, systemd/launchd units)

## MITM detection (`--mitm`, default on)

After a proxy passes the alive check, the engine runs additional probes:

| Layer | What it checks | What trips it |
| --- | --- | --- |
| `tls_fingerprint` | SHA256 of the leaf cert fetched via the proxy, compared against a pin discovered by direct connection. TLS version and cipher suite audited in the same probe. | cert mismatch (MITM), TLS 1.0/1.1, weak cipher (RC4/3DES/CBC-SHA256) |
| `plain_body` | SHA256 of the body of a plain-HTTP echo endpoint (default: `http://httpbin.org/get`) fetched via the proxy, compared against a direct reference. | body modification in transit (JS injection, ad insertion) |

A failing probe downgrades the proxy to `OK=false`, so the pool quarantines it.
The latest verdicts are queryable at `GET /mitm` (`?dirty` to filter to dirty
only).

[iplocate/free-proxy-list]: https://github.com/iplocate/free-proxy-list
