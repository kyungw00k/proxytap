<p align="center">
  <img alt="proxytap logo" src="docs/logo.png" width="160">
</p>

<h1 align="center">proxytap</h1>

<p align="center">A rotating anonymous-proxy gateway with MITM detection. For crawlers, scrapers, and automation that need to look like many different users.</p>

<p align="center">
  <a href="https://github.com/kyungw00k/proxytap/releases/latest"><img alt="release" src="https://img.shields.io/github/v/release/kyungw00k/proxytap?style=flat-square&color=58a6ff"></a>
  <a href="https://github.com/kyungw00k/proxytap/actions/workflows/release.yml"><img alt="build" src="https://img.shields.io/github/actions/workflow/status/kyungw00k/proxytap/release.yml?branch=master&style=flat-square"></a>
  <a href="LICENSE"><img alt="license" src="https://img.shields.io/github/license/kyungw00k/proxytap?style=flat-square"></a>
  <a href="https://github.com/kyungw00k/proxytap/stargazers"><img alt="stars" src="https://img.shields.io/github/stars/kyungw00k/proxytap?style=flat-square"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="#mitm-detection">MITM detection</a> ·
  <a href="menubar-app/">Menubar app</a> ·
  <a href="#install-with-homebrew-macoslinux">Homebrew</a>
</p>

---

The daemon fetches public proxy lists (default: [iplocate/free-proxy-list]),
health-checks each upstream, classifies anonymity, and exposes a single local
HTTP endpoint that clients point their `HTTP_PROXY` at — no code changes
needed.

> PoC (Phases 1-5 shipped). Tauri menubar shell is in [`menubar-app/`](menubar-app/).

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

### From source

```bash
go build ./cmd/proxytapd
./proxytapd

# in another terminal:
curl http://api.iplocate.io/ip -x http://127.0.0.1:8888
curl http://127.0.0.1:9099/stats | jq
curl 'http://127.0.0.1:9099/proxies?healthy'
```

### Pre-built binary (Linux/macOS/Windows)

```bash
# Linux/macOS one-liner (auto-detects OS+arch, installs systemd unit on Linux)
curl -fsSL https://raw.githubusercontent.com/kyungw00k/proxytap/master/scripts/install.sh | bash

# Or pick a binary directly from releases
# https://github.com/kyungw00k/proxytap/releases/latest
```

### Install with Homebrew (macOS/Linux)

```bash
brew tap kyungw00k/tap
brew install proxytap
brew services start proxytap
```

Then open the dashboard at <http://127.0.0.1:9099/> or use the local proxy:

```bash
curl -x http://127.0.0.1:8888 https://api.iplocate.io/ip
```

### Menubar app (macOS/Windows/Linux)

A thin Tauri shell that lives in your menu bar and opens the dashboard on click. Build it from source in [`menubar-app/`](menubar-app/). Pre-built bundles will ship once the build pipeline is wired.

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
| `--global-rps` | `50` | max requests/sec through local proxy (0 = unlimited) |
| `--max-failures` | `5` | Failures before quarantining a proxy |

## Sources

Defaults (overridable via `POST /sources`):

- `https://raw.githubusercontent.com/iplocate/free-proxy-list/main/all-proxies.txt`
- `https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks5.txt`

## Roadmap

- [x] Phase 1: daemon — fetch, health-check, HTTP forward, REST
- [x] Phase 2: MITM detection engine (cert fingerprint pinning, plain-body
      integrity, TLS cipher/version audit; verdicts exposed at `/mitm`)
- [x] Phase 2.1: SPKI pinning with rotation tolerance (leaf SPKI + issuer SPKI,
      stable pin targets, parallel probe, plain-skip on missing ref)
- [x] Phase 3a: embedded web dashboard at `GET /` (single-file, vanilla JS)
- [x] Phase 4: global rate limiter (token bucket) + 429/403/503 auto-retry
      with IP rotation
- [x] Phase 5: packaging (GitHub Actions release matrix, systemd unit,
      install.sh for Linux/macOS/Windows)
- [ ] Phase 3b: Tauri menubar shell wrapping the dashboard (deferred — needs
      a desktop env to visual-QA; dashboard already covers the use case)

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
