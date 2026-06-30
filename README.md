<p align="center">
  <img alt="proxytap logo" src="docs/logo.png" width="160">
</p>

<h1 align="center">proxytap</h1>

<p align="center">A rotating anonymous-proxy gateway with MITM detection. For crawlers, scrapers, and automation that need to look like many different users.</p>

<p align="center">
  <a href="https://github.com/kyungw00k/proxytap/releases/latest"><img alt="release" src="https://img.shields.io/github/v/release/kyungw00k/proxytap?style=flat-square&color=58a6ff"></a>
  <a href="https://github.com/kyungw00k/proxytap/actions/workflows/release.yml"><img alt="daemon build" src="https://img.shields.io/github/actions/workflow/status/kyungw00k/proxytap/release.yml?branch=master&style=flat-square&label=daemon"></a>
  <a href="https://github.com/kyungw00k/proxytap/actions/workflows/menubar.yml"><img alt="menubar build" src="https://img.shields.io/github/actions/workflow/status/kyungw00k/proxytap/menubar.yml?branch=master&style=flat-square&label=menubar"></a>
  <a href="https://github.com/kyungw00k/proxytap/actions/workflows/formula-audit.yml"><img alt="brew audit" src="https://img.shields.io/github/actions/workflow/status/kyungw00k/proxytap/formula-audit.yml?branch=master&style=flat-square&label=brew%20audit"></a>
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
health-checks each upstream, classifies anonymity, runs MITM detection, and
exposes a single local HTTP endpoint that clients point their `HTTP_PROXY`
at — no code changes needed. A built-in dashboard at `http://127.0.0.1:9099/`
surfaces pool health, recent verdicts, and source management.

## Architecture

```
[crawler] --HTTP/HTTPS--> 127.0.0.1:8888 (daemon)
                              |
                              |--> pool (round-robin, capacity-bounded)
                              |        ^
                              |        | alive + anon + MITM verdicts
                              |        |
                              +--> fetcher -- GitHub raw lists
                                     |
                                     +--> cache (~/.proxytap/cache/all.txt)

control plane: 127.0.0.1:9099
  GET  /                embedded dashboard (HTML, vanilla JS)
  GET  /stats           pool counters + last fetch
  GET  /proxies?healthy healthy upstream table
  GET  /mitm            recent MITM verdicts (?dirty to filter)
  GET  /sources         list source URLs   |  POST /sources  edit
```

## Quick start

### Install with Homebrew (macOS/Linux)

```bash
brew tap kyungw00k/tap
brew install proxytap
brew services start proxytap     # daemon on 127.0.0.1:8888 + 127.0.0.1:9099
proxytapd --version              # sanity check
```

### Pre-built binary (Linux/macOS/Windows)

```bash
# One-liner (auto-detects OS+arch, installs systemd unit on Linux)
curl -fsSL https://raw.githubusercontent.com/kyungw00k/proxytap/master/scripts/install.sh | bash

# Or pick a binary directly: https://github.com/kyungw00k/proxytap/releases/latest
```

### From source

```bash
go build ./cmd/proxytapd
./proxytapd
```

### Verify it works

```bash
# Dashboard (open in a browser)
open http://127.0.0.1:9099/

# Use as an HTTP proxy — should print a rotating exit IP per request
for i in 1 2 3; do curl -sx http://127.0.0.1:8888 https://api.iplocate.io/ip; done

# Inspect pool + MITM verdicts
curl http://127.0.0.1:9099/stats
curl 'http://127.0.0.1:9099/proxies?healthy'
curl 'http://127.0.0.1:9099/mitm?dirty'
```

Logs:
- **Homebrew**: `brew services log proxytap` or `~/.proxytap/cache/proxytap.log`
- **systemd**: `journalctl -u proxytap -f`
- **Foreground**: stderr of `proxytapd`

## Configuration (CLI flags)

| Flag | Default | Description |
| --- | --- | --- |
| `--proxy-listen` | `127.0.0.1:8888` | Local HTTP forward proxy |
| `--api-listen` | `127.0.0.1:9099` | Control-plane REST API + dashboard |
| `--cache-dir` | `~/.proxytap/cache` | Disk cache for fetched lists |
| `--fetch-interval` | `30m` | Proxy list refresh interval |
| `--check-interval` | `5m` | Health-check sweep interval |
| `--check-timeout` | `8s` | Per-proxy probe timeout |
| `--check-workers` | `50` | Concurrent probes |
| `--pool-capacity` | `500` | Max proxies held in the pool |
| `--min-anon` | `elite` | `elite` / `anonymous` / `transparent` |
| `--mitm` | `true` | Enable MITM detection on healthy proxies |
| `--global-rps` | `50` | Max requests/sec through local proxy (0 = unlimited) |
| `--max-failures` | `5` | Failures before quarantining a proxy |
| `--version` | — | Print `proxytapd <version>` and exit |

## Sources

Defaults (overridable via `POST /sources`):

- `https://raw.githubusercontent.com/iplocate/free-proxy-list/main/all-proxies.txt`
- `https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks5.txt`

## Menubar app (macOS/Windows/Linux)

A thin [Tauri 2](https://tauri.app) shell that lives in the system tray. Shows
pool health at a glance and opens the dashboard on click. See
[`menubar-app/`](menubar-app/) for build instructions.

Cross-platform bundles (`.app`, `.dmg`, `.msi`, `.deb`, `.AppImage`, `.rpm`)
are produced by the [`menubar`](.github/workflows/menubar.yml) workflow on tag
push; intermediate artifacts are downloadable from any run via the Actions tab.

## Roadmap

- [x] **Phase 1** — daemon: fetcher, health-check, HTTP forward proxy, REST API
- [x] **Phase 2** — MITM detection engine (cert pinning, plain-body integrity,
      TLS cipher/version audit; verdicts at `/mitm`)
- [x] **Phase 2.1** — SPKI pinning with rotation tolerance (leaf SPKI + issuer
      SPKI, stable pin targets, parallel probe, plain-skip on missing ref)
- [x] **Phase 3a** — embedded web dashboard at `GET /` (single-file, vanilla JS)
- [x] **Phase 3b** — Tauri 2 menubar shell with CI matrix for
      `{linux,macos,windows} × {x64,arm64}`
- [x] **Phase 4** — global rate limiter (token bucket) + 429/403/503 auto-retry
      with IP rotation
- [x] **Phase 5** — packaging: GitHub Actions release matrix, Homebrew formula,
      systemd unit, `install.sh` for Linux/macOS/Windows

Follow-ups (not blocking v1):

- [ ] DNS-leak probe (HTTPS-only clients are unaffected; HTTP is opt-in)
- [ ] IPv6 pool mixing (current list is IPv4-only)
- [ ] Per-target rate limiter (global bucket + retry covers the common case)
- [ ] goreleaser migration for unified daemon + menubar release artefacts

## MITM detection (`--mitm`, default on)

After a proxy passes the alive check, the engine runs two independent probes.
A failing probe downgrades the proxy to `OK=false`, so the pool quarantines
it on the next sweep. Latest verdicts are queryable at `GET /mitm`
(`?dirty` to filter).

| Layer | What it checks | What trips it |
| --- | --- | --- |
| `tls_fingerprint` | SHA256 of the **leaf cert's SubjectPublicKeyInfo (SPKI)** fetched via the proxy, compared against a pin discovered by direct connection. Falls back to the **intermediate-CA SPKI** so global-CDN edge rotations (Google, Cloudflare, …) don't trip false positives — a real MITM with a different CA chain still fails. Same probe audits TLS version and cipher suite. | SPKI mismatch on both leaf and issuer (real MITM), TLS 1.0/1.1, weak cipher (RC4/3DES/CBC-SHA256) |
| `plain_body` | SHA256 of a plain-HTTP body fetched via the proxy, compared against a direct reference. Default target: `http://example.com/` (stable, single-edge site; IP-echo services don't work — direct vs via-proxy bodies differ by construction). | body modification in transit (JS injection, ad insertion) |

Default pin targets: `example.com:443`, `www.iana.org:443`, `www.cloudflare.com:443`
(stable, low-rotation, single-edge sites). All three are probed in parallel;
any one returning a PASS is enough.

[iplocate/free-proxy-list]: https://github.com/iplocate/free-proxy-list
