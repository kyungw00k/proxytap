# proxytap menubar

Thin Tauri 2 shell that lives in the system tray and surfaces proxytap daemon
status at a glance. Click the tray icon (or "Open" in the menu) to bring up a
small status panel; double-click "Open dashboard" inside the panel to launch
the full embedded dashboard in your default browser.

```
┌───────────────────────────────────┐
│ ● proxytap                        │
│                                   │
│ ┌─────────┐  ┌─────────┐          │
│ │ Healthy │  │ Served  │          │
│ │   14    │  │  127    │          │
│ │  /345   │  │         │          │
│ └─────────┘  └─────────┘          │
│                                   │
│ [ Open dashboard ] [ Refresh ]    │
│                                   │
│ Proxy endpoint: http://127.0.0.1:8888
└───────────────────────────────────┘
```

## Build (one-time setup)

```bash
cd menubar-app

# 1. JS deps
npm install

# 2. Rust toolchain (skip if you already have one)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 3. Linux: native deps for Tauri 2 (webkit2gtk-4.1, etc.)
#    macOS / Windows: skip
sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget file \
  libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev

# 4. Run dev (hot reload) or build a bundle (.app/.dmg/.msi/.deb/.AppImage)
npm run tauri dev
npm run tauri build
```

## Architecture

- The menubar app does **not** embed the daemon. It talks to a running
  `proxytapd` over `http://127.0.0.1:9099`. Start the daemon separately
  (`proxytapd`, `brew services start proxytap`, or `systemctl start proxytap`).
- The tray panel polls `/stats` every 2 s; if the daemon is unreachable, the
  status dot turns red and a hint is shown.
- "Open dashboard" launches the full embedded web dashboard in the OS default
  browser via `tauri-plugin-shell`.

## Bundle icons

The bundle config references the standard Tauri icon set under
`src-tauri/icons/`. Generate the full set with `npm run tauri icon
../docs/logo.png` once you have a source PNG ≥1024×1024.

## Status

Scaffolded — compiles against Tauri 2 stable, not yet bundled in CI.
Pre-built bundles will ship via GitHub Releases once a build matrix is added
to `.github/workflows/release.yml`.
