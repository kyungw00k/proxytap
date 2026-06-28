<script lang="ts">
  import { onMount } from "svelte";
  import { open } from "@tauri-apps/plugin-shell";

  const DASHBOARD = "http://127.0.0.1:9099";
  const PROXY = "http://127.0.0.1:8888";

  type Stats = {
    pool: { Total: number; Healthy: number; Unhealthy: number };
    requests_served: number;
    last_fetch?: string;
  };

  let stats: Stats | null = null;
  let error: string | null = null;

  async function refresh() {
    try {
      const r = await fetch(`${DASHBOARD}/stats`, { cache: "no-store" });
      if (!r.ok) throw new Error(String(r.status));
      stats = await r.json();
      error = null;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
      stats = null;
    }
  }

  onMount(() => {
    refresh();
    const id = setInterval(refresh, 2000);
    return () => clearInterval(id);
  });
</script>

<div class="app">
  <header>
    <img src="/icon.png" alt="proxytap" />
    <span class="dot" class:ok={stats && stats.pool.Healthy > 0} class:err={!stats || stats.pool.Healthy === 0}></span>
    <h1>proxytap</h1>
  </header>

  {#if error}
    <p style="color: var(--red); font-size: 12px;">
      Daemon unreachable at {DASHBOARD}.<br />
      Start it with <code>proxytapd</code> or <code>brew services start proxytap</code>.
    </p>
  {:else if stats}
    <div class="stats">
      <div class="stat">
        <div class="label">Healthy</div>
        <div class="value">{stats.pool.Healthy}<span style="color: var(--muted); font-size: 12px;">/{stats.pool.Total}</span></div>
      </div>
      <div class="stat">
        <div class="label">Served</div>
        <div class="value">{stats.requests_served}</div>
      </div>
    </div>
  {/if}

  <div class="row">
    <button on:click={() => open(DASHBOARD)}>Open dashboard</button>
    <button class="ghost" on:click={refresh}>Refresh</button>
  </div>

  <p style="color: var(--muted); font-size: 11px; text-align: center;">
    Proxy endpoint: <code>{PROXY}</code>
  </p>
</div>
