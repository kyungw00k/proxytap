package fetcher

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Proxy struct {
	Scheme   string // socks5, socks4, http, https
	Address  string // ip:port
	Source   string // list URL (for traceability)
}

func (p Proxy) String() string {
	return fmt.Sprintf("%s://%s", p.Scheme, p.Address)
}

type Fetcher struct {
	sources    []string
	cacheDir   string
	httpClient *http.Client
	mu         sync.RWMutex
	cached     []Proxy
	lastFetch  time.Time
}

func New(cacheDir string, sources []string) *Fetcher {
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		// cache is best-effort; log via stderr is fine for PoC
		fmt.Fprintf(os.Stderr, "fetcher: warn: mkdir %s: %v\n", cacheDir, err)
	}
	if len(sources) == 0 {
		sources = DefaultSources()
	}
	return &Fetcher{
		sources:    sources,
		cacheDir:   cacheDir,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func DefaultSources() []string {
	return []string{
		"https://raw.githubusercontent.com/iplocate/free-proxy-list/main/all-proxies.txt",
		"https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks5.txt",
	}
}

func (f *Fetcher) Sources() []string {
	return f.sources
}

func (f *Fetcher) SetSources(s []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sources = s
}

func (f *Fetcher) Cached() ([]Proxy, time.Time) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]Proxy, len(f.cached))
	copy(out, f.cached)
	return out, f.lastFetch
}

// Fetch downloads all sources in parallel, parses, deduplicates, and persists
// to a single cache file. It returns the merged list.
func (f *Fetcher) Fetch(ctx context.Context) ([]Proxy, error) {
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		merged  []Proxy
		seen    = map[string]struct{}{}
		errs    []error
	)

	for _, src := range f.sources {
		wg.Add(1)
		go func(src string) {
			defer wg.Done()
			proxies, err := f.fetchOne(ctx, src)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", src, err))
				return
			}
			for _, p := range proxies {
				key := p.String()
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				merged = append(merged, p)
			}
		}(src)
	}
	wg.Wait()

	f.mu.Lock()
	f.cached = merged
	f.lastFetch = time.Now()
	f.mu.Unlock()

	if err := f.persist(merged); err != nil {
		fmt.Fprintf(os.Stderr, "fetcher: warn: persist: %v\n", err)
	}

	if len(merged) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("all sources failed: %v", errs)
	}
	return merged, nil
}

func (f *Fetcher) fetchOne(ctx context.Context, src string) ([]Proxy, error) {
	body, err := f.fetchBody(ctx, src)
	if err != nil {
		// try disk cache as fallback
		if cached, cerr := f.loadCache(src); cerr == nil {
			fmt.Fprintf(os.Stderr, "fetcher: %s: network failed, using cache: %v\n", src, err)
			return parseProxies(src, cached), nil
		}
		return nil, err
	}
	return parseProxies(src, body), nil
}

func (f *Fetcher) fetchBody(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "proxytap/0.1 (https://github.com/kyungw00k)")
	resp, err := f.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func parseProxies(src, body string) []Proxy {
	// Heuristic per source:
	//  - iplocate/all-proxies.txt uses "scheme://ip:port"
	//  - iplocate/protocols/socks5.txt uses "ip:port" (scheme inferred from filename)
	inferred := inferSchemeFromURL(src)
	var out []Proxy
	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "://") {
			parts := strings.SplitN(line, "://", 2)
			scheme := strings.ToLower(parts[0])
			addr := strings.TrimSpace(parts[1])
			if addr == "" || !looksLikeAddr(addr) {
				continue
			}
			out = append(out, Proxy{Scheme: scheme, Address: addr, Source: src})
			continue
		}
		if inferred != "" && looksLikeAddr(line) {
			out = append(out, Proxy{Scheme: inferred, Address: line, Source: src})
		}
	}
	return out
}

func inferSchemeFromURL(src string) string {
	low := strings.ToLower(src)
	switch {
	case strings.Contains(low, "socks5"):
		return "socks5"
	case strings.Contains(low, "socks4"):
		return "socks4"
	case strings.Contains(low, "/https"):
		return "https"
	case strings.Contains(low, "/http"):
		return "http"
	}
	return ""
}

func looksLikeAddr(s string) bool {
	// minimal sanity: contains ":" and the last segment is numeric-ish
	idx := strings.LastIndexByte(s, ':')
	if idx <= 0 || idx == len(s)-1 {
		return false
	}
	return true
}

func (f *Fetcher) persist(proxies []Proxy) error {
	path := filepath.Join(f.cacheDir, "all.txt")
	var b strings.Builder
	for _, p := range proxies {
		b.WriteString(p.String())
		b.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func (f *Fetcher) loadCache(src string) (string, error) {
	// Only the aggregated cache is persisted. For per-source fallback,
	// we use the aggregate if available.
	path := filepath.Join(f.cacheDir, "all.txt")
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Run starts a background loop that refreshes every interval. The first fetch
// is performed immediately. Cancel ctx to stop.
func (f *Fetcher) Run(ctx context.Context, interval time.Duration, onUpdate func([]Proxy)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	refresh := func() {
		proxies, err := f.Fetch(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "fetcher: refresh failed: %v\n", err)
			return
		}
		fmt.Fprintf(os.Stderr, "fetcher: fetched %d proxies\n", len(proxies))
		if onUpdate != nil {
			onUpdate(proxies)
		}
	}
	refresh()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refresh()
		}
	}
}
