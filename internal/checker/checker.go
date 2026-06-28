package checker

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kyungw00k/proxytap/internal/fetcher"
	"golang.org/x/net/proxy"
)

// Result captures one health-check probe for an upstream proxy.
type Result struct {
	Proxy    fetcher.Proxy
	OK       bool
	RTT      time.Duration
	ExitIP   string
	AnonLvl  AnonLevel
	Reason   string
}

type AnonLevel string

const (
	AnonElite      AnonLevel = "elite"      // no XFF/Via, real IP hidden
	AnonAnonymous  AnonLevel = "anonymous"  // XFF absent but Via present
	AnonTransparent AnonLevel = "transparent" // XFF leaks real IP
	AnonUnknown    AnonLevel = "unknown"
)

type Checker struct {
	targetURL  string
	timeout    time.Duration
	concurrent int
	httpClient *http.Client
}

type Options struct {
	TargetURL  string
	Timeout    time.Duration
	Concurrent int
}

func New(opts Options) *Checker {
	if opts.TargetURL == "" {
		opts.TargetURL = "http://ifconfig.me/ip"
	}
	if opts.Timeout == 0 {
		opts.Timeout = 8 * time.Second
	}
	if opts.Concurrent == 0 {
		opts.Concurrent = 50
	}
	return &Checker{
		targetURL:  opts.TargetURL,
		timeout:    opts.Timeout,
		concurrent: opts.Concurrent,
	}
}

// Check probes a single proxy. Returns a Result with RTT, exit IP, and a
// rough anonymity classification. For non-SOCKS5 schemes the anonymity
// header check falls back to "unknown" — full classification across schemes
// is implemented in the MITM engine (Phase 2).
func (c *Checker) Check(ctx context.Context, p fetcher.Proxy) Result {
	res := Result{Proxy: p, AnonLvl: AnonUnknown}
	client, err := c.clientFor(p)
	if err != nil {
		res.Reason = "scheme unsupported: " + err.Error()
		return res
	}

	probeStart := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.targetURL, nil)
	if err != nil {
		res.Reason = "bad request: " + err.Error()
		return res
	}
	req.Header.Set("User-Agent", "proxytap-check/0.1")

	resp, err := client.Do(req)
	if err != nil {
		res.Reason = "request failed: " + err.Error()
		return res
	}
	defer resp.Body.Close()
	res.RTT = time.Since(probeStart)

	if resp.StatusCode != http.StatusOK {
		res.Reason = fmt.Sprintf("status %d", resp.StatusCode)
		return res
	}

	// Read up to 256 bytes of body — that's plenty for an IP echo service.
	buf := make([]byte, 256)
	n, _ := readAtMost(resp.Body, buf)
	res.ExitIP = strings.TrimSpace(string(buf[:n]))

	// Anonymity classification based on forwarded-by headers.
	switch {
	case resp.Header.Get("X-Forwarded-For") != "" || resp.Header.Get("X-Real-Ip") != "":
		res.AnonLvl = AnonTransparent
		res.Reason = "real IP leaked via forwarding header"
	case strings.Contains(strings.ToLower(resp.Header.Get("Via")), "proxy") ||
		strings.Contains(strings.ToLower(resp.Header.Get("X-Proxy-Id")), "proxy"):
		res.AnonLvl = AnonAnonymous
	default:
		res.AnonLvl = AnonElite
	}

	res.OK = true
	return res
}

// CheckAll runs probes concurrently with a worker cap. Returns results for
// every input proxy; failures are included (OK=false) so callers can decide.
func (c *Checker) CheckAll(ctx context.Context, in []fetcher.Proxy) []Result {
	if len(in) == 0 {
		return nil
	}
	workers := c.concurrent
	if workers > len(in) {
		workers = len(in)
	}

	jobs := make(chan fetcher.Proxy, len(in))
	out := make(chan Result, len(in))
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				select {
				case <-ctx.Done():
					out <- Result{Proxy: p, Reason: "cancelled"}
					return
				default:
				}
				out <- c.Check(ctx, p)
			}
		}()
	}

	for _, p := range in {
		jobs <- p
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(out)
	}()

	results := make([]Result, 0, len(in))
	for r := range out {
		results = append(results, r)
	}
	return results
}

// Run loops forever (until ctx cancelled), invoking onResult for each result.
// onPass is invoked at the start of every sweep with the number of probes
// dispatched. This is the integration point used by the pool manager.
func (c *Checker) Run(
	ctx context.Context,
	interval time.Duration,
	snapshot func() []fetcher.Proxy,
	onPass func(totalProbed, ok int),
	onResult func(Result),
) {
	var pass uint64
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	runOnce := func() {
		n := atomic.AddUint64(&pass, 1)
		in := snapshot()
		if len(in) == 0 {
			return
		}
		start := time.Now()
		results := c.CheckAll(ctx, in)
		ok := 0
		for _, r := range results {
			if r.OK {
				ok++
			}
			if onResult != nil {
				onResult(r)
			}
		}
		fmt.Fprintf(stderr(), "checker: pass #%d probed=%d ok=%d took=%s\n",
			n, len(in), ok, time.Since(start))
		if onPass != nil {
			onPass(len(in), ok)
		}
	}

	runOnce()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runOnce()
		}
	}
}

func (c *Checker) clientFor(p fetcher.Proxy) (*http.Client, error) {
	switch p.Scheme {
	case "socks5":
		dialer, err := proxy.SOCKS5("tcp", p.Address, nil, &net.Dialer{Timeout: c.timeout})
		if err != nil {
			return nil, err
		}
		transport := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			},
			ResponseHeaderTimeout: c.timeout,
			// security: never allow upstream to fake cert for HTTPS — the
			// Go default InsecureSkipVerify=false is correct; we keep it.
		}
		return &http.Client{
			Transport: transport,
			Timeout:   c.timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		}, nil
	case "http", "https":
		proxyURL, err := url.Parse(p.String())
		if err != nil {
			return nil, err
		}
		transport := &http.Transport{
			Proxy:               http.ProxyURL(proxyURL),
			ResponseHeaderTimeout: c.timeout,
		}
		return &http.Client{Transport: transport, Timeout: c.timeout}, nil
	default:
		return nil, fmt.Errorf("unsupported scheme %q", p.Scheme)
	}
}
