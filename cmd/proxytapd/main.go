package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/kyungw00k/proxytap/internal/api"
	"github.com/kyungw00k/proxytap/internal/checker"
	"github.com/kyungw00k/proxytap/internal/fetcher"
	"github.com/kyungw00k/proxytap/internal/limiter"
	"github.com/kyungw00k/proxytap/internal/mitm"
	"github.com/kyungw00k/proxytap/internal/pool"
	"github.com/kyungw00k/proxytap/internal/proxy"
)

var version = "dev"

func main() {
	var (
		versionFlag   = flag.Bool("version", false, "print version and exit")
		proxyListen   = flag.String("proxy-listen", "127.0.0.1:8888", "HTTP forward proxy listen address")
		apiListen     = flag.String("api-listen", "127.0.0.1:9099", "control-plane REST API listen address")
		cacheDir      = flag.String("cache-dir", defaultCacheDir(), "cache directory")
		fetchInterval = flag.Duration("fetch-interval", 30*time.Minute, "proxy list refresh interval")
		checkInterval = flag.Duration("check-interval", 5*time.Minute, "health-check interval")
		checkTimeout  = flag.Duration("check-timeout", 8*time.Second, "per-proxy health-check timeout")
		checkWorkers  = flag.Int("check-workers", 50, "concurrent health-check workers")
		minAnon       = flag.String("min-anon", "elite", "minimum anonymity level: elite|anonymous|transparent")
		maxFailures   = flag.Int("max-failures", 5, "consecutive failures before a proxy is quarantined")
		capacity      = flag.Int("pool-capacity", 500, "max proxies held in the pool")
		mitmEnabled   = flag.Bool("mitm", true, "enable MITM detection on healthy proxies")
		globalRPS     = flag.Int("global-rps", 50, "max requests/sec through the local proxy (0 = unlimited)")
	)
	flag.Parse()

	if *versionFlag {
		fmt.Println("proxytapd", version)
		return
	}

	if err := run(*proxyListen, *apiListen, *cacheDir,
		*fetchInterval, *checkInterval, *checkTimeout, *checkWorkers,
		*minAnon, *maxFailures, *capacity, *mitmEnabled, *globalRPS); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run(
	proxyListen, apiListen, cacheDir string,
	fetchInterval, checkInterval, checkTimeout time.Duration,
	checkWorkers int,
	minAnon string, maxFailures, capacity int,
	mitmEnabled bool, globalRPS int,
) error {
	rootCtx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer cancel()

	f := fetcher.New(cacheDir, nil)
	p := pool.New(pool.Options{
		MaxFailures:  maxFailures,
		MinAnonLevel: parseAnonLevel(minAnon),
		Capacity:     capacity,
	})
	var mitmEngine *mitm.Engine
	if mitmEnabled {
		mitmEngine = mitm.New(mitm.Options{Timeout: checkTimeout})
		if err := mitmEngine.DiscoverPins(rootCtx); err != nil {
			fmt.Fprintf(os.Stderr, "warn: pin discovery failed: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "mitm: pinned %d hosts\n", len(mitmEngine.SnapshotPins()))
		}
		if err := mitmEngine.DiscoverPlainRef(rootCtx); err != nil {
			fmt.Fprintf(os.Stderr, "warn: plain-ref discovery failed: %v\n", err)
		}
	}

	chk := checker.New(checker.Options{
		Timeout:    checkTimeout,
		Concurrent: checkWorkers,
		MITM:       mitmEngine,
	})

	initial, err := f.Fetch(rootCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: initial fetch failed: %v\n", err)
	} else {
		p.Reset(initial)
	}

	go f.Run(rootCtx, fetchInterval, func(proxies []fetcher.Proxy) {
		p.Reset(proxies)
	})

	// checker periodically probes the current pool and feeds results back
	go chk.Run(rootCtx, checkInterval,
		func() []fetcher.Proxy {
			out := make([]fetcher.Proxy, 0)
			for _, e := range p.Snapshot() {
				out = append(out, e.Proxy)
			}
			return out
		},
		nil,
		func(r checker.Result) {
			p.Apply(r)
		},
	)

	// local forward proxy (HTTP CONNECT for HTTPS, plain HTTP forward)
	var bucket *limiter.TokenBucket
	if globalRPS > 0 {
		bucket = limiter.NewTokenBucket(globalRPS, globalRPS*2)
	}
	proxySrv := proxy.New(proxyListen, p, bucket)
	go func() {
		if err := proxySrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "proxy server error: %v\n", err)
			cancel()
		}
	}()

	// control-plane REST API
	apiSrv := api.New(apiListen, p, f, chk)
	go func() {
		fmt.Fprintf(os.Stderr, "api: listening on http://%s\n", apiListen)
		if err := apiSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "api server error: %v\n", err)
			cancel()
		}
	}()

	<-rootCtx.Done()
	fmt.Fprintln(os.Stderr, "shutdown: draining...")

	shutdownCtx, sCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer sCancel()
	_ = proxySrv.Shutdown(shutdownCtx)
	_ = apiSrv.Shutdown(shutdownCtx)
	return nil
}

func parseAnonLevel(s string) checker.AnonLevel {
	switch s {
	case "elite", "ELITE":
		return checker.AnonElite
	case "anonymous", "ANONYMOUS":
		return checker.AnonAnonymous
	case "transparent", "TRANSPARENT":
		return checker.AnonTransparent
	default:
		return checker.AnonElite
	}
}

func defaultCacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "proxytap")
	}
	return filepath.Join(home, ".proxytap", "cache")
}
