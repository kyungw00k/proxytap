package mitm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/kyungw00k/proxytap/internal/fetcher"
	"golang.org/x/net/proxy"
)

type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

type Engine struct {
	pinHosts    []string
	plainTarget string
	timeout     time.Duration

	mu       sync.RWMutex
	pins     map[string]string
	plainRef string

	directDialer *net.Dialer
}

type Options struct {
	PinHosts    []string
	PlainTarget string
	Timeout     time.Duration
}

func New(opts Options) *Engine {
	if len(opts.PinHosts) == 0 {
		opts.PinHosts = DefaultPinHosts()
	}
	if opts.PlainTarget == "" {
		opts.PlainTarget = "http://httpbin.org/get"
	}
	if opts.Timeout == 0 {
		opts.Timeout = 8 * time.Second
	}
	return &Engine{
		pinHosts:     opts.PinHosts,
		plainTarget:  opts.PlainTarget,
		timeout:      opts.Timeout,
		pins:         map[string]string{},
		directDialer: &net.Dialer{Timeout: opts.Timeout},
	}
}

func DefaultPinHosts() []string {
	return []string{
		"www.google.com:443",
		"cloudflare.com:443",
		"github.com:443",
	}
}

func (e *Engine) PinsDiscovered() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.pins) > 0
}

func (e *Engine) SnapshotPins() map[string]string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make(map[string]string, len(e.pins))
	for k, v := range e.pins {
		out[k] = v
	}
	return out
}

func (e *Engine) PlainRef() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.plainRef
}

// Probe runs every layer and returns a Verdict. Each layer appends to Probes;
// any failure downgrades Score and sets Clean=false.
func (e *Engine) Probe(ctx context.Context, p fetcher.Proxy) Verdict {
	v := Verdict{Proxy: p, Clean: true, Score: 100}

	dial, err := dialerFor(p, e.timeout)
	if err != nil {
		v.Clean = false
		v.Score = 0
		v.Probes = []ProbeResult{{
			Layer:  LayerTLSFingerprint,
			Pass:   false,
			Reason: "dial setup failed: " + err.Error(),
		}}
		return v
	}

	r := e.probeTLS(ctx, dial)
	if !r.Pass {
		v.Clean = false
		v.Score -= 60
	}
	v.Probes = append(v.Probes, r)

	r = e.probePlain(ctx, dial)
	if !r.Pass {
		v.Clean = false
		v.Score -= 40
	}
	v.Probes = append(v.Probes, r)

	if v.Score < 0 {
		v.Score = 0
	}
	return v
}

func dialerFor(p fetcher.Proxy, timeout time.Duration) (DialFunc, error) {
	switch p.Scheme {
	case "socks5":
		d, err := proxy.SOCKS5("tcp", p.Address, nil, &net.Dialer{Timeout: timeout})
		if err != nil {
			return nil, err
		}
		return wrapCtxDialer(d), nil
	case "http", "https":
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			return httpConnectDial(p.Address, addr, timeout, ctx)
		}, nil
	default:
		return nil, fmt.Errorf("unsupported scheme %q", p.Scheme)
	}
}

func wrapCtxDialer(d proxy.Dialer) DialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		type dialResult struct {
			c   net.Conn
			err error
		}
		ch := make(chan dialResult, 1)
		go func() {
			c, err := d.Dial(network, addr)
			ch <- dialResult{c, err}
		}()
		select {
		case <-ctx.Done():
			go func() {
				if res := <-ch; res.c != nil {
					res.c.Close()
				}
			}()
			return nil, ctx.Err()
		case res := <-ch:
			return res.c, res.err
		}
	}
}

func httpConnectDial(proxyAddr, target string, timeout time.Duration, ctx context.Context) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write([]byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n")); err != nil {
		conn.Close()
		return nil, err
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, err
	}
	line := string(buf[:n])
	if !contains(line, " 200 ") {
		conn.Close()
		return nil, fmt.Errorf("upstream refused CONNECT: %q", firstLine(line))
	}
	return conn, nil
}

func firstLine(s string) string {
	for i, c := range s {
		if c == '\n' || c == '\r' {
			return s[:i]
		}
	}
	return s
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

var _ = url.Parse // keep url import if future parser lands here
var _ = errors.New
