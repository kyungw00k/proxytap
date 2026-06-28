package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kyungw00k/proxytap/internal/limiter"
	"github.com/kyungw00k/proxytap/internal/pool"
	"golang.org/x/net/proxy"
)

const (
	maxRetries      = 3
	upstreamTimeout = 30 * time.Second
	copyBufferSize  = 32 * 1024
)

var retryStatuses = map[int]bool{
	http.StatusTooManyRequests:     true, // 429
	http.StatusForbidden:           true, // 403
	http.StatusServiceUnavailable:  true, // 503
}

type Picker interface {
	Pick() (*pool.Entry, func(ok bool))
}

type Server struct {
	listenAddr string
	picker     Picker
	bucket     *limiter.TokenBucket
	srv        *http.Server
	requests   atomic.Int64
	bytesIn    atomic.Int64
	bytesOut   atomic.Int64
	blocked    atomic.Int64
	retried    atomic.Int64
}

func New(listenAddr string, picker Picker, bucket *limiter.TokenBucket) *Server {
	s := &Server{
		listenAddr: listenAddr,
		picker:     picker,
		bucket:     bucket,
	}
	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           http.HandlerFunc(s.handle),
		ReadHeaderTimeout: 10 * time.Second,
	}
	s.srv = srv
	return s
}

func (s *Server) ListenAndServe() error {
	fmt.Printf("proxy: listening on http://%s\n", s.listenAddr)
	return s.srv.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

func (s *Server) Requests() int64  { return s.requests.Load() }
func (s *Server) BytesIn() int64   { return s.bytesIn.Load() }
func (s *Server) BytesOut() int64  { return s.bytesOut.Load() }
func (s *Server) Blocked() int64   { return s.blocked.Load() }
func (s *Server) Retried() int64   { return s.retried.Load() }

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.requests.Add(1)
	if s.bucket != nil && !s.bucket.Allow() {
		s.blocked.Add(1)
		w.Header().Set("Retry-After", "1")
		http.Error(w, "proxytap: global rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	s.handleHTTP(w, r)
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		entry, release := s.picker.Pick()
		if entry == nil {
			http.Error(w, "no healthy proxy in pool", http.StatusBadGateway)
			return
		}

		client, err := clientForEntry(entry)
		if err != nil {
			release(false)
			lastErr = err
			continue
		}

		sanitizeHeaders(r.Header)

		req := r.Clone(r.Context())
		req.RequestURI = ""
		resp, err := client.Do(req)
		if err != nil {
			release(false)
			lastErr = err
			continue
		}

		if retryStatuses[resp.StatusCode] {
			resp.Body.Close()
			release(false)
			s.retried.Add(1)
			lastErr = fmt.Errorf("upstream returned %d", resp.StatusCode)
			continue
		}

		defer resp.Body.Close()
		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		n, _ := io.Copy(w, resp.Body)
		s.bytesOut.Add(n)
		release(true)
		return
	}
	http.Error(w, fmt.Sprintf("all retries exhausted: %v", lastErr), http.StatusBadGateway)
}

// handleConnect implements HTTP CONNECT for HTTPS (and arbitrary TCP).
// We open a tunneled connection via the chosen upstream and pipe bytes both
// ways. On upstream failure we retry transparently up to maxRetries.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	if host == "" {
		http.Error(w, "CONNECT: missing host", http.StatusBadRequest)
		return
	}

	var (
		upstream net.Conn
		entry    *pool.Entry
		release  func(bool)
		err      error
	)
	for attempt := 0; attempt < maxRetries; attempt++ {
		entry, release = s.picker.Pick()
		if entry == nil {
			http.Error(w, "no healthy proxy in pool", http.StatusBadGateway)
			return
		}
		upstream, err = dialUpstream(entry, host)
		if err == nil {
			break
		}
		release(false)
	}
	if upstream == nil {
		http.Error(w, fmt.Sprintf("CONNECT: dial failed: %v", err), http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		release(false)
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		release(false)
		return
	}
	defer client.Close()

	// Tell the client the tunnel is up.
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		release(false)
		return
	}

	// Copy bidirectionally, counting bytes.
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.CopyBuffer(upstream, client, make([]byte, copyBufferSize))
		s.bytesIn.Add(n)
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.CopyBuffer(client, upstream, make([]byte, copyBufferSize))
		s.bytesOut.Add(n)
		done <- struct{}{}
	}()

	<-done // first side closes the tunnel
	release(true)
	_ = entry // entry captured for future metrics
}

func clientForEntry(e *pool.Entry) (*http.Client, error) {
	switch e.Proxy.Scheme {
	case "socks5":
		dialer, err := proxy.SOCKS5("tcp", e.Proxy.Address, nil,
			&net.Dialer{Timeout: upstreamTimeout})
		if err != nil {
			return nil, err
		}
		tr := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			},
			ResponseHeaderTimeout: upstreamTimeout,
		}
		return &http.Client{Transport: tr, Timeout: upstreamTimeout}, nil
	case "http", "https":
		u, err := url.Parse(e.Proxy.String())
		if err != nil {
			return nil, err
		}
		tr := &http.Transport{Proxy: http.ProxyURL(u)}
		return &http.Client{Transport: tr, Timeout: upstreamTimeout}, nil
	default:
		return nil, errors.New("unsupported scheme: " + e.Proxy.Scheme)
	}
}

func dialUpstream(e *pool.Entry, target string) (net.Conn, error) {
	switch e.Proxy.Scheme {
	case "socks5":
		dialer, err := proxy.SOCKS5("tcp", e.Proxy.Address, nil,
			&net.Dialer{Timeout: upstreamTimeout})
		if err != nil {
			return nil, err
		}
		return dialer.Dial("tcp", target)
	case "http", "https":
		// HTTP CONNECT through an HTTP upstream. We open a raw TCP connection
		// to the proxy and issue CONNECT manually — keeps us off the stdlib
		// http.Transport path which would not let us hijack the stream.
		conn, err := net.DialTimeout("tcp", e.Proxy.Address, upstreamTimeout)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
		br := make([]byte, 256)
		n, _ := conn.Read(br)
		status := strings.SplitN(string(br[:n]), " ", 3)
		if len(status) < 2 || !strings.HasPrefix(status[1], "200") {
			conn.Close()
			return nil, fmt.Errorf("upstream HTTP CONNECT refused: %s", strings.TrimSpace(string(br[:n])))
		}
		return conn, nil
	default:
		return nil, errors.New("unsupported scheme: " + e.Proxy.Scheme)
	}
}

func sanitizeHeaders(h http.Header) {
	hopByHop := []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailers", "Transfer-Encoding", "Upgrade",
	}
	for _, k := range hopByHop {
		h.Del(k)
	}
	// strip accidental forwarding headers to maximise anonymity
	h.Del("X-Forwarded-For")
	h.Del("X-Real-Ip")
	h.Del("Via")
	h.Del("X-Proxy-Id")
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}
