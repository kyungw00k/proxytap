package mitm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
)

func (e *Engine) DiscoverPlainRef(ctx context.Context) error {
	body, err := e.fetchPlainDirect(ctx, e.plainTarget)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	e.mu.Lock()
	e.plainRef = hash
	e.mu.Unlock()
	return nil
}

func (e *Engine) fetchPlainDirect(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "proxytap-mitm/0.1")
	client := &http.Client{Timeout: e.timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("plain ref: status " + resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64*1024))
}

func (e *Engine) probePlain(ctx context.Context, dial DialFunc) ProbeResult {
	e.mu.RLock()
	want := e.plainRef
	target := e.plainTarget
	e.mu.RUnlock()
	if want == "" {
		return ProbeResult{
			Layer:  LayerPlainBody,
			Pass:   true,
			Reason: "skipped: plain reference not discovered",
		}
	}

	body, hashStr, status, err := e.fetchPlainViaProxy(ctx, target, dial)
	if err != nil {
		return ProbeResult{
			Layer:  LayerPlainBody,
			Pass:   false,
			Reason: "fetch via proxy failed: " + err.Error(),
		}
	}
	if status != http.StatusOK {
		return ProbeResult{
			Layer:    LayerPlainBody,
			Pass:     false,
			Reason:   "non-200 from target via proxy",
			Evidence: "status=" + http.StatusText(status),
		}
	}
	if hashStr == want {
		return ProbeResult{Layer: LayerPlainBody, Pass: true}
	}

	snippet := string(body)
	if len(snippet) > 160 {
		snippet = snippet[:160] + "..."
	}
	return ProbeResult{
		Layer:    LayerPlainBody,
		Pass:     false,
		Reason:   "response body modified in transit — possible injection",
		Evidence: "got " + hashStr[:16] + "... want " + want[:16] + "... ; body: " + snippet,
	}
}

func (e *Engine) fetchPlainViaProxy(ctx context.Context, target string, dial DialFunc) (body []byte, hash string, status int, err error) {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dial(ctx, network, addr)
		},
		ResponseHeaderTimeout: e.timeout,
	}
	client := &http.Client{Transport: transport, Timeout: e.timeout}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, "", 0, err
	}
	req.Header.Set("User-Agent", "proxytap-mitm/0.1")

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", 0, err
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, "", resp.StatusCode, err
	}
	sum := sha256.Sum256(body)
	return body, hex.EncodeToString(sum[:]), resp.StatusCode, nil
}

var _ = sync.Mutex{}
