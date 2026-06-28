package api

import (
	"context"
	_ "embed"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/kyungw00k/proxytap/internal/fetcher"
	"github.com/kyungw00k/proxytap/internal/mitm"
	"github.com/kyungw00k/proxytap/internal/pool"
)

//go:embed dashboard/index.html
var dashboardHTML []byte

type VerdictSource interface {
	RecentVerdicts() []mitm.Verdict
}

// Server is the read-mostly control plane. It exposes JSON endpoints for the
// (future) menubar app and for ad-hoc curl inspection.
type Server struct {
	listenAddr string
	pool       *pool.Pool
	fetcher    *fetcher.Fetcher
	verdicts   VerdictSource
	srv        *http.Server
}

type StatsResp struct {
	Pool          pool.Stats `json:"pool"`
	RequestsServed int64     `json:"requests_served"`
	LastFetch     string     `json:"last_fetch,omitempty"`
	Sources       []string   `json:"sources"`
}

type ProxyDTO struct {
	Scheme     string `json:"scheme"`
	Address    string `json:"address"`
	Source     string `json:"source,omitempty"`
	ExitIP     string `json:"exit_ip,omitempty"`
	AnonLevel  string `json:"anon_level,omitempty"`
	RTTMillis  int64  `json:"rtt_ms,omitempty"`
	Healthy    bool   `json:"healthy"`
	Failures   int    `json:"failures"`
	Successes  int64  `json:"successes"`
	LastOK     string `json:"last_ok,omitempty"`
}

func New(listenAddr string, p *pool.Pool, f *fetcher.Fetcher, vs VerdictSource) *Server {
	s := &Server{
		listenAddr: listenAddr,
		pool:       p,
		fetcher:    f,
		verdicts:   vs,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleDashboard)
	mux.HandleFunc("/stats", s.handleStats)
	mux.HandleFunc("/proxies", s.handleProxies)
	mux.HandleFunc("/sources", s.handleSources)
	mux.HandleFunc("/mitm", s.handleMITM)
	s.srv = &http.Server{Addr: listenAddr, Handler: mux}
	return s
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(dashboardHTML)
}

func (s *Server) ListenAndServe() error {
	return s.srv.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	_, last := s.fetcher.Cached()
	resp := StatsResp{
		Pool:           s.pool.Stats(),
		RequestsServed: s.pool.RequestsServed(),
		LastFetch:      last.Format("2006-01-02T15:04:05Z07:00"),
		Sources:        s.fetcher.Sources(),
	}
	writeJSON(w, resp)
}

func (s *Server) handleProxies(w http.ResponseWriter, r *http.Request) {
	healthyOnly := r.URL.Query().Has("healthy")
	out := []ProxyDTO{}
	for _, e := range s.pool.Snapshot() {
		dto := ProxyDTO{
			Scheme:    e.Proxy.Scheme,
			Address:   e.Proxy.Address,
			Source:    e.Proxy.Source,
			ExitIP:    e.ExitIP,
			AnonLevel: string(e.AnonLevel),
			RTTMillis: e.RTT.Milliseconds(),
			Healthy:   !e.LastOK.IsZero() && e.Failures == 0,
			Failures:  e.Failures,
			Successes: e.Successes,
		}
		if !e.LastOK.IsZero() {
			dto.LastOK = e.LastOK.Format("2006-01-02T15:04:05Z07:00")
		}
		if healthyOnly && !dto.Healthy {
			continue
		}
		out = append(out, dto)
	}
	writeJSON(w, out)
}

func (s *Server) handleSources(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]any{"sources": s.fetcher.Sources()})
	case http.MethodPost, http.MethodPut:
		var body struct {
			Sources []string `json:"sources"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		// minimal sanity: every source must look like a URL
		for _, u := range body.Sources {
			if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
				http.Error(w, "invalid source: "+u, http.StatusBadRequest)
				return
			}
		}
		s.fetcher.SetSources(body.Sources)
		writeJSON(w, map[string]any{"sources": s.fetcher.Sources()})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleMITM(w http.ResponseWriter, r *http.Request) {
	onlyDirty := r.URL.Query().Has("dirty")
	if s.verdicts == nil {
		writeJSON(w, map[string]any{"verdicts": []any{}})
		return
	}
	all := s.verdicts.RecentVerdicts()
	out := make([]mitm.Verdict, 0, len(all))
	for _, v := range all {
		if onlyDirty && v.Clean {
			continue
		}
		out = append(out, v)
	}
	writeJSON(w, map[string]any{
		"total":      len(all),
		"shown":      len(out),
		"filter":     map[string]bool{"dirty": onlyDirty},
		"verdicts":   out,
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
