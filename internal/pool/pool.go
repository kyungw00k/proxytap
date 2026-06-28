package pool

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/kyungw00k/proxytap/internal/checker"
	"github.com/kyungw00k/proxytap/internal/fetcher"
)

// Entry is the live, mutable per-proxy state tracked by the pool.
type Entry struct {
	Proxy      fetcher.Proxy
	ExitIP     string
	AnonLevel  checker.AnonLevel
	LastOK     time.Time
	RTT        time.Duration
	Failures   int
	Successes  int64
	Inflight   int32
}

type Stats struct {
	Total      int
	Healthy    int
	Unhealthy  int
	ByScheme   map[string]int
	ByAnon     map[string]int
	LastRotate time.Time
}

type rotationPolicy int

const (
	RoundRobin rotationPolicy = iota
)

type Pool struct {
	mu          sync.RWMutex
	entries     []*Entry
	idx         int
	policy      rotationPolicy
	maxFailures int
	minAnonLvl  checker.AnonLevel
	capacity    int

	requestsServed atomic.Int64
	lastRotate     atomic.Value // time.Time
}

type Options struct {
	MaxFailures  int
	MinAnonLevel checker.AnonLevel
	Capacity     int
}

func New(opts Options) *Pool {
	if opts.MaxFailures == 0 {
		opts.MaxFailures = 5
	}
	if opts.MinAnonLevel == "" {
		opts.MinAnonLevel = checker.AnonElite
	}
	if opts.Capacity == 0 {
		opts.Capacity = 500
	}
	p := &Pool{
		policy:      RoundRobin,
		maxFailures: opts.MaxFailures,
		minAnonLvl:  opts.MinAnonLevel,
		capacity:    opts.Capacity,
	}
	p.lastRotate.Store(time.Time{})
	return p
}

// Reset replaces the entire pool. Used by the fetcher when a fresh list is
// pulled. Live entries that still match (by Proxy URL) keep their counters.
func (p *Pool) Reset(proxies []fetcher.Proxy) {
	p.mu.Lock()
	defer p.mu.Unlock()

	prev := map[string]*Entry{}
	for _, e := range p.entries {
		prev[e.Proxy.String()] = e
	}

	next := make([]*Entry, 0, len(proxies))
	for _, pr := range proxies {
		if p.capacity > 0 && len(next) >= p.capacity {
			break
		}
		if e, ok := prev[pr.String()]; ok {
			next = append(next, e)
			continue
		}
		next = append(next, &Entry{Proxy: pr})
	}
	p.entries = next
	if p.idx >= len(next) {
		p.idx = 0
	}
}

// Apply merges a health-check result. Healthy entries are marked OK and
// promoted; failing entries accumulate failures and are quarantined once
// the threshold is exceeded.
func (p *Pool) Apply(r checker.Result) {
	p.mu.Lock()
	defer p.mu.Unlock()

	entry := p.findOrCreateLocked(r.Proxy)
	if entry == nil {
		return
	}
	if r.OK {
		entry.LastOK = time.Now()
		entry.RTT = r.RTT
		entry.ExitIP = r.ExitIP
		entry.AnonLevel = r.AnonLvl
		entry.Failures = 0
		return
	}
	entry.Failures++
}

func (p *Pool) findOrCreateLocked(pr fetcher.Proxy) *Entry {
	for _, e := range p.entries {
		if e.Proxy.String() == pr.String() {
			return e
		}
	}
	e := &Entry{Proxy: pr}
	p.entries = append(p.entries, e)
	return e
}

// healthyLocked returns whether an entry is currently usable.
func (p *Pool) healthyLocked(e *Entry) bool {
	if e == nil {
		return false
	}
	if e.Failures > p.maxFailures {
		return false
	}
	if !anonMeets(e.AnonLevel, p.minAnonLvl) {
		return false
	}
	if e.LastOK.IsZero() {
		return false
	}
	return true
}

// Pick selects the next healthy entry under the rotation policy. Returns
// the entry and a release function the caller MUST defer to update counters.
// If no healthy proxy is available, returns nil.
func (p *Pool) Pick() (*Entry, func(ok bool)) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.entries) == 0 {
		return nil, func(bool) {}
	}

	n := len(p.entries)
	for i := 0; i < n; i++ {
		idx := (p.idx + i) % n
		e := p.entries[idx]
		if !p.healthyLocked(e) {
			continue
		}
		p.idx = (idx + 1) % n
		atomic.AddInt32(&e.Inflight, 1)
		p.requestsServed.Add(1)
		return e, func(ok bool) {
			atomic.AddInt32(&e.Inflight, -1)
			if ok {
				atomic.AddInt64(&e.Successes, 1)
				return
			}
			// light-touch failure bump; full Apply path is reserved for
			// explicit health-check results.
			p.mu.Lock()
			e.Failures++
			p.mu.Unlock()
		}
	}
	return nil, func(bool) {}
}

// Snapshot returns a deep-enough copy for read-only inspection (REST API).
func (p *Pool) Snapshot() []Entry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Entry, 0, len(p.entries))
	for _, e := range p.entries {
		out = append(out, *e)
	}
	return out
}

func (p *Pool) Stats() Stats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	s := Stats{
		Total:      len(p.entries),
		ByScheme:   map[string]int{},
		ByAnon:     map[string]int{},
	}
	for _, e := range p.entries {
		s.ByScheme[e.Proxy.Scheme]++
		if e.AnonLevel == "" {
			s.ByAnon[string(checker.AnonUnknown)]++
		} else {
			s.ByAnon[string(e.AnonLevel)]++
		}
		if p.healthyLocked(e) {
			s.Healthy++
		} else {
			s.Unhealthy++
		}
	}
	s.LastRotate, _ = p.lastRotate.Load().(time.Time)
	return s
}

func (p *Pool) RequestsServed() int64 { return p.requestsServed.Load() }

func anonMeets(have, want checker.AnonLevel) bool {
	if want == "" {
		return true
	}
	if have == "" {
		// not yet probed → allow on first pass; the checker will classify
		return true
	}
	order := map[checker.AnonLevel]int{
		checker.AnonElite:       3,
		checker.AnonAnonymous:   2,
		checker.AnonTransparent: 1,
		checker.AnonUnknown:     0,
	}
	return order[have] >= order[want]
}
