package limiter

import (
	"sync"
	"time"
)

type TokenBucket struct {
	mu     sync.Mutex
	rate   int
	burst  int
	tokens int
	last   time.Time
}

func NewTokenBucket(rate, burst int) *TokenBucket {
	if burst <= 0 {
		burst = rate
	}
	return &TokenBucket{
		rate:   rate,
		burst:  burst,
		tokens: burst,
		last:   time.Now(),
	}
}

func (b *TokenBucket) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	if b.rate > 0 {
		elapsed := now.Sub(b.last).Seconds()
		refill := int(elapsed * float64(b.rate))
		if refill > 0 {
			b.tokens += refill
			if b.tokens > b.burst {
				b.tokens = b.burst
			}
			b.last = now
		}
	}
	if b.tokens > 0 {
		b.tokens--
		return true
	}
	return false
}

func (b *TokenBucket) Tokens() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.tokens
}
