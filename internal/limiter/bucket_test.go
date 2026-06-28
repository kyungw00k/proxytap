package limiter

import (
	"testing"
	"time"
)

func TestTokenBucket_BurstThenBlock(t *testing.T) {
	b := NewTokenBucket(0, 2)
	if !b.Allow() {
		t.Fatal("1st call should be allowed")
	}
	if !b.Allow() {
		t.Fatal("2nd call should be allowed")
	}
	if b.Allow() {
		t.Fatal("3rd call should be blocked (burst exhausted, rate=0)")
	}
}

func TestTokenBucket_Refills(t *testing.T) {
	b := NewTokenBucket(20, 1)
	if !b.Allow() {
		t.Fatal("1st call should be allowed")
	}
	if b.Allow() {
		t.Fatal("2nd call too soon, should be blocked")
	}
	time.Sleep(70 * time.Millisecond)
	if !b.Allow() {
		t.Fatal("after 70ms at rate=20/s, 1 token should have refilled")
	}
}

func TestTokenBucket_TokensReflectsState(t *testing.T) {
	b := NewTokenBucket(0, 3)
	if got := b.Tokens(); got != 3 {
		t.Fatalf("initial tokens = %d; want 3", got)
	}
	b.Allow()
	b.Allow()
	if got := b.Tokens(); got != 1 {
		t.Fatalf("after 2 Allow, tokens = %d; want 1", got)
	}
}
