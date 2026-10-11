package replay

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func TestConsumeOnce(t *testing.T) {
	s := New(10)
	exp := t0.Add(time.Hour)
	if err := s.Consume("a.b.c", exp, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Consume("a.b.c", exp, t0.Add(time.Minute)); !errors.Is(err, ErrReplayed) {
		t.Fatal(err)
	}
	if err := s.Consume("other", exp, t0); err != nil {
		t.Fatal("distinct token rejected:", err)
	}
}

func TestKeyIgnoresUnusedBase64Bits(t *testing.T) {
	// "AAA" and "AAB" decode to the same two bytes: the final character's low
	// two bits are unused. Lenient JWT verification accepts both encodings.
	if Key("eyJ.eyJ.AAA") != Key("eyJ.eyJ.AAB") {
		t.Fatal("alternate signature encodings produced different keys")
	}
	if Key("eyJ.eyJ.AAA") != Key("eyJ.eyJ.AAA==") {
		t.Fatal("padding changed the key")
	}
	if Key("eyJ.eyJ.AAA") == Key("eyJ.eyJ.AAE") {
		t.Fatal("different signatures collided")
	}
	if Key("a.b") == Key("a.b.") || Key("ab.c") == Key("a.bc") {
		t.Fatal("segment boundaries must be part of the key")
	}
	s := New(10)
	exp := t0.Add(time.Hour)
	if err := s.Consume("eyJ.eyJ.AAA", exp, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Consume("eyJ.eyJ.AAB", exp, t0); !errors.Is(err, ErrReplayed) {
		t.Fatal("re-encoded signature accepted:", err)
	}
}

func TestExpiryPurge(t *testing.T) {
	s := New(10)
	exp := t0.Add(time.Hour)
	_ = s.Consume("a", exp, t0)
	if err := s.Consume("a", exp, exp.Add(-time.Second)); !errors.Is(err, ErrReplayed) {
		t.Fatal("accepted before expiry")
	}
	// After expiry the entry is purged; a re-issued token with a later exp is new.
	if err := s.Consume("a", exp.Add(2*time.Hour), exp); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 1 {
		t.Fatal(s.Len())
	}
	_ = s.Consume("b", exp.Add(time.Hour), exp)
	_ = s.Consume("c", exp.Add(5*time.Hour), exp.Add(3*time.Hour))
	if s.Len() != 1 {
		t.Fatalf("expired entries retained: %d", s.Len())
	}
}

func TestExpiredTokenRefused(t *testing.T) {
	s := New(10)
	if err := s.Consume("a", t0, t0); !errors.Is(err, ErrExpired) || s.Len() != 0 {
		t.Fatal(err, s.Len())
	}
	// A token consumed just before expiry must not be accepted again by a
	// request that reaches the store after its entry was purged.
	exp := t0.Add(time.Second)
	if err := s.Consume("race", exp, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Consume("race", exp, exp); !errors.Is(err, ErrExpired) {
		t.Fatal("expired token accepted after purge:", err)
	}
}

func TestFullStoreRefusesWithoutEvicting(t *testing.T) {
	s := New(2)
	_ = s.Consume("early", t0.Add(1*time.Minute), t0)
	_ = s.Consume("late", t0.Add(10*time.Minute), t0)
	if err := s.Consume("new", t0.Add(5*time.Minute), t0); !errors.Is(err, ErrFull) {
		t.Fatal("full store did not refuse:", err)
	}
	for _, raw := range []string{"early", "late"} {
		if err := s.Consume(raw, t0.Add(10*time.Minute), t0); !errors.Is(err, ErrReplayed) {
			t.Fatal("live entry evicted:", raw, err)
		}
	}
	if err := s.Consume("new", t0.Add(5*time.Minute), t0.Add(time.Minute)); err != nil {
		t.Fatal("capacity not reclaimed after expiry:", err)
	}
	if s.Len() != 2 {
		t.Fatal(s.Len())
	}
}

func TestConcurrentSingleWinner(t *testing.T) {
	s := New(100)
	exp := t0.Add(time.Hour)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if s.Consume("same", exp, t0) == nil {
				wins.Add(1)
			}
			_ = s.Consume(fmt.Sprint("t", i), exp, t0)
		}(i)
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal("winners:", wins.Load())
	}
	if s.Len() > 100 {
		t.Fatal(s.Len())
	}
}
