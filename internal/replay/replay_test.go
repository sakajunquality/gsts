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

func TestExpiryPurge(t *testing.T) {
	s := New(10)
	exp := t0.Add(time.Hour)
	_ = s.Consume("a", exp, t0)
	if err := s.Consume("a", exp, exp.Add(-time.Second)); !errors.Is(err, ErrReplayed) {
		t.Fatal("accepted before expiry")
	}
	// After expiry the entry is purged; the token itself would fail verification.
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

func TestAlreadyExpiredNotStored(t *testing.T) {
	s := New(10)
	if err := s.Consume("a", t0, t0); err != nil || s.Len() != 0 {
		t.Fatal(err, s.Len())
	}
}

func TestEvictsEarliestExpiryWhenFull(t *testing.T) {
	s := New(2)
	_ = s.Consume("early", t0.Add(1*time.Minute), t0)
	_ = s.Consume("late", t0.Add(10*time.Minute), t0)
	if err := s.Consume("new", t0.Add(5*time.Minute), t0); err != nil {
		t.Fatal("full store rejected request:", err)
	}
	if s.Len() != 2 {
		t.Fatal(s.Len())
	}
	if err := s.Consume("late", t0.Add(10*time.Minute), t0); !errors.Is(err, ErrReplayed) {
		t.Fatal("later-expiring entry evicted")
	}
	if err := s.Consume("new", t0.Add(5*time.Minute), t0); !errors.Is(err, ErrReplayed) {
		t.Fatal("new entry missing")
	}
	if err := s.Consume("early", t0.Add(1*time.Minute), t0); err != nil {
		t.Fatal("evicted entry should be accepted again:", err)
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
