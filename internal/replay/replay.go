// Package replay remembers consumed ID tokens so each is accepted at most once
// per process. It is in-memory and per instance; it is not a fleet-wide store.
package replay

import (
	"container/heap"
	"crypto/sha256"
	"errors"
	"sync"
	"time"
)

// ErrReplayed reports that a token was already consumed and has not expired.
var ErrReplayed = errors.New("ID token already used")

type entry struct {
	key   [sha256.Size]byte
	exp   time.Time
	index int
}

// expiryHeap orders entries by earliest expiry.
type expiryHeap []*entry

func (h expiryHeap) Len() int           { return len(h) }
func (h expiryHeap) Less(i, j int) bool { return h[i].exp.Before(h[j].exp) }
func (h expiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i]; h[i].index, h[j].index = i, j }
func (h *expiryHeap) Push(x any)        { e := x.(*entry); e.index = len(*h); *h = append(*h, e) }
func (h *expiryHeap) Pop() any {
	old := *h
	e := old[len(old)-1]
	old[len(old)-1] = nil
	*h = old[:len(old)-1]
	return e
}

// Store holds the SHA-256 of consumed raw JWTs until their expiry. Memory is
// bounded by maxEntries; only hashes are retained, never the tokens.
type Store struct {
	mu    sync.Mutex
	max   int
	seen  map[[sha256.Size]byte]*entry
	byExp expiryHeap
}

// New returns a store holding at most maxEntries live tokens (minimum 1).
func New(maxEntries int) *Store {
	return &Store{max: max(1, maxEntries), seen: map[[sha256.Size]byte]*entry{}}
}

// Consume records raw until exp. It returns ErrReplayed if raw was consumed and
// has not yet expired. Expired entries are purged first. When the store is
// full, the entry expiring soonest is evicted so the request is never refused
// for capacity; that token could then be accepted again once.
func (s *Store) Consume(raw string, exp, now time.Time) error {
	key := sha256.Sum256([]byte(raw))
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.byExp) > 0 && !s.byExp[0].exp.After(now) {
		delete(s.seen, heap.Pop(&s.byExp).(*entry).key)
	}
	if _, ok := s.seen[key]; ok {
		return ErrReplayed
	}
	if !exp.After(now) {
		return nil // cannot be accepted again; nothing to remember
	}
	for len(s.seen) >= s.max {
		delete(s.seen, heap.Pop(&s.byExp).(*entry).key)
	}
	e := &entry{key: key, exp: exp}
	s.seen[key] = e
	heap.Push(&s.byExp, e)
	return nil
}

// Len reports the number of remembered tokens, for tests and diagnostics.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}
