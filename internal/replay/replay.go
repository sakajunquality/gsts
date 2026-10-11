// Package replay remembers consumed ID tokens so each is accepted at most once
// per process. It is in-memory and per instance; it is not a fleet-wide store.
package replay

import (
	"container/heap"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"time"
)

// ErrReplayed reports that a token was already consumed and has not expired.
var ErrReplayed = errors.New("ID token already used")

// ErrExpired reports that the token expired before it could be consumed.
var ErrExpired = errors.New("ID token expired before use")

// ErrFull reports that the store cannot remember another live token. The
// request must be refused: evicting a live entry would let that token be
// replayed.
var ErrFull = errors.New("replay store full")

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

// Key identifies a compact JWT by its decoded segments rather than its text.
// JWT verification decodes base64url leniently, so one signature has several
// textual encodings (unused trailing bits, optional padding); hashing the
// decoded bytes maps all of them to the same key. A segment that does not
// decode is hashed as written.
func Key(raw string) [sha256.Size]byte {
	h := sha256.New()
	for _, seg := range strings.Split(raw, ".") {
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(seg, "="))
		if err != nil {
			b = []byte(seg)
		}
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	var key [sha256.Size]byte
	copy(key[:], h.Sum(nil))
	return key
}

// Store holds the keys of consumed JWTs until their expiry. Memory is bounded
// by maxEntries; only hashes are retained, never the tokens.
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
// has not yet expired, ErrExpired if exp is not in the future (the entry a
// concurrent request recorded may already have been purged, so an expired
// token is never accepted), and ErrFull when no live entry can be added.
// Expired entries are purged first; live entries are never evicted.
func (s *Store) Consume(raw string, exp, now time.Time) error {
	key := Key(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.byExp) > 0 && !s.byExp[0].exp.After(now) {
		delete(s.seen, heap.Pop(&s.byExp).(*entry).key)
	}
	if !exp.After(now) {
		return ErrExpired
	}
	if _, ok := s.seen[key]; ok {
		return ErrReplayed
	}
	if len(s.seen) >= s.max {
		return ErrFull
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
