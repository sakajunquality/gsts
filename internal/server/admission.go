package server

import (
	"math"
	"slices"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sakajunquality/gsts/internal/config"
)

// admission bounds all exchange attempts, including invalid credentials, before
// any remote work. There are no queues or attacker-controlled map keys.
type admission struct {
	mu      sync.Mutex
	active  int
	tokens  float64
	updated time.Time
}

func (a *admission) acquire(c config.Config, now time.Time) (release func(), retry int) {
	maxConcurrent, rate, burst := c.MaxConcurrent, c.ExchangeRate, c.ExchangeBurst
	if maxConcurrent <= 0 {
		maxConcurrent = config.DefaultMaxConcurrent
	}
	if rate <= 0 {
		rate = config.DefaultExchangeRate
	}
	if burst <= 0 {
		burst = config.DefaultExchangeBurst
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.updated.IsZero() {
		a.tokens = float64(burst)
		a.updated = now
	}
	elapsed := math.Max(0, now.Sub(a.updated).Seconds())
	a.tokens = math.Min(float64(burst), a.tokens+elapsed*float64(rate)/60)
	if now.After(a.updated) {
		a.updated = now
	}
	if a.active >= maxConcurrent {
		return nil, 1
	}
	if a.tokens < 1 {
		return nil, max(1, int(math.Ceil((1-a.tokens)*60/float64(rate))))
	}
	a.tokens--
	a.active++
	var once sync.Once
	return func() { once.Do(func() { a.mu.Lock(); a.active--; a.mu.Unlock() }) }, 0
}

// admittedClaims restricts audience evaluation to the intersection with the
// service allowlist. A second, unlisted audience cannot authorize a policy.
func admittedClaims(claims jwt.MapClaims, c config.Config) (jwt.MapClaims, bool) {
	allowed := c.AllowedAudiences
	if len(allowed) == 0 {
		allowed = []string{c.Identifier}
	}
	audiences, err := claims.GetAudience()
	if err != nil {
		return nil, false
	}
	var admitted []string
	for _, aud := range audiences {
		if aud != "" && slices.Contains(allowed, aud) {
			admitted = append(admitted, aud)
		}
	}
	if len(admitted) == 0 {
		return nil, false
	}
	copy := jwt.MapClaims{}
	for k, v := range claims {
		copy[k] = v
	}
	if _, scalar := claims["aud"].(string); !scalar {
		copy["aud"] = admitted
	}
	return copy, true
}
