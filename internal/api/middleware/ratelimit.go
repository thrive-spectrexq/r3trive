package middleware

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type clientRecord struct {
	tokens     float64
	lastRefill time.Time
}

// RateLimit implements an in-memory token bucket rate limiter per client IP.
func RateLimit(requestsPerMin int) func(http.Handler) http.Handler {
	if requestsPerMin <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}

	var mu sync.Mutex
	clients := make(map[string]*clientRecord)
	rate := float64(requestsPerMin) / 60.0 // tokens per second
	burst := float64(requestsPerMin)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := extractIP(r)

			mu.Lock()
			rec, exists := clients[ip]
			now := time.Now()
			if !exists {
				rec = &clientRecord{tokens: burst, lastRefill: now}
				clients[ip] = rec
			} else {
				elapsed := now.Sub(rec.lastRefill).Seconds()
				rec.tokens += elapsed * rate
				if rec.tokens > burst {
					rec.tokens = burst
				}
				rec.lastRefill = now
			}

			if rec.tokens < 1.0 {
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": "rate limit exceeded",
				})
				return
			}

			rec.tokens -= 1.0
			mu.Unlock()

			next.ServeHTTP(w, r)
		})
	}
}

func extractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
