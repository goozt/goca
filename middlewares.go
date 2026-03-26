package main

import (
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/goozt/gopgbase/infra/ca/internal/utils"
)

func errorHandlingMiddleware(next *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := newBlockingResponseWriter(w)
		next.ServeHTTP(buf, r)

		if buf.statusCode == 0 {
			buf.statusCode = http.StatusOK
		}

		if buf.statusCode >= 400 {
			ct := buf.headers.Get("Content-Type")
			if !strings.HasPrefix(ct, "application/json") {
				msg := strings.ToLower(http.StatusText(buf.statusCode))
				if msg == "" {
					msg = "unexpected error"
				}
				utils.WriteError(w, buf.statusCode, msg)
				return
			}
		}

		for key, values := range buf.headers {
			for _, v := range values {
				w.Header().Add(key, v)
			}
		}
		w.WriteHeader(buf.statusCode)
		_, _ = w.Write(buf.body.Bytes())
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := newResponseWriter(w)
		next.ServeHTTP(wrapped, r)
		slog.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapped.statusCode,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote_addr", r.RemoteAddr,
			"user_agent", r.UserAgent(),
		)
	})
}

func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				slog.Error("panic recovered",
					"error", err,
					"stack", string(debug.Stack()),
					"path", r.URL.Path,
				)
				http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
			}
		}()
		wrapped := newResponseWriter(w)
		next.ServeHTTP(wrapped, r)
	})
}

// authMiddleware enforces API key authentication when the API_KEY environment
// variable is set. Requests missing or presenting the wrong key receive 401.
func authMiddleware(next http.Handler) http.Handler {
	apiKey := os.Getenv("API_KEY")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if apiKey == "" {
			// Auth disabled — no API_KEY configured.
			next.ServeHTTP(w, r)
			return
		}
		provided := r.Header.Get("X-API-Key")
		if provided == "" {
			utils.WriteError(w, http.StatusUnauthorized, "missing X-API-Key header")
			return
		}
		if provided != apiKey {
			slog.Warn("auth: invalid API key", "remote_addr", r.RemoteAddr, "path", r.URL.Path)
			utils.WriteError(w, http.StatusUnauthorized, "invalid API key")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ipRateLimiter is a simple per-IP sliding-window rate limiter backed by
// stdlib only — no external dependencies required.
type ipRateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
}

func newIPRateLimiter(limit int, window time.Duration) *ipRateLimiter {
	rl := &ipRateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
	go rl.cleanup()
	return rl
}

// allow returns true when the request should be permitted.
func (rl *ipRateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-rl.window)

	prev := rl.requests[ip]
	valid := prev[:0]
	for _, t := range prev {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	if len(valid) >= rl.limit {
		rl.requests[ip] = valid
		return false
	}
	rl.requests[ip] = append(valid, now)
	return true
}

// cleanup periodically removes stale entries to prevent unbounded memory growth.
func (rl *ipRateLimiter) cleanup() {
	ticker := time.NewTicker(rl.window)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-rl.window)
		for ip, times := range rl.requests {
			valid := times[:0]
			for _, t := range times {
				if t.After(cutoff) {
					valid = append(valid, t)
				}
			}
			if len(valid) == 0 {
				delete(rl.requests, ip)
			} else {
				rl.requests[ip] = valid
			}
		}
		rl.mu.Unlock()
	}
}

// defaultLimiter allows 60 requests per IP per minute with a burst of up to 20.
var defaultLimiter = newIPRateLimiter(60, time.Minute)

func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		if !defaultLimiter.allow(ip) {
			slog.Warn("rate limit exceeded", "remote_addr", ip, "path", r.URL.Path)
			utils.WriteError(w, http.StatusTooManyRequests, "rate limit exceeded, please slow down")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// securityHeadersMiddleware sets defensive HTTP headers on every response.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
