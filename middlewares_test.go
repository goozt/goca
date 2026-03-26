package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func okHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func TestAuthMiddleware_NoAPIKeySet(t *testing.T) {
	os.Unsetenv("API_KEY")
	handler := authMiddleware(http.HandlerFunc(okHandler))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("want 200 when API_KEY unset, got %d", w.Code)
	}
}

func TestAuthMiddleware_MissingHeader(t *testing.T) {
	os.Setenv("API_KEY", "secret")
	defer os.Unsetenv("API_KEY")
	handler := authMiddleware(http.HandlerFunc(okHandler))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 for missing header, got %d", w.Code)
	}
}

func TestAuthMiddleware_WrongKey(t *testing.T) {
	os.Setenv("API_KEY", "secret")
	defer os.Unsetenv("API_KEY")
	handler := authMiddleware(http.HandlerFunc(okHandler))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "wrong")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 for wrong key, got %d", w.Code)
	}
}

func TestAuthMiddleware_CorrectKey(t *testing.T) {
	os.Setenv("API_KEY", "secret")
	defer os.Unsetenv("API_KEY")
	handler := authMiddleware(http.HandlerFunc(okHandler))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("want 200 for correct key, got %d", w.Code)
	}
}

func TestRateLimiter_AllowsUnderLimit(t *testing.T) {
	rl := newIPRateLimiter(5, time.Minute)
	for i := 0; i < 5; i++ {
		if !rl.allow("127.0.0.1") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
}

func TestRateLimiter_BlocksOverLimit(t *testing.T) {
	rl := newIPRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		rl.allow("127.0.0.1")
	}
	if rl.allow("127.0.0.1") {
		t.Error("4th request should be blocked")
	}
}

func TestRateLimiter_IndependentIPs(t *testing.T) {
	rl := newIPRateLimiter(2, time.Minute)
	rl.allow("1.1.1.1")
	rl.allow("1.1.1.1")
	// 1.1.1.1 is now at limit; 2.2.2.2 should still be allowed.
	if !rl.allow("2.2.2.2") {
		t.Error("different IP should not be rate-limited")
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	handler := securityHeadersMiddleware(http.HandlerFunc(okHandler))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	headers := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Cache-Control":          "no-store",
	}
	for header, want := range headers {
		if got := w.Header().Get(header); got != want {
			t.Errorf("%s: want %q, got %q", header, want, got)
		}
	}
}
