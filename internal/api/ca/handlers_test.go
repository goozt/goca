package ca

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateHostname(t *testing.T) {
	cases := []struct {
		hostname string
		wantErr  bool
	}{
		{"example.com", false},
		{"api.internal", false},
		{"node1", false},
		{"", true},
		{"a/b", true},
		{"../secret", true},
		{"has\x00null", true},
		{string(make([]byte, 254)), true}, // too long
	}
	for _, tc := range cases {
		err := validateHostname(tc.hostname)
		if (err != nil) != tc.wantErr {
			t.Errorf("validateHostname(%q): wantErr=%v, got err=%v", tc.hostname, tc.wantErr, err)
		}
	}
}

func TestInCertDir(t *testing.T) {
	cases := []struct {
		base   string
		target string
		want   bool
	}{
		{"/certs", "/certs/client.foo.crt", true},
		{"/certs", "/certs/sub/node.crt", true},
		{"/certs", "/etc/passwd", false},
		{"/certs", "/certs/../etc/passwd", false},
		{"/certs", "/certs", true},
	}
	for _, tc := range cases {
		got := inCertDir(tc.base, tc.target)
		if got != tc.want {
			t.Errorf("inCertDir(%q, %q) = %v, want %v", tc.base, tc.target, got, tc.want)
		}
	}
}

func TestHandleGetCert_InvalidFile(t *testing.T) {
	cases := []struct {
		certfile    string
		allowedFile bool // true = in allowlist (may 404 on disk, but not 400)
	}{
		{"ca.crt", true},
		{"rootCA.crt", true},
		{"client.foo.crt", false},
		{"node.bar.crt", false},
		{"some.crt", false},
		// Note: "../../etc/passwd" is intentionally omitted — Go's mux
		// path-cleans it to "/etc/passwd" and issues a 301 redirect before
		// our handler is even called, which is itself a safe outcome.
	}

	for _, tc := range cases {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /{certfile}", handleGetCert)

		req := httptest.NewRequest(http.MethodGet, "/"+tc.certfile, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		// For allowed files we only check we didn't get 400; the file won't
		// exist on disk so ServeFile returns 404 — that's expected here.
		if !tc.allowedFile && w.Code != http.StatusBadRequest {
			t.Errorf("GET /%s: want 400, got %d", tc.certfile, w.Code)
		}
		if tc.allowedFile && w.Code == http.StatusBadRequest {
			t.Errorf("GET /%s: want non-400, got 400", tc.certfile)
		}
	}
}
