package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
		// Path traversal variants
		{"..evil", true},         // contains ..
		{"evil/../secret", true}, // contains both / and ..
		{"-leading", true},       // label starts with -
		{"trailing-", true},      // label ends with -
		{"under_score", true},    // underscore not allowed in DNS label
		{"valid-host", false},
		{"a", false},
	}
	for _, tc := range cases {
		err := validateHostname(tc.hostname)
		if (err != nil) != tc.wantErr {
			t.Errorf("validateHostname(%q): wantErr=%v, got err=%v", tc.hostname, tc.wantErr, err)
		}
	}
}

func TestInCertDir(t *testing.T) {
	base := t.TempDir()
	sub := filepath.Join(base, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	existingFile := filepath.Join(base, "client.foo.crt")
	if err := os.WriteFile(existingFile, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	existingSubFile := filepath.Join(sub, "node.crt")
	if err := os.WriteFile(existingSubFile, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		target string
		want   bool
	}{
		{"existing file in base", existingFile, true},
		{"existing file in subdir", existingSubFile, true},
		{"file outside base", "/etc/passwd", false},
		{"traversal to outside", filepath.Join(base, "..", "passwd"), false},
		{"base itself", base, true},
		{"nonexistent file inside base", filepath.Join(base, "future.crt"), true},
	}
	for _, tc := range cases {
		got := inCertDir(base, tc.target)
		if got != tc.want {
			t.Errorf("%s: inCertDir(%q, %q) = %v, want %v", tc.name, base, tc.target, got, tc.want)
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

// TestInCertDir_SymlinkAttack verifies that a symlink inside the cert dir
// pointing to a file outside it is rejected by inCertDir.
func TestInCertDir_SymlinkAttack(t *testing.T) {
	base := t.TempDir()
	external := t.TempDir()

	// Create a real file in the external directory.
	extFile := filepath.Join(external, "secret.crt")
	if err := os.WriteFile(extFile, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Place a symlink inside base that resolves outside base.
	symlinkInBase := filepath.Join(base, "evil.crt")
	if err := os.Symlink(extFile, symlinkInBase); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	if inCertDir(base, symlinkInBase) {
		t.Error("inCertDir allowed a symlink pointing outside the base directory")
	}
}

// TestServeExistingNodeCert_Returns204 verifies that the handler writes an
// HTTP 204 with no body (RFC 7231 §6.3.5).
func TestServeExistingNodeCert_Returns204(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "node.crt")
	keyFile := filepath.Join(dir, "node.key")
	if err := os.WriteFile(certFile, []byte("cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	serveExistingNodeCert(w, dir, certFile, keyFile)

	if w.Code != http.StatusNoContent {
		t.Errorf("want 204, got %d", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Errorf("want empty body for 204, got %q", w.Body.String())
	}
}

// TestHandleGetCert_PathTraversal verifies that path traversal attempts via
// the certfile parameter are blocked by the allowlist before any FS access.
// Note: Go's ServeMux path-cleans "../../etc/passwd" → "/etc/passwd" and
// issues a 301 redirect, so the handler is never reached for such inputs.
// The allowlist is the second line of defence for any value that does reach it.
func TestHandleGetCert_PathTraversal(t *testing.T) {
	dangerous := []string{
		"../etc/passwd",
		"..%2Fetc%2Fpasswd",
		"ca.crt/../../../etc/passwd",
		"secret.key",
	}
	for _, certfile := range dangerous {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /{certfile}", handleGetCert)
		req := httptest.NewRequest(http.MethodGet, "/"+certfile, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		// Any response that is not 200 is acceptable; specifically the mux
		// may 301-redirect or the handler may 400. Neither is a data leak.
		if w.Code == http.StatusOK {
			t.Errorf("GET /%s: must not return 200 for traversal input", certfile)
		}
	}
}
