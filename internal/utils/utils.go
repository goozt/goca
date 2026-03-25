package utils

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type caPathStore struct {
	Path  string
	Ready bool
}

var certDir = caPathStore{Path: "", Ready: false}

type APIError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

func GetHostUrl(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func HandleNotFound(w http.ResponseWriter, r *http.Request) {
	WriteError(w, http.StatusNotFound, "endpoint not found")
}

func WriteJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("failed to encode response", "error", err)
	}
}

func WriteError(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, APIError{
		Error:   http.StatusText(status),
		Message: message,
		Code:    status,
	})
}

func GetCertDir(posPathArgs ...string) string {
	// P1: Check if certDir is already set and ready
	if certDir.Ready && certDir.Path != "" {
		slog.Debug("using cached certDir", "path", certDir.Path)
		return certDir.Path
	}

	// P2: Check command-line arguments
	if len(posPathArgs) > 0 && posPathArgs[0] != "" {
		return posPathArgs[0]
	}

	// P3: Check environment variable
	if envDir := os.Getenv("CERTS_DIR"); envDir != "" {
		return envDir
	}

	// P4: Default path
	return "./.ca"
}

func VerifyCertDir(dir string) {
	absPath, err := filepath.Abs(strings.TrimSpace(dir))
	if err != nil {
		slog.Error("invalid path", "dir", dir, "error", err)
		os.Exit(1)
	}
	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Error("certs directory does not exist", "dir", absPath)
		} else {
			slog.Error("failed to access certs directory", "dir", absPath, "error", err)
		}
		os.Exit(1)
	}
	if !info.IsDir() {
		slog.Error("path is not a directory", "dir", absPath)
		os.Exit(1)
	}
	f, err := os.Open(absPath)
	if err != nil {
		slog.Error("certs directory is not readable (check permissions)", "dir", absPath, "error", err)
		os.Exit(1)
	}
	f.Close()

	certDir.Path = absPath
	certDir.Ready = true
}
