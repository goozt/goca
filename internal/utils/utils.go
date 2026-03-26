package utils

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type ZipFileData struct {
	Filename string `json:"filename"`
	Data     []byte `json:"data"`
}

type caPathStore struct {
	mu       sync.RWMutex
	Path     string
	RootPath string
	Ready    bool
}

var certDir caPathStore

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
	certDir.mu.RLock()
	if certDir.Ready && certDir.Path != "" {
		path := certDir.Path
		certDir.mu.RUnlock()
		slog.Debug("using cached certDir", "path", path)
		return path
	}
	certDir.mu.RUnlock()

	if len(posPathArgs) > 0 && posPathArgs[0] != "" {
		return posPathArgs[0]
	}

	if envDir := os.Getenv("CERTS_DIR"); envDir != "" {
		return envDir
	}

	return "./.ca"
}

func GetRootCertDir() string {
	certDir.mu.RLock()
	if certDir.Ready && certDir.RootPath != "" {
		path := certDir.RootPath
		certDir.mu.RUnlock()
		return path
	}
	certDir.mu.RUnlock()

	absPath, _ := filepath.Abs(".rootCA")
	return absPath
}

func VerifyCertDir(rootDir, dir string) {
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

	absRootDir, err := filepath.Abs(rootDir)
	if err != nil {
		slog.Error("invalid root directory path", "dir", rootDir, "error", err)
		os.Exit(1)
	}
	info, err = os.Stat(absRootDir)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Error("certs directory does not exist", "dir", absRootDir)
		} else {
			slog.Error("failed to access certs directory", "dir", absRootDir, "error", err)
		}
		os.Exit(1)
	}
	if !info.IsDir() {
		slog.Error("path is not a directory", "dir", absRootDir)
		os.Exit(1)
	}
	f, err = os.Open(absRootDir)
	if err != nil {
		slog.Error("certs directory is not readable (check permissions)", "dir", absRootDir, "error", err)
		os.Exit(1)
	}
	f.Close()

	certDir.mu.Lock()
	certDir.Path = absPath
	certDir.RootPath = absRootDir
	certDir.Ready = true
	certDir.mu.Unlock()
}

func ZipData(fileData []ZipFileData, filename string) ([]byte, error) {
	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)

	for _, file := range fileData {
		writer, err := zipWriter.Create(file.Filename)
		if err != nil {
			return nil, err
		}
		_, err = writer.Write(file.Data)
		if err != nil {
			return nil, err
		}
	}

	if err := zipWriter.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func DirExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

func FileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func FilesExist(paths ...string) bool {
	for _, path := range paths {
		if !FileExists(path) {
			return false
		}
	}
	return true
}
