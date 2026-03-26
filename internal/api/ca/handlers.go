package ca

import (
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/goozt/gopgbase/infra/ca/internal/ca"
	"github.com/goozt/gopgbase/infra/ca/internal/db"
	"github.com/goozt/gopgbase/infra/ca/internal/utils"
)

// certOpMu serialises concurrent certificate create/delete operations to
// prevent TOCTOU races on the cert/key files.
var certOpMu sync.Mutex

// validateHostname rejects hostnames that could be used for path traversal.
// Dots are allowed since hostnames like "api.example.com" are valid.
func validateHostname(hostname string) error {
	if strings.TrimSpace(hostname) == "" {
		return fmt.Errorf("hostname cannot be empty")
	}
	if len(hostname) > 253 {
		return fmt.Errorf("hostname too long (max 253 characters)")
	}
	if strings.ContainsAny(hostname, "/\\\x00") || strings.Contains(hostname, "..") {
		return fmt.Errorf("hostname contains invalid characters")
	}
	return nil
}

// inCertDir verifies that target is inside base after path cleaning, to
// prevent directory traversal even when the individual components look safe.
func inCertDir(base, target string) bool {
	cleanBase := filepath.Clean(base) + string(os.PathSeparator)
	cleanTarget := filepath.Clean(target)
	return strings.HasPrefix(cleanTarget, cleanBase) || cleanTarget == filepath.Clean(base)
}

func handleGetRootCaCert(w http.ResponseWriter, r *http.Request) {
	caCertPath := filepath.Join(utils.GetRootCertDir(), "rootCA.crt")
	w.Header().Del("If-Modified-Since")
	w.Header().Del("If-None-Match")
	w.Header().Set("Content-Disposition", "attachment; filename=\"rootCA.crt\"")
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	http.ServeFile(w, r, caCertPath)
}

func handleGetInterCaCert(w http.ResponseWriter, r *http.Request) {
	caCertPath := filepath.Join(utils.GetCertDir(), "ca.crt")
	w.Header().Del("If-Modified-Since")
	w.Header().Del("If-None-Match")
	w.Header().Set("Content-Disposition", "attachment; filename=\"ca.crt\"")
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	http.ServeFile(w, r, caCertPath)
}

func handleGetCert(w http.ResponseWriter, r *http.Request) {
	certfile := r.PathValue("certfile")
	// Strict allowlist: only the two public CA certs are served here.
	// Client and node certs are intentionally not exposed via this generic endpoint.
	allowed := map[string]bool{"ca.crt": true, "rootCA.crt": true}
	if !allowed[certfile] {
		utils.WriteError(w, http.StatusBadRequest, "invalid certificate file requested")
		return
	}
	certPath := filepath.Join(utils.GetCertDir(), certfile)
	w.Header().Del("If-Modified-Since")
	w.Header().Del("If-None-Match")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", certfile))
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	http.ServeFile(w, r, certPath)
}

func handleGetCRL(w http.ResponseWriter, r *http.Request) {
	certDir := utils.GetCertDir()
	caCert := filepath.Join(certDir, "ca.crt")
	caKey := filepath.Join(certDir, "ca.key")

	interCaCert, interCaKey, err := ca.LoadCAFromFiles(caCert, caKey)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "failed to load CA: "+err.Error())
		return
	}

	caDB := db.GetDB()
	revocations := caDB.ListRevocations()
	entries := make([]pkix.RevokedCertificate, 0, len(revocations))
	for _, rev := range revocations {
		serial, ok := new(big.Int).SetString(rev.SerialHex, 16)
		if !ok {
			continue
		}
		entries = append(entries, pkix.RevokedCertificate{
			SerialNumber:   serial,
			RevocationTime: rev.Time,
		})
	}

	crlNum := caDB.NextCRLNumber()
	crlBytes, err := ca.CreateCRLFromRevocations(entries, crlNum, interCaCert, interCaKey)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "failed to generate CRL: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Content-Disposition", "attachment; filename=\"ca.crl\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(crlBytes)
}

func handleListCaCerts(w http.ResponseWriter, r *http.Request) {
	certDir := utils.GetCertDir()
	files, err := os.ReadDir(certDir)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "failed to read cert directory")
		return
	}
	baseURL := utils.GetHostUrl(r) + "/ca/"
	certFiles := []string{}
	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".crt" {
			certFiles = append(certFiles, baseURL+file.Name())
		}
	}
	utils.WriteJSON(w, http.StatusOK, map[string]any{"certs": certFiles})
}

func handleRevokeClientCert(w http.ResponseWriter, r *http.Request) {
	hostname := r.PathValue("hostname")
	if err := validateHostname(hostname); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	caDB := db.GetDB()
	ic, ok := caDB.GetIssuedByHostname(hostname)
	if !ok {
		utils.WriteError(w, http.StatusNotFound, "no such client certificate")
		return
	}

	if err := caDB.AddRevocation(ic.SerialHex, time.Now().UTC(), 0); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "failed to record revocation")
		return
	}

	certDir := utils.GetCertDir()
	certFile := filepath.Join(certDir, fmt.Sprintf("client.%s.crt", hostname))
	keyFile := filepath.Join(certDir, fmt.Sprintf("client.%s.key", hostname))

	if !inCertDir(certDir, certFile) || !inCertDir(certDir, keyFile) {
		utils.WriteError(w, http.StatusBadRequest, "invalid certificate path")
		return
	}

	certOpMu.Lock()
	defer certOpMu.Unlock()

	os.Remove(certFile)
	os.Remove(keyFile)

	slog.Info("audit: client certificate deleted",
		"hostname", hostname, "cert_file", certFile, "remote_addr", r.RemoteAddr)

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "client certificate revoked and deleted successfully",
	})
}

func handleRevokeNodeCert(w http.ResponseWriter, r *http.Request) {
	hostname := r.PathValue("hostname")
	if err := validateHostname(hostname); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	caDB := db.GetDB()
	ic, ok := caDB.GetIssuedByHostname(hostname)
	if !ok {
		utils.WriteError(w, http.StatusNotFound, "no such node certificate")
		return
	}

	if err := caDB.AddRevocation(ic.SerialHex, time.Now().UTC(), 0); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "failed to record revocation")
		return
	}

	certDir := utils.GetCertDir()
	certFile := filepath.Join(certDir, hostname, "node.crt")
	keyFile := filepath.Join(certDir, hostname, "node.key")

	if !inCertDir(certDir, certFile) || !inCertDir(certDir, keyFile) {
		utils.WriteError(w, http.StatusBadRequest, "invalid certificate path")
		return
	}

	certOpMu.Lock()
	defer certOpMu.Unlock()

	os.Remove(certFile)
	os.Remove(keyFile)

	slog.Info("audit: node certificate deleted",
		"hostname", hostname, "cert_file", certFile, "remote_addr", r.RemoteAddr)

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "node certificate revoked and deleted successfully",
	})
}

func handleGetOrCreateClientCert(w http.ResponseWriter, r *http.Request) {
	hostname := r.PathValue("hostname")
	if err := validateHostname(hostname); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	certDir := utils.GetCertDir()
	caCert := filepath.Join(certDir, "ca.crt")
	caKey := filepath.Join(certDir, "ca.key")
	certFile := filepath.Join(certDir, fmt.Sprintf("client.%s.crt", hostname))
	keyFile := filepath.Join(certDir, fmt.Sprintf("client.%s.key", hostname))

	if !inCertDir(certDir, certFile) || !inCertDir(certDir, keyFile) {
		utils.WriteError(w, http.StatusBadRequest, "invalid certificate path")
		return
	}

	certOpMu.Lock()
	defer certOpMu.Unlock()

	_, errCert := os.Stat(certFile)
	_, errKey := os.Stat(keyFile)
	if errCert == nil && errKey == nil {
		utils.WriteError(w, http.StatusConflict, "client certificate and key already exist")
		return
	}

	os.Remove(certFile)
	os.Remove(keyFile)

	key, err := ca.GenerateCAKey()
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "failed to generate key: "+err.Error())
		return
	}

	interCaCert, interCaKey, err := ca.LoadCAFromFiles(caCert, caKey)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "failed to load CA: "+err.Error())
		return
	}

	subject, _ := ca.NewCertSubject(hostname)
	subject.Country = "IN"
	subject.Organization = "Goozt"
	subject.OrganizationalUnit = "Client Certificates"
	template := ca.CreateClientCertTemplate(subject)
	cert, err := ca.CreateClientCertificate(template, interCaCert, interCaKey, key)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "failed to create client certificate: "+err.Error())
		return
	}

	if err := ca.SaveCertAndKey(cert, key, certFile, keyFile); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "failed to save cert and key: "+err.Error())
		return
	}

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		utils.WriteError(w, http.StatusInternalServerError, "certificate file was not found after creation")
		return
	}

	caDB := db.GetDB()
	if err := caDB.SaveIssuedCert(cert, hostname); err != nil {
		slog.Error("failed to save issued client cert", "err", err, "hostname", hostname)
	}

	slog.Info("audit: client certificate created",
		"hostname", hostname, "cert_file", certFile, "remote_addr", r.RemoteAddr)

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message":   "client certificate generated successfully",
		"cert-file": certFile,
		"key-file":  keyFile,
	})
}

func handleGetOrCreateNodeCert(w http.ResponseWriter, r *http.Request) {
	caDB := db.GetDB()

	hostname := r.PathValue("hostname")
	if err := validateHostname(hostname); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	_, ok := caDB.GetIssuedByHostname(hostname)
	if ok {
		certDir := utils.GetCertDir()
		certFile := filepath.Join(certDir, hostname, "node.crt")
		keyFile := filepath.Join(certDir, hostname, "node.key")
		if !inCertDir(certDir, certFile) || !inCertDir(certDir, keyFile) {
			utils.WriteError(w, http.StatusInternalServerError, "invalid certificate path in database")
			return
		}
		if _, err := os.Stat(certFile); os.IsNotExist(err) {
			utils.WriteError(w, http.StatusInternalServerError, "certificate file was not found for issued cert")
			return
		}
		utils.WriteJSON(w, http.StatusOK, map[string]string{
			"message":   "node certificate already exists",
			"cert-file": certFile,
			"key-file":  keyFile,
		})
		return
	}
	certDir := utils.GetCertDir()
	caCert := filepath.Join(certDir, "ca.crt")
	caKey := filepath.Join(certDir, "ca.key")
	certFile := filepath.Join(certDir, hostname, "node.crt")
	keyFile := filepath.Join(certDir, hostname, "node.key")

	if !inCertDir(certDir, certFile) || !inCertDir(certDir, keyFile) {
		utils.WriteError(w, http.StatusBadRequest, "invalid certificate path")
		return
	}

	certOpMu.Lock()
	defer certOpMu.Unlock()

	_, errCert := os.Stat(certFile)
	_, errKey := os.Stat(keyFile)
	if errCert == nil && errKey == nil {
		utils.WriteError(w, http.StatusConflict, "node certificate and key already exist")
		return
	}

	os.Remove(certFile)
	os.Remove(keyFile)

	key, err := ca.GenerateCAKey()
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "failed to generate key: "+err.Error())
		return
	}

	interCaCert, interCaKey, err := ca.LoadCAFromFiles(caCert, caKey)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "failed to load CA: "+err.Error())
		return
	}

	subject, _ := ca.NewCertSubject(hostname)
	subject.Country = "IN"
	subject.Organization = "Goozt"
	subject.OrganizationalUnit = "Node Certificates"
	template := ca.CreateServerCertTemplate(subject)
	cert, err := ca.CreateServerCertificate(template, interCaCert, interCaKey, key)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "failed to create node certificate: "+err.Error())
		return
	}

	if err := ca.SaveCertAndKey(cert, key, certFile, keyFile); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "failed to save cert and key: "+err.Error())
		return
	}

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		utils.WriteError(w, http.StatusInternalServerError, "certificate file was not found after creation")
		return
	}

	if err := caDB.SaveIssuedCert(cert, hostname); err != nil {
		slog.Error("failed to save issued cert", "err", err, "hostname", hostname)
	}

	slog.Info("audit: node certificate created",
		"hostname", hostname, "cert_file", certFile, "remote_addr", r.RemoteAddr)

	pemCert := ca.PemEncodeCertificate(cert)
	pemKey, err := ca.PemEncodePrivateKey(key)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "failed to encode private key: "+err.Error())
		return
	}

	interCaPEM, err := os.ReadFile(caCert)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "failed to read intermediate CA cert: "+err.Error())
		return
	}
	rootCAPEM, err := os.ReadFile(filepath.Join(utils.GetRootCertDir(), "rootCA.crt"))
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "failed to read root CA cert: "+err.Error())
		return
	}

	data := []utils.ZipFileData{
		{Filename: "node.crt", Data: pemCert},
		{Filename: "node.key", Data: pemKey},
		{Filename: "ca.crt", Data: interCaPEM},
		{Filename: "rootCA.crt", Data: rootCAPEM},
	}
	zipBin, err := utils.ZipData(data, "ca.zip")
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "failed to create zip archive: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Del("If-Modified-Since")
	w.Header().Del("If-None-Match")
	w.Header().Set("Content-Disposition", "attachment; filename=\"ca.zip\"")
	w.Header().Set("Content-Length", strconv.Itoa(len(zipBin)))
	if _, err := w.Write(zipBin); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "failed to write zip archive: "+err.Error())
		return
	}
}
