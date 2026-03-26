package api

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"math/big"
	"net"
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

func validateLabel(label string) error {
	for _, r := range label {
		if r == '-' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			continue
		}
		return fmt.Errorf("hostname label contains invalid character %q", r)
	}
	return nil
}

func validateDnsLabels(hostname string) error {
	labels := strings.Split(hostname, ".")
	for i, label := range labels {
		if label == "" {
			if i == len(labels)-1 && strings.HasSuffix(hostname, ".") {
				continue
			}
			return fmt.Errorf("hostname contains empty label")
		}
		if len(label) > 63 {
			return fmt.Errorf("hostname label too long")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("hostname label cannot start or end with '-'")
		}

		if err := validateLabel(label); err != nil {
			return err
		}
	}

	return nil
}

func validateHostname(hostname string) error {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return fmt.Errorf("hostname cannot be empty")
	}
	if len(hostname) > 253 {
		return fmt.Errorf("hostname too long (max 253 characters)")
	}

	// Reject obvious bad chars early
	if strings.ContainsAny(hostname, "/\\\x00") || strings.Contains(hostname, "..") {
		return fmt.Errorf("hostname contains invalid characters")
	}

	// Optional: if it's an IP literal, allow (or reject) depending policy
	if ip := net.ParseIP(hostname); ip != nil {
		return nil // or return fmt.Errorf("IP literals not allowed")
	}

	// Hostname labels: RFC 1123 / 1035 style
	if err := validateDnsLabels(hostname); err != nil {
		return err
	}

	return nil
}

// inCertDir verifies that target is inside base, resolving symlinks so that
// a symlink inside base pointing outside cannot bypass the check.
// For paths that do not exist yet (pre-creation), the parent directory is
// resolved instead and the filename is re-joined, preserving containment
// guarantees while allowing cert creation to work correctly.
func inCertDir(base, target string) bool {
	baseAbs, err := filepath.Abs(base)
	if err != nil {
		return false
	}
	baseResolved, err := filepath.EvalSymlinks(baseAbs)
	if err != nil {
		return false
	}

	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return false
	}
	targetResolved, err := filepath.EvalSymlinks(targetAbs)
	if err != nil {
		dir, extra := filepath.Dir(targetAbs), filepath.Base(targetAbs)
		for {
			maybeResolved, perr := filepath.EvalSymlinks(dir)
			if perr == nil {
				targetResolved = filepath.Join(maybeResolved, extra)
				break
			}
			if _, statErr := os.Stat(dir); statErr != nil && os.IsNotExist(statErr) {
				parent := filepath.Dir(dir)
				if parent == dir {
					targetResolved = filepath.Clean(targetAbs)
					break
				}
				extra = filepath.Join(filepath.Base(dir), extra)
				dir = parent
				continue
			}
			return false
		}
	}

	baseWithSep := baseResolved + string(os.PathSeparator)
	return targetResolved == baseResolved || strings.HasPrefix(targetResolved, baseWithSep)
}

func handleGetRootCaCert(w http.ResponseWriter, r *http.Request) {
	caCertPath := filepath.Join(utils.GetRootCertDir(), "rootCA.crt")
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		utils.WriteError(w, http.StatusNotFound, "root CA certificate not found")
		return
	}
	w.Header().Del("If-Modified-Since")
	w.Header().Del("If-None-Match")
	w.Header().Set("Content-Disposition", "attachment; filename=\"rootCA.crt\"")
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	http.ServeFile(w, r, caCertPath)
}

func handleGetInterCaCert(w http.ResponseWriter, r *http.Request) {
	caCertPath := filepath.Join(utils.GetCertDir(), "ca.crt")
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		utils.WriteError(w, http.StatusNotFound, "intermediate CA certificate not found")
		return
	}
	w.Header().Del("If-Modified-Since")
	w.Header().Del("If-None-Match")
	w.Header().Set("Content-Disposition", "attachment; filename=\"ca.crt\"")
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	http.ServeFile(w, r, caCertPath)
}

func handleGetCert(w http.ResponseWriter, r *http.Request) {
	certfile := r.PathValue("certfile")

	allowed := map[string]bool{"ca.crt": true, "rootCA.crt": true}
	if !allowed[certfile] {
		utils.WriteError(w, http.StatusBadRequest, "invalid certificate file requested")
		return
	}
	certDir := utils.GetCertDir()
	rawPath := filepath.Join(certDir, certfile)

	absCertDir, err := filepath.Abs(certDir)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "cannot determine certificate directory")
		return
	}
	absCertDir, err = filepath.EvalSymlinks(absCertDir)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "cannot resolve certificate directory")
		return
	}

	absTarget, err := filepath.Abs(rawPath)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "cannot determine requested file path")
		return
	}
	absTarget, err = filepath.EvalSymlinks(absTarget)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "cannot resolve requested file path")
		return
	}

	absCertDirWithSep := absCertDir + string(os.PathSeparator)
	if !(absTarget == absCertDir || strings.HasPrefix(absTarget, absCertDirWithSep)) {
		utils.WriteError(w, http.StatusForbidden, "requested file is outside the certificate directory")
		return
	}

	if _, err := os.Stat(rawPath); os.IsNotExist(err) {
		utils.WriteError(w, http.StatusNotFound, "certificate file not found")
		return
	}

	w.Header().Del("If-Modified-Since")
	w.Header().Del("If-None-Match")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", certfile))
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	http.ServeFile(w, r, rawPath)
}

func handleCaBundleCerts(w http.ResponseWriter, r *http.Request) {
	certDir := utils.GetCertDir()
	rootCACertPath := filepath.Join(utils.GetRootCertDir(), "rootCA.crt")
	interCACertPath := filepath.Join(certDir, "ca.crt")

	bundle, err := ca.LoadCertificateBundle(interCACertPath, rootCACertPath)
	if err != nil {
		slog.Error("failed to load certificate bundle", "err", err)
		utils.WriteError(w, http.StatusInternalServerError, "failed to load certificate bundle")
		return
	}

	w.Header().Del("If-Modified-Since")
	w.Header().Del("If-None-Match")
	w.Header().Set("Content-Disposition", "attachment; filename=\"ca-bundle.crt\"")
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bundle)
}

func handleGetCRL(w http.ResponseWriter, r *http.Request) {
	certDir := utils.GetCertDir()
	caCert := filepath.Join(certDir, "ca.crt")
	caKey := filepath.Join(certDir, "ca.key")

	interCaCert, interCaKey, err := ca.LoadCAFromFiles(caCert, caKey)
	if err != nil {
		slog.Error("failed to load CA", "err", err)
		utils.WriteError(w, http.StatusInternalServerError, "failed to load CA")
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
		slog.Error("failed to generate CRL", "err", err)
		utils.WriteError(w, http.StatusInternalServerError, "failed to generate CRL")
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

	certDir := utils.GetCertDir()
	certFile := filepath.Join(certDir, fmt.Sprintf("client.%s.crt", hostname))
	keyFile := filepath.Join(certDir, fmt.Sprintf("client.%s.key", hostname))

	if !inCertDir(certDir, certFile) || !inCertDir(certDir, keyFile) {
		utils.WriteError(w, http.StatusBadRequest, "invalid certificate path")
		return
	}

	certOpMu.Lock()
	defer certOpMu.Unlock()

	if err := os.Remove(certFile); err != nil && !os.IsNotExist(err) {
		slog.Error("failed to delete client certificate", "err", err, "hostname", hostname)
		utils.WriteError(w, http.StatusInternalServerError, "failed to delete certificate file")
		return
	}
	if err := os.Remove(keyFile); err != nil && !os.IsNotExist(err) {
		slog.Error("failed to delete client key", "err", err, "hostname", hostname)
		utils.WriteError(w, http.StatusInternalServerError, "failed to delete key file")
		return
	}

	if err := caDB.AddRevocation(ic.SerialHex, time.Now().UTC(), 0); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "failed to record revocation")
		return
	}

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

	certDir := utils.GetCertDir()
	certFile := filepath.Join(certDir, hostname, "node.crt")
	keyFile := filepath.Join(certDir, hostname, "node.key")

	if !inCertDir(certDir, certFile) || !inCertDir(certDir, keyFile) {
		utils.WriteError(w, http.StatusBadRequest, "invalid certificate path")
		return
	}

	certOpMu.Lock()
	defer certOpMu.Unlock()

	if err := os.RemoveAll(filepath.Join(certDir, hostname)); err != nil {
		slog.Error("failed to delete node certificate", "err", err, "hostname", hostname)
		utils.WriteError(w, http.StatusInternalServerError, "failed to delete node certificate")
		return
	}

	if err := caDB.AddRevocation(ic.SerialHex, time.Now().UTC(), 0); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "failed to record revocation")
		return
	}

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
		slog.Error("failed to generate key", "err", err)
		utils.WriteError(w, http.StatusInternalServerError, "failed to generate key")
		return
	}

	interCaCert, interCaKey, err := ca.LoadCAFromFiles(caCert, caKey)
	if err != nil {
		slog.Error("failed to load CA", "err", err)
		utils.WriteError(w, http.StatusInternalServerError, "failed to load CA")
		return
	}

	subject, _ := ca.NewCertSubject(hostname)
	subject.Country = "IN"
	subject.Organization = "Goozt"
	subject.OrganizationalUnit = "Client Certificates"
	template := ca.CreateClientCertTemplate(subject)
	cert, err := ca.CreateClientCertificate(template, interCaCert, interCaKey, key)
	if err != nil {
		slog.Error("failed to create client certificate", "err", err, "hostname", hostname)
		utils.WriteError(w, http.StatusInternalServerError, "failed to create client certificate")
		return
	}

	if err := ca.SaveCertAndKey(cert, key, certFile, keyFile); err != nil {
		slog.Error("failed to save cert and key", "err", err, "hostname", hostname)
		utils.WriteError(w, http.StatusInternalServerError, "failed to save certificate")
		return
	}

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		utils.WriteError(w, http.StatusInternalServerError, "certificate file was not found after creation")
		return
	}

	caDB := db.GetDB()
	if err := caDB.SaveIssuedCert(cert, hostname); err != nil {
		slog.Error("failed to save issued client cert", "err", err, "hostname", hostname)
		os.Remove(certFile)
		os.Remove(keyFile)
		utils.WriteError(w, http.StatusInternalServerError, "failed to record certificate")
		return
	}

	slog.Info("audit: client certificate created",
		"hostname", hostname, "cert_file", certFile, "remote_addr", r.RemoteAddr)

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message":   "client certificate generated successfully",
		"cert-file": certFile,
		"key-file":  keyFile,
	})
}

// serveExistingNodeCert signals that a node cert is already present with a
// proper 204 No Content response (RFC 7231 §6.3.5 forbids a body on 204).
func serveExistingNodeCert(w http.ResponseWriter, certDir, certFile, keyFile string) {
	if !inCertDir(certDir, certFile) || !inCertDir(certDir, keyFile) {
		utils.WriteError(w, http.StatusInternalServerError, "invalid certificate path in database")
		return
	}
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		utils.WriteError(w, http.StatusInternalServerError, "certificate file was not found for issued cert")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// buildAndSendNodeCertZip creates a new node cert, saves it, records it in the
// DB, and sends the cert bundle as a zip download.
func buildAndSendNodeCertZip(w http.ResponseWriter, r *http.Request, hostname string) {
	certDir := utils.GetCertDir()
	caCert := filepath.Join(certDir, "ca.crt")
	caKey := filepath.Join(certDir, "ca.key")
	certFile := filepath.Join(certDir, hostname, "node.crt")
	keyFile := filepath.Join(certDir, hostname, "node.key")

	fmt.Println(certDir, certFile, keyFile)
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
		slog.Error("failed to generate key", "err", err)
		utils.WriteError(w, http.StatusInternalServerError, "failed to generate key")
		return
	}

	interCaCert, interCaKey, err := ca.LoadCAFromFiles(caCert, caKey)
	if err != nil {
		slog.Error("failed to load CA", "err", err)
		utils.WriteError(w, http.StatusInternalServerError, "failed to load CA")
		return
	}

	subject, _ := ca.NewCertSubject(hostname)
	subject.Country = "IN"
	subject.Organization = "Goozt"
	subject.OrganizationalUnit = "Node Certificates"
	template := ca.CreateServerCertTemplate(subject)
	cert, err := ca.CreateServerCertificate(template, interCaCert, interCaKey, key)
	if err != nil {
		slog.Error("failed to create node certificate", "err", err, "hostname", hostname)
		utils.WriteError(w, http.StatusInternalServerError, "failed to create node certificate")
		return
	}

	err = os.Mkdir(filepath.Join(certDir, hostname), 0755)
	if err != nil && !os.IsExist(err) {
		slog.Error("failed to create cert directory", "err", err, "hostname", hostname)
		utils.WriteError(w, http.StatusInternalServerError, "failed to create cert directory")
		return
	}

	if err := ca.SaveCertAndKey(cert, key, certFile, keyFile); err != nil {
		slog.Error("failed to save cert and key", "err", err, "hostname", hostname)
		utils.WriteError(w, http.StatusInternalServerError, "failed to save certificate")
		return
	}

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		utils.WriteError(w, http.StatusInternalServerError, "certificate file was not found after creation")
		return
	}

	caDB := db.GetDB()
	if err := caDB.SaveIssuedCert(cert, hostname); err != nil {
		slog.Error("failed to save issued cert", "err", err, "hostname", hostname)
		os.RemoveAll(filepath.Join(certDir, hostname))
		utils.WriteError(w, http.StatusInternalServerError, "failed to record certificate")
		return
	}

	slog.Info("audit: node certificate created",
		"hostname", hostname, "cert_file", certFile, "remote_addr", r.RemoteAddr)

	zipBin, err := buildNodeZip(cert, key, caCert)
	if err != nil {
		slog.Error("failed to build certificate bundle", "err", err, "hostname", hostname)
		utils.WriteError(w, http.StatusInternalServerError, "failed to build certificate bundle")
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Del("If-Modified-Since")
	w.Header().Del("If-None-Match")
	w.Header().Set("Content-Disposition", "attachment; filename=\"ca.zip\"")
	w.Header().Set("Content-Length", strconv.Itoa(len(zipBin)))
	if _, err := w.Write(zipBin); err != nil {
		slog.Error("failed to write zip archive", "err", err, "hostname", hostname)
	}
}

// buildNodeZip assembles the four-file bundle (node cert+key + CA chain).
func buildNodeZip(cert *x509.Certificate, key crypto.Signer, caCertPath string) ([]byte, error) {
	rootCACertPath := filepath.Join(utils.GetRootCertDir(), "rootCA.crt")
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("CA certificate file not found")
	}
	if _, err := os.Stat(rootCACertPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("root CA certificate file not found")
	}
	pemCert := ca.PemEncodeCertificate(cert)
	pemKey, err := ca.PemEncodePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key")
	}
	bundle, err := ca.LoadCertificateBundle(caCertPath, rootCACertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate bundle")
	}
	data := []utils.ZipFileData{
		{Filename: "node.crt", Data: pemCert},
		{Filename: "node.key", Data: pemKey},
		{Filename: "ca.crt", Data: bundle},
	}
	zipBin, err := utils.ZipData(data, "ca.zip")
	if err != nil {
		return nil, fmt.Errorf("failed to create zip archive")
	}
	return zipBin, nil
}

func handleGetOrCreateNodeCert(w http.ResponseWriter, r *http.Request) {
	hostname := r.PathValue("hostname")
	if err := validateHostname(hostname); err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	caDB := db.GetDB()
	certDir := utils.GetCertDir()
	certFile := filepath.Join(certDir, hostname, "node.crt")
	keyFile := filepath.Join(certDir, hostname, "node.key")
	if _, ok := caDB.GetIssuedByHostname(hostname); ok && utils.FilesExist(certFile, keyFile) {
		serveExistingNodeCert(w, certDir, certFile, keyFile)
		return
	}

	buildAndSendNodeCertZip(w, r, hostname)
}
