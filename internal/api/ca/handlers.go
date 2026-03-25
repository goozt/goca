package ca

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/goozt/gopgbase/infra/ca/internal/ca"
	"github.com/goozt/gopgbase/infra/ca/internal/utils"
)

func handleGetCaCert(w http.ResponseWriter, r *http.Request) {
	caCertPath := utils.GetCertDir() + "/ca.crt"
	w.Header().Del("If-Modified-Since")
	w.Header().Del("If-None-Match")
	w.Header().Set("Content-Disposition", "attachment; filename=\"ca.crt\"")
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	http.ServeFile(w, r, caCertPath)
}

func handleGetInterCaCert(w http.ResponseWriter, r *http.Request) {
	caCertPath := utils.GetCertDir() + "/interca.crt"
	w.Header().Del("If-Modified-Since")
	w.Header().Del("If-None-Match")
	w.Header().Set("Content-Disposition", "attachment; filename=\"interca.crt\"")
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	http.ServeFile(w, r, caCertPath)
}

func handleGetCert(w http.ResponseWriter, r *http.Request) {
	certfile := r.PathValue("certfile")
	if !strings.HasSuffix(certfile, ".crt") {
		utils.WriteError(w, http.StatusBadRequest, "Invalid certificate file requested")
		return
	}
	if !slices.Contains([]string{"ca.crt", "interca.crt"}, certfile) || strings.Contains(certfile, "client.") || strings.Contains(certfile, "node.") || strings.Contains(certfile, "node.") {
		utils.WriteError(w, http.StatusBadRequest, "Invalid certificate file requested")
		return
	}
	clientCertPath := utils.GetCertDir() + fmt.Sprintf("/%s", certfile)
	w.Header().Del("If-Modified-Since")
	w.Header().Del("If-None-Match")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", certfile))
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	http.ServeFile(w, r, clientCertPath)
}

func handleListCaCerts(w http.ResponseWriter, r *http.Request) {
	certDir := utils.GetCertDir()
	files, err := os.ReadDir(certDir)
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, "Failed to read cert directory")
		return
	}
	baseURL := utils.GetHostUrl(r) + "/ca/"
	certFiles := []string{}
	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".crt" {
			certFiles = append(certFiles, baseURL+file.Name())
		}
	}

	utils.WriteJSON(w, http.StatusOK, map[string]any{
		"certs": certFiles,
	})
}

func handleDeleteClientCert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	certDir := utils.GetCertDir()
	certFile := filepath.Join(certDir, fmt.Sprintf("client.%s.crt", id))
	keyFile := filepath.Join(certDir, fmt.Sprintf("client.%s.key", id))

	os.Remove(certFile)
	os.Remove(keyFile)

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message":   "Client certificate deleted successfully",
		"cert-file": certFile,
		"key-file":  keyFile,
	})
}

func handleDeleteNodeCert(w http.ResponseWriter, r *http.Request) {
	hostname := r.PathValue("hostname")
	certDir := utils.GetCertDir()
	certFile := filepath.Join(certDir, hostname, "node.crt")
	keyFile := filepath.Join(certDir, hostname, "node.key")

	os.Remove(certFile)
	os.Remove(keyFile)

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message":   "Node certificate deleted successfully",
		"cert-file": certFile,
		"key-file":  keyFile,
	})
}

func handleCreateClientCert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	certDir := utils.GetCertDir()
	caCert := filepath.Join(certDir, "interca.crt")
	caKey := filepath.Join(certDir, "interca.key")
	certFile := filepath.Join(certDir, fmt.Sprintf("client.%s.crt", id))
	keyFile := filepath.Join(certDir, fmt.Sprintf("client.%s.key", id))
	_, errCert := os.Stat(certFile)
	_, errKey := os.Stat(keyFile)

	fmt.Println(certDir)

	if errCert == nil && errKey == nil {
		utils.WriteError(w, http.StatusConflict, "Client certificate and key already exist")
		return
	}

	os.Remove(certFile)
	os.Remove(keyFile)

	key, err := ca.GenerateCAKey()
	if err != nil {
		utils.WriteJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to generate key: " + err.Error(),
		})
		return
	}

	interCaCert, interCaKey, err := ca.LoadCAFromFiles(caCert, caKey)
	if err != nil {
		utils.WriteJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to load CA: " + err.Error(),
		})
		return
	}

	subject, _ := ca.NewCertSubject(fmt.Sprintf("client.%s", id))
	subject.Country = "IN"
	subject.Organization = "Goozt"
	subject.OrganizationalUnit = "Client Certificates"
	template := ca.CreateClientCertTemplate(subject)
	cert, err := ca.CreateClientCertificate(template, interCaCert, interCaKey, key)
	if err != nil {
		utils.WriteJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to create client certificate: " + err.Error(),
		})
		return
	}

	if err := ca.SaveCertAndKey(cert, key, certFile, keyFile); err != nil {
		utils.WriteJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to save cert and key: " + err.Error(),
		})
		return
	}

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		utils.WriteJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Command succeeded but certificate file was not found",
		})
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message":   "Client certificate generated successfully",
		"cert-file": certFile,
		"key-file":  keyFile,
	})
}

func handleCreateNodeCert(w http.ResponseWriter, r *http.Request) {
	hostname := r.PathValue("hostname")
	certDir := utils.GetCertDir()
	caCert := filepath.Join(certDir, "interca.crt")
	caKey := filepath.Join(certDir, "interca.key")
	certFile := filepath.Join(certDir, hostname, "node.crt")
	keyFile := filepath.Join(certDir, hostname, "node.key")
	_, errCert := os.Stat(certFile)
	_, errKey := os.Stat(keyFile)

	fmt.Println(certDir)

	if errCert == nil && errKey == nil {
		utils.WriteError(w, http.StatusConflict, "Node certificate and key already exist")
		return
	}

	os.Remove(certFile)
	os.Remove(keyFile)

	key, err := ca.GenerateCAKey()
	if err != nil {
		utils.WriteJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to generate key: " + err.Error(),
		})
		return
	}

	interCaCert, interCaKey, err := ca.LoadCAFromFiles(caCert, caKey)
	if err != nil {
		utils.WriteJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to load CA: " + err.Error(),
		})
		return
	}

	subject, _ := ca.NewCertSubject(hostname)
	subject.Country = "IN"
	subject.Organization = "Goozt"
	subject.OrganizationalUnit = "Node Certificates"
	template := ca.CreateServerCertTemplate(subject)
	cert, err := ca.CreateServerCertificate(template, interCaCert, interCaKey, key)
	if err != nil {
		utils.WriteJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to create node certificate: " + err.Error(),
		})
		return
	}

	os.MkdirAll(filepath.Join(certDir, hostname), 0744)
	if err := ca.SaveCertAndKey(cert, key, certFile, keyFile); err != nil {
		utils.WriteJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to save cert and key: " + err.Error(),
		})
		return
	}

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		utils.WriteJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Command succeeded but certificate file was not found",
		})
		return
	}

	utils.WriteJSON(w, http.StatusOK, map[string]string{
		"message":   "Node certificate generated successfully",
		"cert-file": certFile,
		"key-file":  keyFile,
	})
}
