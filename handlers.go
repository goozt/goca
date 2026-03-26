package main

import (
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/goozt/gopgbase/infra/ca/internal/ca"
	"github.com/goozt/gopgbase/infra/ca/internal/utils"
)

func handleHealth(w http.ResponseWriter, r *http.Request) {
	type healthStatus struct {
		Status string            `json:"status"`
		Time   string            `json:"time"`
		Checks map[string]string `json:"checks"`
	}

	checks := make(map[string]string)
	healthy := true

	// Check 1: cert directory is writable.
	certDir := utils.GetCertDir()
	probe := filepath.Join(certDir, ".health_probe")
	if f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600); err != nil {
		checks["cert_dir_writable"] = "fail: " + err.Error()
		healthy = false
	} else {
		f.Close()
		os.Remove(probe)
		checks["cert_dir_writable"] = "ok"
	}

	// Check 2: intermediate CA cert exists and has not expired.
	caCertPath := filepath.Join(certDir, "ca.crt")
	caKeyPath := filepath.Join(certDir, "ca.key")
	if caCert, _, err := ca.LoadCAFromFiles(caCertPath, caKeyPath); err != nil {
		checks["ca_cert"] = "fail: " + err.Error()
		healthy = false
	} else if time.Now().After(caCert.NotAfter) {
		checks["ca_cert"] = "fail: intermediate CA certificate has expired"
		healthy = false
	} else {
		checks["ca_cert"] = "ok (expires " + caCert.NotAfter.UTC().Format(time.RFC3339) + ")"
	}

	status := "ok"
	httpStatus := http.StatusOK
	if !healthy {
		status = "degraded"
		httpStatus = http.StatusServiceUnavailable
	}

	utils.WriteJSON(w, httpStatus, healthStatus{
		Status: status,
		Time:   time.Now().UTC().Format(time.RFC3339),
		Checks: checks,
	})
}
