package main

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/goozt/gopgbase/infra/ca/internal/ca"
	"github.com/goozt/gopgbase/infra/ca/internal/utils"
)

func GenerateCA(certDir string) {
	subject, err := ca.NewCertSubject("Root CA")
	if err != nil {
		slog.Error("failed to create CA subject", "error", err)
		return
	}
	key, err := ca.GenerateCAKey()
	if err != nil {
		slog.Error("failed to generate CA private key", "error", err)
		return
	}
	template := ca.CreateCACertTemplate(subject)
	cert, err := ca.CreateCACertificate(template, key)
	if err != nil {
		slog.Error("failed to create CA certificate", "error", err)
		return
	}

	err = os.MkdirAll(certDir, 0755)
	if err != nil {
		slog.Error("failed to create certificate directory", "path", certDir, "error", err)
		return
	}

	err = ca.SaveCertAndKey(cert, key, certDir+"/rootCA.crt", certDir+"/rootCA.key")
	if err != nil {
		slog.Error("failed to generate CA certificate", "error", err)
		os.Remove(certDir + "/rootCA.crt")
		os.Remove(certDir + "/rootCA.key")
		return
	}
	slog.Info("CA certificate and key generated successfully", "certPath", certDir+"/rootCA.crt", "keyPath", certDir+"/rootCA.key")
}

func GenerateInterCA(certDir string) {
	subject, err := ca.NewCertSubject("Intermediate CA")
	if err != nil {
		slog.Error("failed to create Intermediate CA subject", "error", err)
		return
	}
	key, err := ca.GenerateECDSAKey()
	if err != nil {
		slog.Error("failed to generate Intermediate CA private key", "error", err)
		return
	}
	rootCaDir := utils.GetRootCertDir()
	rootCaCertPath := filepath.Join(rootCaDir, "rootCA.crt")
	rootCaKeyPath := filepath.Join(rootCaDir, "rootCA.key")
	caCert, caKey, err := ca.LoadCAFromFiles(rootCaCertPath, rootCaKeyPath)
	if err != nil {
		slog.Error("failed to load Root CA certificate and key", "error", err)
		return
	}
	template := ca.CreateInterCACertTemplate(subject)
	cert, err := ca.CreateInterCACertificate(template, caCert, caKey, key)
	if err != nil {
		slog.Error("failed to create Intermediate CA certificate", "error", err)
		return
	}

	err = os.MkdirAll(certDir, 0755)
	if err != nil {
		slog.Error("failed to create certificate directory", "path", certDir, "error", err)
		return
	}
	interCaCertPath := filepath.Join(certDir, "ca.crt")
	interCaKeyPath := filepath.Join(certDir, "ca.key")
	err = ca.SaveCertAndKey(cert, key, interCaCertPath, interCaKeyPath)
	if err != nil {
		slog.Error("failed to generate Intermediate CA certificate", "error", err)
		os.Remove(interCaCertPath)
		os.Remove(interCaKeyPath)
		return
	}
	slog.Info("Intermediate CA certificate and key generated successfully", "certPath", interCaCertPath, "keyPath", interCaKeyPath)
}

func GenerateClientRootCert(certDir string, caCertPath string, caKeyPath string) {
	subject, err := ca.NewCertSubject("Root Client")
	if err != nil {
		slog.Error("failed to create client certificate subject", "error", err)
		return
	}
	key, err := ca.GenerateECDSAKey()
	if err != nil {
		slog.Error("failed to generate client private key", "error", err)
		return
	}
	caCert, caKey, err := ca.LoadCAFromFiles(caCertPath, caKeyPath)
	if err != nil {
		slog.Error("failed to load Root CA certificate and key", "error", err)
		return
	}
	template := ca.CreateClientCertTemplate(subject)
	cert, err := ca.CreateClientCertificate(template, caCert, caKey, key)
	if err != nil {
		slog.Error("failed to create client certificate", "error", err)
		return
	}

	err = os.MkdirAll(certDir, 0755)
	if err != nil {
		slog.Error("failed to create certificate directory", "path", certDir, "error", err)
		return
	}
	err = ca.SaveCertAndKey(cert, key, certDir+"/client.root.crt", certDir+"/client.root.key")
	if err != nil {
		slog.Error("failed to generate client certificate", "error", err)
		os.Remove(certDir + "/client.root.crt")
		os.Remove(certDir + "/client.root.key")
		return
	}
	slog.Info("Client certificate and key generated successfully", "certPath", certDir+"/client.root.crt", "keyPath", certDir+"/client.root.key")
}
