package main

import (
	"log/slog"
	"os"

	"github.com/goozt/gopgbase/infra/ca/internal/ca"
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

	err = ca.SaveCertAndKey(cert, key, certDir+"/ca.crt", certDir+"/ca.key")
	if err != nil {
		slog.Error("failed to generate CA certificate", "error", err)
		os.Remove(certDir + "/ca.crt")
		os.Remove(certDir + "/ca.key")
		return
	}
	slog.Info("CA certificate and key generated successfully", "certPath", certDir+"/ca.crt", "keyPath", certDir+"/ca.key")
}

func GenerateInterCA(certDir string, caCertPath string, caKeyPath string) {
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
	caCert, caKey, err := ca.LoadCAFromFiles(caCertPath, caKeyPath)
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
	err = ca.SaveCertAndKey(cert, key, certDir+"/interca.crt", certDir+"/interca.key")
	if err != nil {
		slog.Error("failed to generate Intermediate CA certificate", "error", err)
		os.Remove(certDir + "/interca.crt")
		os.Remove(certDir + "/interca.key")
		return
	}
	slog.Info("Intermediate CA certificate and key generated successfully", "certPath", certDir+"/interca.crt", "keyPath", certDir+"/interca.key")
}
