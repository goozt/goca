package ca

import (
	"net/http"
)

type CaHandler struct{}

func NewCaHandler() *CaHandler {
	return &CaHandler{}
}

func (h *CaHandler) RegisterRoutes() *http.ServeMux {
	r := http.NewServeMux()
	r.HandleFunc("GET /rootCa.crt", handleGetRootCaCert)
	r.HandleFunc("GET /ca.crt", handleGetInterCaCert)
	r.HandleFunc("GET /{certfile}", handleGetCert)

	r.HandleFunc("POST /client/{hostname}", handleGetOrCreateClientCert)
	r.HandleFunc("DELETE /client/{hostname}", handleRevokeClientCert)

	r.HandleFunc("POST /node/{hostname}", handleGetOrCreateNodeCert)
	r.HandleFunc("DELETE /node/{hostname}", handleRevokeNodeCert)

	r.HandleFunc("GET /ca.crl", handleGetCRL)
	r.HandleFunc("GET /certs/", handleListCaCerts)
	return r
}
