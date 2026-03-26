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
	r.HandleFunc("GET /list", handleListCaCerts)
	r.HandleFunc("GET /rootCa.crt", handleGetRootCaCert)
	r.HandleFunc("GET /ca.crt", handleGetInterCaCert)
	r.HandleFunc("GET /{certfile}", handleGetCert)

	r.HandleFunc("POST /client/{id}", handleCreateClientCert)
	r.HandleFunc("DELETE /client/{id}", handleDeleteClientCert)

	r.HandleFunc("POST /node/{hostname}", handleCreateNodeCert)
	r.HandleFunc("DELETE /node/{hostname}", handleDeleteNodeCert)
	return r
}
