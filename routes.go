package main

import (
	"net/http"

	"github.com/goozt/gopgbase/infra/ca/internal/api/ca"
)

func registerRoutes(router *http.ServeMux) {
	caHandler := ca.NewCaHandler()
	caRouter := caHandler.RegisterRoutes()

	router.Handle("/ca/", http.StripPrefix("/ca", caRouter))
	router.HandleFunc("GET /health", handleHealth)
}
