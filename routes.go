package main

import (
	"net/http"

	"github.com/goozt/gopgbase/infra/ca/internal/api"
)

func registerRoutes(router *http.ServeMux) {
	caHandler := api.NewCaHandler()
	caRouter := caHandler.RegisterRoutes()

	// Auth middleware applied to all /ca/ endpoints; /health is public.
	router.Handle("/ca/", authMiddleware(http.StripPrefix("/ca", caRouter)))
	router.HandleFunc("GET /health", handleHealth)
}
