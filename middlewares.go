package main

import (
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/goozt/gopgbase/infra/ca/internal/utils"
)

func notFoundErrorMiddleware(next *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := newBlockingResponseWriter(w)
		next.ServeHTTP(buf, r)

		if buf.statusCode == 0 {
			buf.statusCode = http.StatusOK
		}

		if buf.statusCode == http.StatusNotFound {
			utils.WriteError(w, http.StatusNotFound, "endpoint not found")
			return
		}

		for key, values := range buf.headers {
			for _, v := range values {
				w.Header().Add(key, v)
			}
		}
		w.WriteHeader(buf.statusCode)
		_, _ = w.Write(buf.body.Bytes())
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := newResponseWriter(w)
		next.ServeHTTP(wrapped, r)
		slog.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapped.statusCode,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote_addr", r.RemoteAddr,
			"user_agent", r.UserAgent(),
		)
	})
}

func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				slog.Error("panic recovered",
					"error", err,
					"stack", string(debug.Stack()),
					"path", r.URL.Path,
				)
				http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
			}
		}()
		wrapped := newResponseWriter(w)
		next.ServeHTTP(wrapped, r)
	})
}
