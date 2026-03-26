package main

import (
	"bytes"
	"net/http"
)

// Blocking Response Writer
type blockingResponseWriter struct {
	ResponseWriter http.ResponseWriter
	headers        http.Header
	statusCode     int
	body           bytes.Buffer
}

func newBlockingResponseWriter(w http.ResponseWriter) *blockingResponseWriter {
	return &blockingResponseWriter{
		ResponseWriter: w,
		headers:        make(http.Header),
	}
}

func (b *blockingResponseWriter) Header() http.Header {
	return b.headers
}

func (b *blockingResponseWriter) WriteHeader(statusCode int) {
	if b.statusCode != 0 {
		return
	}
	b.statusCode = statusCode
}

func (b *blockingResponseWriter) Write(data []byte) (int, error) {
	if b.statusCode == 0 {
		b.statusCode = http.StatusOK
	}
	return b.body.Write(data)
}

// Forwarding Response Writer
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	bytes      int
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if rw.statusCode == 0 {
		rw.statusCode = http.StatusOK
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.bytes += n
	return n, err
}
