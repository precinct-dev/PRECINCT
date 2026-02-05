package middleware

import (
	"net/http"
)

// RequestSizeLimit enforces maximum request body size
func RequestSizeLimit(next http.Handler, maxBytes int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply size limit using http.MaxBytesReader
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		next.ServeHTTP(w, r)
	})
}
