package middleware

import (
	"bufio"
	"net"
	"net/http"
	"strconv"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// metricsResponseWriter wraps http.ResponseWriter to capture the status code
// for request_total metric recording.
type metricsResponseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (w *metricsResponseWriter) WriteHeader(code int) {
	if !w.written {
		w.statusCode = code
		w.written = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *metricsResponseWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.statusCode = http.StatusOK
		w.written = true
	}
	return w.ResponseWriter.Write(b)
}

func (w *metricsResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

func (w *metricsResponseWriter) Flush() {
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

// RequestMetrics is an outermost middleware that records request_total after
// the response is written. It wraps the ResponseWriter to capture the status
// code. Position: step 0, wrapping the entire middleware chain.
func RequestMetrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped := &metricsResponseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(wrapped, r)

		// Record request_total metric after the response is fully written
		if gwMetrics != nil {
			gwMetrics.RequestTotal.Add(r.Context(), 1,
				metric.WithAttributes(
					attribute.String("method", r.Method),
					attribute.String("path", r.URL.Path),
					attribute.String("status_code", strconv.Itoa(wrapped.statusCode)),
					attribute.String("spiffe_id", GetSPIFFEID(r.Context())),
				),
			)
		}
	})
}
