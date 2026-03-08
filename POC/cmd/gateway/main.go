package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway"
	gwmetrics "github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/metrics"
	"github.com/RamXX/agentic_reference_architecture/POC/ports/email"
	"github.com/RamXX/agentic_reference_architecture/POC/ports/openclaw"
)

func main() {
	// Health check subcommand for Docker HEALTHCHECK in distroless images.
	// RFA-8z8.1: In prod mode the server uses HTTPS, so the health check
	// must use the correct scheme. We use SPIFFE_MODE to determine this.
	if len(os.Args) > 1 && os.Args[1] == "health" {
		spiffeMode := os.Getenv("SPIFFE_MODE")
		if spiffeMode == "" {
			spiffeMode = "prod"
		}
		var port string
		if strings.EqualFold(spiffeMode, "prod") {
			port = os.Getenv("SPIFFE_LISTEN_PORT")
			if port == "" {
				port = "9443"
			}
		} else {
			port = os.Getenv("PORT")
			if port == "" {
				port = "9090"
			}
		}

		if strings.EqualFold(spiffeMode, "prod") {
			// In prod mode, the listener enforces mTLS client auth. Health checks
			// from the same container may not have a client cert, so use a TCP
			// readiness probe against the listen port instead of HTTP.
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%s", port), 2*time.Second)
			if err != nil {
				os.Exit(1)
			}
			_ = conn.Close()
			os.Exit(0)
		}

		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get(fmt.Sprintf("http://localhost:%s/health", port))
		if err != nil {
			os.Exit(1)
		}
		if err := resp.Body.Close(); err != nil {
			os.Exit(1)
		}
		if resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Load configuration from environment
	cfg := gateway.ConfigFromEnv()
	if err := gateway.ValidateDevRuntimeGuardrails(cfg); err != nil {
		log.Fatalf("Startup guardrail violation: %v", err)
	}

	// RFA-m6j.1: Initialize OpenTelemetry TracerProvider.
	// When OTelEndpoint is empty, this is a no-op (AC6).
	otelShutdown, err := gateway.InitTracer(context.Background(), cfg.OTelEndpoint, cfg.OTelServiceName)
	if err != nil {
		log.Fatalf("Failed to initialize OTel tracer: %v", err)
	}

	// GAP-3: Initialize OpenTelemetry MeterProvider for application metrics.
	// When OTelEndpoint is empty, this is a no-op (no-op meter already in use).
	meterShutdown, err := gwmetrics.InitMeterProvider(context.Background(), cfg.OTelEndpoint, cfg.OTelServiceName)
	if err != nil {
		log.Fatalf("Failed to initialize OTel meter provider: %v", err)
	}

	// Create gateway server
	gw, err := gateway.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create gateway: %v", err)
	}

	// Register port adapters for third-party agent integrations.
	gw.RegisterPort(openclaw.NewAdapter(gw))
	gw.RegisterPort(email.NewAdapter(gw))

	// RFA-8z8.1: In prod mode, initialize SPIFFE mTLS before creating the server.
	// This connects to the SPIRE Agent, obtains an X.509 SVID, and configures
	// both the server TLS and the reverse proxy upstream transport.
	if strings.EqualFold(cfg.SPIFFEMode, "prod") {
		if err := gw.EnableSPIFFETLS(context.Background()); err != nil {
			log.Fatalf("Failed to initialize SPIFFE mTLS: %v", err)
		}
	}

	// Determine listen address and TLS configuration based on SPIFFE mode.
	var listenAddr string
	var serverTLS *tls.Config

	if strings.EqualFold(cfg.SPIFFEMode, "prod") {
		// RFA-8z8.1 AC1: Serve HTTPS with SPIRE-issued SVID on the SPIFFE listen port
		listenAddr = fmt.Sprintf(":%d", cfg.SPIFFEListenPort)
		serverTLS = gw.ServerTLSConfig()
	} else {
		// Dev mode: bind loopback by default; non-loopback requires explicit override.
		listenAddr = gateway.ResolveDevListenAddr(cfg)
	}

	// Create HTTP server
	srv := &http.Server{
		Addr:         listenAddr,
		Handler:      gw.Handler(),
		TLSConfig:    serverTLS,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in goroutine
	go func() {
		if strings.EqualFold(cfg.SPIFFEMode, "prod") {
			log.Printf("Starting PRECINCT Gateway (HTTPS/mTLS) on port %d", cfg.SPIFFEListenPort)
			log.Printf("Upstream MCP server (mTLS): %s", cfg.UpstreamURL)
			log.Printf("SPIFFE trust domain: %s", cfg.SPIFFETrustDomain)
			// ListenAndServeTLS with empty cert/key file paths because the TLS
			// config already has the certificate from go-spiffe.
			if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Server failed: %v", err)
			}
		} else {
			log.Printf("Starting PRECINCT Gateway (HTTP) on port %d", cfg.Port)
			log.Printf("Dev listener bind host: %s", cfg.DevListenHost)
			log.Printf("Upstream MCP server: %s", cfg.UpstreamURL)
			log.Printf("OPA policy directory: %s", cfg.OPAPolicyDir)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Server failed: %v", err)
			}
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down gateway...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Gateway forced to shutdown: %v", err)
	}

	// Close gateway resources (including SPIFFE TLS)
	if err := gw.Close(); err != nil {
		log.Printf("Gateway close error: %v", err)
	}

	// GAP-3: Flush pending OTel metrics before exit.
	if err := meterShutdown(ctx); err != nil {
		log.Printf("OTel meter shutdown error: %v", err)
	}

	// RFA-m6j.1: Flush pending OTel spans before exit.
	if err := otelShutdown(ctx); err != nil {
		log.Printf("OTel shutdown error: %v", err)
	}

	log.Println("Gateway stopped")
}
