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

	"github.com/precinct-dev/precinct/internal/gateway"
	gwmetrics "github.com/precinct-dev/precinct/internal/gateway/metrics"
	"github.com/precinct-dev/precinct/ports/discord"
	"github.com/precinct-dev/precinct/ports/email"
	"github.com/precinct-dev/precinct/ports/openclaw"
)

func main() {
	// Health check subcommand for Docker HEALTHCHECK in distroless images.
	// RFA-8z8.1: In prod mode the server uses HTTPS, so the health check
	// must use the correct scheme. We use SPIFFE_MODE to determine this.
	if len(os.Args) > 1 && os.Args[1] == "health" {
		cfg := gateway.ConfigFromEnv()
		healthURL := fmt.Sprintf("http://localhost:%d/health", cfg.Port)
		if strings.EqualFold(cfg.SPIFFEMode, "prod") && cfg.PublicListenPort > 0 {
			healthURL = fmt.Sprintf("http://localhost:%d/health", cfg.PublicListenPort)
		}

		// In legacy prod-only mTLS mode with no public listener, fall back to a
		// TCP probe because the HTTPS listener requires a client certificate.
		if strings.EqualFold(cfg.SPIFFEMode, "prod") && cfg.PublicListenPort <= 0 {
			port := os.Getenv("SPIFFE_LISTEN_PORT")
			if port == "" {
				port = "9443"
			}
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%s", port), 2*time.Second)
			if err != nil {
				os.Exit(1)
			}
			_ = conn.Close()
			os.Exit(0)
		}

		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get(healthURL)
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
	gw.RegisterPort(discord.NewAdapter(gw))
	gw.RegisterPort(email.NewAdapter(gw))

	// RFA-8z8.1: In prod mode, initialize SPIFFE mTLS before creating the server.
	// This connects to the SPIRE Agent, obtains an X.509 SVID, and configures
	// both the server TLS and the reverse proxy upstream transport.
	enableSupplementalMTLS := cfg.SPIFFEInternalMTLSEnabled && !strings.EqualFold(cfg.SPIFFEMode, "prod")
	if strings.EqualFold(cfg.SPIFFEMode, "prod") || enableSupplementalMTLS {
		if err := gw.EnableSPIFFETLS(context.Background()); err != nil {
			log.Fatalf("Failed to initialize SPIFFE mTLS: %v", err)
		}
	}

	internalSrv := newInternalServer(cfg, gw)
	publicSrv := newPublicServer(cfg, gw)
	supplementalMTLSSrv := newSupplementalMTLSServer(cfg, gw)

	// Start server in goroutine
	go func() {
		if strings.EqualFold(cfg.SPIFFEMode, "prod") {
			log.Printf("Starting PRECINCT Gateway (HTTPS/mTLS) on port %d", cfg.SPIFFEListenPort)
			log.Printf("Upstream MCP server (mTLS): %s", cfg.UpstreamURL)
			log.Printf("SPIFFE trust domain: %s", cfg.SPIFFETrustDomain)
			// ListenAndServeTLS with empty cert/key file paths because the TLS
			// config already has the certificate from go-spiffe.
			if err := internalSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Server failed: %v", err)
			}
		} else {
			log.Printf("Starting PRECINCT Gateway (HTTP) on port %d", cfg.Port)
			log.Printf("Dev listener bind host: %s", cfg.DevListenHost)
			log.Printf("Upstream MCP server: %s", cfg.UpstreamURL)
			log.Printf("OPA policy directory: %s", cfg.OPAPolicyDir)
			if err := internalSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Server failed: %v", err)
			}
		}
	}()
	if supplementalMTLSSrv != nil {
		go func() {
			log.Printf("Starting PRECINCT Gateway internal SPIFFE mTLS listener (HTTPS/mTLS) on port %d", cfg.SPIFFEListenPort)
			if err := supplementalMTLSSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Supplemental mTLS server failed: %v", err)
			}
		}()
	}
	if publicSrv != nil {
		go func() {
			log.Printf("Starting PRECINCT Gateway public listener (HTTP) on %s", publicSrv.Addr)
			if err := publicSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Public server failed: %v", err)
			}
		}()
	}

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down gateway...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := internalSrv.Shutdown(ctx); err != nil {
		log.Fatalf("Gateway forced to shutdown: %v", err)
	}
	if publicSrv != nil {
		if err := publicSrv.Shutdown(ctx); err != nil {
			log.Fatalf("Public gateway forced to shutdown: %v", err)
		}
	}
	if supplementalMTLSSrv != nil {
		if err := supplementalMTLSSrv.Shutdown(ctx); err != nil {
			log.Fatalf("Supplemental mTLS gateway forced to shutdown: %v", err)
		}
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

func newInternalServer(cfg *gateway.Config, gw *gateway.Gateway) *http.Server {
	listenAddr := gateway.ResolveDevListenAddr(cfg)
	var serverTLS *tls.Config
	if strings.EqualFold(cfg.SPIFFEMode, "prod") {
		listenAddr = fmt.Sprintf(":%d", cfg.SPIFFEListenPort)
		serverTLS = gw.ServerTLSConfig()
	}
	return &http.Server{
		Addr:         listenAddr,
		Handler:      gw.Handler(),
		TLSConfig:    serverTLS,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
}

func newPublicServer(cfg *gateway.Config, gw *gateway.Gateway) *http.Server {
	if !strings.EqualFold(cfg.SPIFFEMode, "prod") || cfg.PublicListenPort <= 0 {
		return nil
	}
	return &http.Server{
		Addr:         gateway.ResolvePublicListenAddr(cfg),
		Handler:      gw.PublicHandler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
}

func newSupplementalMTLSServer(cfg *gateway.Config, gw *gateway.Gateway) *http.Server {
	if strings.EqualFold(cfg.SPIFFEMode, "prod") || !cfg.SPIFFEInternalMTLSEnabled {
		return nil
	}
	return &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.SPIFFEListenPort),
		Handler:      gw.Handler(),
		TLSConfig:    gw.ServerTLSConfig(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
}
