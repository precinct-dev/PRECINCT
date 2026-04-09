// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

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
)

func main() {
	// Health check subcommand for Docker HEALTHCHECK in distroless images.
	// For mTLS deployments (SPIFFE_MODE=prod), use a TCP probe on SPIFFE listen port.
	if len(os.Args) > 1 && os.Args[1] == "health" {
		cfg := gateway.ConfigFromEnv()
		healthURL := fmt.Sprintf("http://localhost:%d/health", cfg.Port)
		if strings.EqualFold(cfg.SPIFFEMode, "prod") {
			port := os.Getenv("SPIFFE_LISTEN_PORT")
			if port == "" {
				port = fmt.Sprintf("%d", cfg.SPIFFEListenPort)
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

	// Initialize OpenTelemetry trace and metric providers.
	otelShutdown, err := gateway.InitTracer(context.Background(), cfg.OTelEndpoint, cfg.OTelServiceName)
	if err != nil {
		log.Fatalf("Failed to initialize OTel tracer: %v", err)
	}

	meterShutdown, err := gwmetrics.InitMeterProvider(context.Background(), cfg.OTelEndpoint, cfg.OTelServiceName)
	if err != nil {
		log.Fatalf("Failed to initialize OTel meter provider: %v", err)
	}

	// Create gateway server instance and enable all control-plane middleware.
	gw, err := gateway.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create gateway: %v", err)
	}

	// In prod mode initialize SPIFFE mTLS before binding listeners.
	if strings.EqualFold(cfg.SPIFFEMode, "prod") {
		if err := gw.EnableSPIFFETLS(context.Background()); err != nil {
			log.Fatalf("Failed to initialize SPIFFE mTLS: %v", err)
		}
	}

	controlSrv := newControlServer(cfg, gw)

	// Start server in goroutine
	go func() {
		if strings.EqualFold(cfg.SPIFFEMode, "prod") {
			log.Printf("Starting PRECINCT Control service (HTTPS/mTLS) on port %d", cfg.SPIFFEListenPort)
			if err := controlSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Control service failed: %v", err)
			}
		} else {
			log.Printf("Starting PRECINCT Control service (HTTP) on port %d", cfg.Port)
			log.Printf("Dev listener bind host: %s", cfg.DevListenHost)
			if err := controlSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Control service failed: %v", err)
			}
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down control service...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := controlSrv.Shutdown(ctx); err != nil {
		log.Fatalf("Control service forced to shutdown: %v", err)
	}

	if err := gw.Close(); err != nil {
		log.Printf("Control gateway close error: %v", err)
	}

	if err := meterShutdown(ctx); err != nil {
		log.Printf("OTel meter shutdown error: %v", err)
	}
	if err := otelShutdown(ctx); err != nil {
		log.Printf("OTel shutdown error: %v", err)
	}

	log.Println("Control service stopped")
}

func newControlServer(cfg *gateway.Config, gw *gateway.Gateway) *http.Server {
	listenAddr := gateway.ResolveDevListenAddr(cfg)
	var serverTLS *tls.Config
	if strings.EqualFold(cfg.SPIFFEMode, "prod") {
		listenAddr = fmt.Sprintf(":%d", cfg.SPIFFEListenPort)
		serverTLS = gw.ServerTLSConfig()
	}

	return &http.Server{
		Addr:         listenAddr,
		Handler:      gw.ControlHandler(),
		TLSConfig:    serverTLS,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
}
