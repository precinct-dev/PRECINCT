package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/example/agentic-security-poc/internal/gateway"
)

func main() {
	// Load configuration from environment
	cfg := gateway.ConfigFromEnv()

	// Create gateway server
	gw, err := gateway.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create gateway: %v", err)
	}

	// Create HTTP server
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      gw.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("Starting MCP Security Gateway on port %d", cfg.Port)
		log.Printf("Upstream MCP server: %s", cfg.UpstreamURL)
		log.Printf("OPA endpoint: %s", cfg.OPAEndpoint)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
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

	log.Println("Gateway stopped")
}
