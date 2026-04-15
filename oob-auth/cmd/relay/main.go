// Command relay starts the OOB-Auth relay backend HTTP server.
//
// It can run with either an in-memory store (for development) or a
// Firestore-backed store (for production on Cloud Run).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/kallja/ai-sandbox/oob-auth/relay"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	storeType := flag.String("store", "memory", "store backend: memory or firestore")
	gcpProject := flag.String("gcp-project", "", "GCP project ID (required for firestore store)")
	cfClientID := flag.String("cf-client-id", envOrDefault("CF_ACCESS_CLIENT_ID", ""), "Cloudflare Access client ID")
	cfClientSecret := flag.String("cf-client-secret", envOrDefault("CF_ACCESS_CLIENT_SECRET", ""), "Cloudflare Access client secret")
	flag.Parse()

	store, cleanup, err := buildStore(*storeType, *gcpProject)
	if err != nil {
		log.Fatalf("store init: %v", err)
	}
	defer cleanup()

	srv := relay.NewServer(store)
	handler := relay.LoggingMiddleware(
		relay.CloudflareMiddleware(*cfClientID, *cfClientSecret, srv.Handler()),
	)

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	go func() {
		slog.Info("relay listening", "addr", *addr, "store", *storeType)
		if err := httpSrv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	httpSrv.Shutdown(shutdownCtx)
}

func buildStore(storeType, gcpProject string) (relay.Store, func(), error) {
	switch storeType {
	case "memory":
		return relay.NewMemStore(), func() {}, nil
	case "firestore":
		if gcpProject == "" {
			return nil, nil, fmt.Errorf("--gcp-project is required for firestore store")
		}
		ctx := context.Background()
		client, err := firestore.NewClient(ctx, gcpProject)
		if err != nil {
			return nil, nil, fmt.Errorf("create firestore client: %w", err)
		}
		return relay.NewFirestoreStore(client), func() { client.Close() }, nil
	default:
		return nil, nil, fmt.Errorf("unknown store type: %s", storeType)
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
