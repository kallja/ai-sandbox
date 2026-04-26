// Command relay starts the E2EE Relay Protocol server.
package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"cloud.google.com/go/firestore"
	ecrypto "github.com/kallja/ai-sandbox/secure-message-exchange/crypto"
	"github.com/kallja/ai-sandbox/secure-message-exchange/relay"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	storeType := flag.String("store", "memory", "store backend: memory or firestore")
	gcpProject := flag.String("gcp-project", envOrDefault("GCP_PROJECT", ""), "GCP project ID (required for firestore)")
	keyDir := flag.String("key-dir", envOrDefault("KEY_DIR", ""), "directory containing server identity keys")
	powDiff := flag.Int("pow-difficulty", 20, "proof-of-work difficulty (leading zero bits)")
	clientKeysDir := flag.String("client-keys-dir", envOrDefault("CLIENT_KEYS_DIR", ""), "directory containing client public keys for registry")
	flag.Parse()

	if *keyDir == "" {
		log.Fatal("--key-dir is required")
	}

	// Load server identity keys.
	serverX25519Priv, err := ecrypto.LoadX25519Private(*keyDir + "/x25519.pem")
	if err != nil {
		log.Fatalf("load server X25519 key: %v", err)
	}

	serverEdPub, err := ecrypto.LoadEd25519Public(*keyDir + "/ed25519.pub")
	if err != nil {
		log.Fatalf("load server Ed25519 public key: %v", err)
	}

	// Build store.
	store, cleanup, err := buildStore(*storeType, *gcpProject)
	if err != nil {
		log.Fatalf("store init: %v", err)
	}
	defer cleanup()

	// Build client registry.
	registry := buildRegistry(*clientKeysDir)

	srv := relay.NewServer(relay.ServerConfig{
		Store:          store,
		ServerPriv:     serverX25519Priv,
		ServerIdentity: serverEdPub,
		Registry:       registry,
		PoWDifficulty:  *powDiff,
	})

	handler := relay.LoggingMiddleware(srv.Handler())
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	go func() {
		slog.Info("relay listening", "addr", *addr, "store", *storeType, "pow", *powDiff)
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

func buildRegistry(clientKeysDir string) relay.ClientRegistry {
	clients := make(map[[32]byte]ed25519.PublicKey)

	if clientKeysDir != "" {
		entries, err := os.ReadDir(clientKeysDir)
		if err != nil {
			slog.Warn("read client keys dir", "error", err)
			return relay.NewStaticRegistry(clients)
		}

		for _, entry := range entries {
			if entry.IsDir() {
				pubPath := clientKeysDir + "/" + entry.Name() + "/ed25519.pub"
				pub, err := ecrypto.LoadEd25519Public(pubPath)
				if err != nil {
					slog.Warn("load client key", "path", pubPath, "error", err)
					continue
				}
				fp := ecrypto.Fingerprint(pub)
				clients[fp] = pub
				slog.Info("registered client", "name", entry.Name(), "fingerprint", ecrypto.FingerprintHex(pub))
			}
		}
	}

	return relay.NewStaticRegistry(clients)
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
