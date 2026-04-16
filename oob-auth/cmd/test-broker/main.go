// Command test-broker is a non-interactive version of client-b for
// automated testing. Instead of prompting for an authorization code,
// it returns a fixed mock code. In token mode it also runs an embedded
// mock token endpoint.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/kallja/ai-sandbox/oob-auth/clientb"
	"github.com/kallja/ai-sandbox/oob-auth/crypto"
	"github.com/kallja/ai-sandbox/oob-auth/protocol"
)

func main() {
	relayURL := flag.String("relay", "http://localhost:8080", "relay backend URL")
	mode := flag.String("mode", "code", "response mode: code or token")
	privKeyPath := flag.String("key", "", "path to Ed25519 private key PEM")
	peerPubPath := flag.String("peer-pub", "", "path to Requester's Ed25519 public key PEM")
	mockCode := flag.String("mock-code", "test-auth-code", "authorization code to return")
	mockTokenAddr := flag.String("mock-token-addr", ":9090", "listen address for the mock token endpoint (token mode only)")
	timeout := flag.Duration("timeout", 2*time.Minute, "max time to wait for intent")
	flag.Parse()

	if *privKeyPath == "" || *peerPubPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	privKey, err := crypto.LoadPrivateKey(*privKeyPath)
	if err != nil {
		log.Fatalf("load private key: %v", err)
	}
	peerPub, err := crypto.LoadPublicKey(*peerPubPath)
	if err != nil {
		log.Fatalf("load peer public key: %v", err)
	}

	cfg := &clientb.Config{
		RelayURL:   *relayURL,
		PrivateKey: privKey,
		PeerPub:    peerPub,
		Mode:       *mode,
	}

	auth := &mockOAuth{code: *mockCode}

	var redeemer clientb.TokenRedeemer
	if *mode == "token" {
		// Start an embedded mock token endpoint on a fixed address so
		// client-a can set --token-url=http://test-broker:<port>/token.
		tokenSrv, tokenURL := startMockTokenServer(*mockTokenAddr)
		defer tokenSrv.Close()
		fmt.Printf("Mock token endpoint: %s\n", tokenURL)
		redeemer = &clientb.HTTPTokenRedeemer{Client: http.DefaultClient}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	fmt.Println("Test broker waiting for intent...")
	if err := clientb.Run(ctx, cfg, http.DefaultClient, auth, redeemer); err != nil {
		fmt.Fprintf(os.Stderr, "test-broker: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Test broker: response sent successfully.")
}

// mockOAuth implements clientb.OAuthExecutor by returning a fixed auth code.
type mockOAuth struct {
	code string
}

func (m *mockOAuth) Authorize(_ context.Context, intent *protocol.Intent) (string, error) {
	fmt.Printf("Received intent: client_id=%s scopes=%v\n", intent.ClientID, intent.Scopes)
	fmt.Printf("Auto-returning mock auth code: %s\n", m.code)
	return m.code, nil
}

// startMockTokenServer starts an HTTP server that returns a fake token response.
func startMockTokenServer(addr string) (*http.Server, string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "mock-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen for mock token server: %v", err)
	}

	srv := &http.Server{Handler: mux}
	go srv.Serve(listener)

	return srv, fmt.Sprintf("http://%s/token", listener.Addr().String())
}
