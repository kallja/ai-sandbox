// Command client-a runs the OOB-Auth Requester.
//
// It generates an encrypted OAuth intent, publishes it to the relay,
// and waits for the Broker to return tokens.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/kallja/ai-sandbox/oob-auth/clienta"
	"github.com/kallja/ai-sandbox/oob-auth/crypto"
)

func main() {
	relayURL := flag.String("relay", "http://localhost:8080", "relay backend URL")
	authURL := flag.String("auth-url", "", "OAuth authorization endpoint")
	tokenURL := flag.String("token-url", "", "OAuth token endpoint")
	clientID := flag.String("client-id", "", "OAuth client ID")
	scopes := flag.String("scopes", "", "comma-separated OAuth scopes")
	redirectURI := flag.String("redirect-uri", "http://localhost:8080/callback", "OAuth redirect URI")
	privKeyPath := flag.String("key", "", "path to Ed25519 private key PEM")
	peerPubPath := flag.String("peer-pub", "", "path to Broker's Ed25519 public key PEM")
	timeout := flag.Duration("timeout", 5*time.Minute, "max time to wait for response")
	flag.Parse()

	if *authURL == "" || *clientID == "" || *privKeyPath == "" || *peerPubPath == "" {
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

	cfg := &clienta.Config{
		RelayURL:    *relayURL,
		AuthURL:     *authURL,
		TokenURL:    *tokenURL,
		ClientID:    *clientID,
		Scopes:      splitScopes(*scopes),
		RedirectURI: *redirectURI,
		PrivateKey:  privKey,
		PeerPub:     peerPub,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	fmt.Println("Publishing encrypted intent to relay...")
	result, err := clienta.Run(ctx, cfg, http.DefaultClient)
	if err != nil {
		log.Fatalf("requester: %v", err)
	}

	if result.Error != "" {
		fmt.Fprintf(os.Stderr, "Broker error: %s\n", result.Error)
		os.Exit(1)
	}

	if result.AccessToken != "" {
		fmt.Printf("Access Token: %s\n", result.AccessToken)
		fmt.Printf("Token Type:   %s\n", result.TokenType)
		fmt.Printf("Expires In:   %d seconds\n", result.ExpiresIn)
	} else if result.AuthCode != "" {
		fmt.Printf("Auth Code: %s\n", result.AuthCode)
	}
}

func splitScopes(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}
