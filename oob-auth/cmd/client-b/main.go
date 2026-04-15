// Command client-b runs the OOB-Auth Trusted Broker.
//
// It long-polls the relay for encrypted intents from Client A,
// executes the OAuth flow, and returns encrypted tokens.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/kallja/ai-sandbox/oob-auth/clientb"
	"github.com/kallja/ai-sandbox/oob-auth/crypto"
)

func main() {
	relayURL := flag.String("relay", "http://localhost:8080", "relay backend URL")
	mode := flag.String("mode", "code", "response mode: code or token")
	privKeyPath := flag.String("key", "", "path to Ed25519 private key PEM")
	peerPubPath := flag.String("peer-pub", "", "path to Requester's Ed25519 public key PEM")
	timeout := flag.Duration("timeout", 10*time.Minute, "max time to wait for intent")
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	auth := &clientb.URLPresenter{}
	redeemer := &clientb.HTTPTokenRedeemer{Client: http.DefaultClient}

	if err := clientb.Run(ctx, cfg, http.DefaultClient, auth, redeemer); err != nil {
		fmt.Fprintf(os.Stderr, "broker: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Response sent to Requester.")
}
