// Command chat implements bidirectional E2EE messaging over the OOB-Auth
// relay backend. Two instances exchange encrypted messages using Ed25519
// key pairs and NaCl box encryption.
//
// Usage:
//
//	bin/chat --relay=http://localhost:8080 --key=my.key --peer-pub=peer.pub
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/kallja/ai-sandbox/oob-auth/crypto"
	"github.com/kallja/ai-sandbox/oob-auth/protocol"
)

func main() {
	relayURL := flag.String("relay", "http://localhost:8080", "relay backend URL")
	privKeyPath := flag.String("key", "", "path to Ed25519 private key PEM")
	peerPubPath := flag.String("peer-pub", "", "path to peer's Ed25519 public key PEM")
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

	myPub := privKey.Public().(ed25519.PublicKey)
	myQueueID := crypto.QueueID(myPub)
	peerQueueID := crypto.QueueID(peerPub)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	client := http.DefaultClient

	fmt.Println("Chat ready. Type a message and press Enter to send. Ctrl+C to quit.")
	fmt.Printf("  My queue:   %s\n", myQueueID[:16]+"...")
	fmt.Printf("  Peer queue: %s\n", peerQueueID[:16]+"...")
	fmt.Println()

	// Receive loop: long-poll the relay for incoming messages.
	go receiveLoop(ctx, client, *relayURL, myQueueID, peerPub, privKey)

	// Send loop: read stdin lines and publish encrypted messages.
	sendLoop(ctx, client, *relayURL, peerQueueID, privKey, peerPub)
}

// sendLoop reads lines from stdin, encrypts them, and publishes to the
// peer's relay queue.
func sendLoop(ctx context.Context, client *http.Client, relayURL, peerQueueID string, privKey ed25519.PrivateKey, peerPub ed25519.PublicKey) {
	scanner := bufio.NewScanner(os.Stdin)
	myPub := privKey.Public().(ed25519.PublicKey)

	for scanner.Scan() {
		if ctx.Err() != nil {
			return
		}
		msg := scanner.Bytes()
		if len(msg) == 0 {
			continue
		}
		if len(msg) > protocol.MaxMessageSize {
			fmt.Fprintf(os.Stderr, "message too long: %d bytes (max %d)\n", len(msg), protocol.MaxMessageSize)
			continue
		}

		padded, err := crypto.Pad(msg, protocol.PaddedPlaintextSize)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pad: %v\n", err)
			continue
		}

		nonce, ciphertext, err := crypto.Seal(padded, privKey, peerPub)
		if err != nil {
			fmt.Fprintf(os.Stderr, "encrypt: %v\n", err)
			crypto.Zero(padded)
			continue
		}
		crypto.Zero(padded)

		env := &protocol.Envelope{
			SenderID:   crypto.Fingerprint(myPub),
			Nonce:      nonce[:],
			Ciphertext: ciphertext,
		}

		if err := publish(ctx, client, relayURL, peerQueueID, env); err != nil {
			fmt.Fprintf(os.Stderr, "send: %v\n", err)
		}
	}
}

// receiveLoop long-polls the relay for messages, decrypts, and prints them.
func receiveLoop(ctx context.Context, client *http.Client, relayURL, myQueueID string, peerPub ed25519.PublicKey, privKey ed25519.PrivateKey) {
	url := relayURL + "/api/v1/queue/" + myQueueID

	for {
		if ctx.Err() != nil {
			return
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return
		}

		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			time.Sleep(time.Second)
			continue
		}

		switch resp.StatusCode {
		case http.StatusOK:
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}

			env, err := protocol.UnmarshalEnvelope(body)
			if err != nil {
				fmt.Fprintf(os.Stderr, "unmarshal: %v\n", err)
				continue
			}

			var nonce [24]byte
			copy(nonce[:], env.Nonce)
			padded, err := crypto.Open(env.Ciphertext, nonce, peerPub, privKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "decrypt: %v\n", err)
				continue
			}

			msg, err := crypto.Unpad(padded)
			crypto.Zero(padded)
			if err != nil {
				fmt.Fprintf(os.Stderr, "unpad: %v\n", err)
				continue
			}

			fmt.Printf("\r< %s\n", msg)

		case http.StatusNoContent:
			resp.Body.Close()
			continue

		default:
			resp.Body.Close()
			time.Sleep(time.Second)
		}
	}
}

// publish sends an encrypted envelope to the relay.
func publish(ctx context.Context, client *http.Client, relayURL, queueID string, env *protocol.Envelope) error {
	data, err := protocol.MarshalEnvelope(env)
	if err != nil {
		return err
	}

	url := relayURL + "/api/v1/queue/" + queueID
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("relay returned %d: %s", resp.StatusCode, body)
	}
	return nil
}
