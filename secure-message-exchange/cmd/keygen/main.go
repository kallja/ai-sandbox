// Command keygen generates identity keys for the E2EE Relay Protocol.
//
// It creates Ed25519 (signing), X25519 (key exchange), and ML-KEM-768
// (post-quantum KEM) key pairs, saving private keys as PEM (0600) and
// public keys in formats suitable for peer configuration.
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/kallja/ai-sandbox/secure-message-exchange/crypto"
)

func main() {
	dir := flag.String("dir", ".", "output directory for generated keys")
	flag.Parse()

	if err := os.MkdirAll(*dir, 0700); err != nil {
		log.Fatalf("create output dir: %v", err)
	}

	// Ed25519
	edPub, edPriv, err := crypto.GenerateEd25519()
	if err != nil {
		log.Fatalf("generate Ed25519: %v", err)
	}
	if err := crypto.SaveEd25519Private(edPriv, filepath.Join(*dir, "ed25519.pem")); err != nil {
		log.Fatalf("save Ed25519 private: %v", err)
	}
	if err := crypto.SaveEd25519Public(edPub, filepath.Join(*dir, "ed25519.pub")); err != nil {
		log.Fatalf("save Ed25519 public: %v", err)
	}

	// X25519
	x25519Priv, err := crypto.GenerateX25519()
	if err != nil {
		log.Fatalf("generate X25519: %v", err)
	}
	if err := crypto.SaveX25519Private(x25519Priv, filepath.Join(*dir, "x25519.pem")); err != nil {
		log.Fatalf("save X25519 private: %v", err)
	}
	if err := crypto.SaveX25519Public(x25519Priv.PublicKey(), filepath.Join(*dir, "x25519.pub")); err != nil {
		log.Fatalf("save X25519 public: %v", err)
	}

	// ML-KEM-768
	mlkemDK, err := crypto.GenerateMLKEM768()
	if err != nil {
		log.Fatalf("generate ML-KEM-768: %v", err)
	}
	if err := crypto.SaveMLKEM768Private(mlkemDK, filepath.Join(*dir, "mlkem768.key")); err != nil {
		log.Fatalf("save ML-KEM-768 private: %v", err)
	}
	if err := crypto.SaveMLKEM768Public(mlkemDK.EncapsulationKey(), filepath.Join(*dir, "mlkem768.pub")); err != nil {
		log.Fatalf("save ML-KEM-768 public: %v", err)
	}

	// Fingerprint
	fp := crypto.FingerprintHex(edPub)
	os.WriteFile(filepath.Join(*dir, "fingerprint.txt"), []byte(fp+"\n"), 0644)

	fmt.Println("Keys generated successfully.")
	fmt.Printf("  Ed25519 public:  %s\n", base64.StdEncoding.EncodeToString(edPub))
	fmt.Printf("  X25519 public:   %s\n", base64.StdEncoding.EncodeToString(x25519Priv.PublicKey().Bytes()))
	fmt.Printf("  ML-KEM-768 pub:  %s... (%d bytes)\n", base64.StdEncoding.EncodeToString(mlkemDK.EncapsulationKey().Bytes()[:32]), len(mlkemDK.EncapsulationKey().Bytes()))
	fmt.Printf("  Fingerprint:     %s\n", fp)
	fmt.Printf("  Output dir:      %s\n", *dir)
}
