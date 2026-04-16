// Command keygen generates Ed25519 key pairs for OOB-Auth testing.
//
// It writes four PEM files to the output directory:
//   requester-private.pem, requester-public.pem
//   broker-private.pem, broker-public.pem
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/kallja/ai-sandbox/oob-auth/crypto"
)

func main() {
	outDir := flag.String("out", ".", "output directory for key files")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		log.Fatalf("create output directory: %v", err)
	}

	for _, name := range []string{"requester", "broker"} {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			log.Fatalf("generate %s key pair: %v", name, err)
		}

		privPath := filepath.Join(*outDir, name+"-private.pem")
		pubPath := filepath.Join(*outDir, name+"-public.pem")

		if err := crypto.SavePrivateKey(kp.Private, privPath); err != nil {
			log.Fatalf("save %s private key: %v", name, err)
		}
		if err := crypto.SavePublicKey(kp.Public, pubPath); err != nil {
			log.Fatalf("save %s public key: %v", name, err)
		}

		fmt.Printf("%s: %s, %s\n", name, privPath, pubPath)
	}
}
