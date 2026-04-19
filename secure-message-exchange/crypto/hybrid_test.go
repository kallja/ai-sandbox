package crypto

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"testing"
)

func TestHybrid_RoundTrip(t *testing.T) {
	// Generate recipient keys.
	x25519Priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mlkemDK, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}

	// Encapsulate.
	ephPub, mlkemCt, senderRK, err := HybridEncapsulate(
		x25519Priv.PublicKey(), mlkemDK.EncapsulationKey(),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Decapsulate.
	recipientRK, err := HybridDecapsulate(ephPub, mlkemCt, x25519Priv, mlkemDK)
	if err != nil {
		t.Fatal(err)
	}

	if senderRK != recipientRK {
		t.Fatal("root keys do not match")
	}
}

func TestHybrid_WrongX25519Key(t *testing.T) {
	x25519Priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	wrongX25519Priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	mlkemDK, _ := mlkem.GenerateKey768()

	ephPub, mlkemCt, senderRK, err := HybridEncapsulate(
		x25519Priv.PublicKey(), mlkemDK.EncapsulationKey(),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Decapsulate with wrong X25519 key.
	recipientRK, err := HybridDecapsulate(ephPub, mlkemCt, wrongX25519Priv, mlkemDK)
	if err != nil {
		t.Fatal(err)
	}

	// Root keys must differ since X25519 shared secret is different.
	if senderRK == recipientRK {
		t.Fatal("root keys should differ with wrong X25519 key")
	}
}

func TestHybrid_WrongMLKEMKey(t *testing.T) {
	x25519Priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	mlkemDK, _ := mlkem.GenerateKey768()
	wrongMLKEMDK, _ := mlkem.GenerateKey768()

	ephPub, mlkemCt, senderRK, err := HybridEncapsulate(
		x25519Priv.PublicKey(), mlkemDK.EncapsulationKey(),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Decapsulate with wrong ML-KEM key — implicit rejection gives random shared secret.
	recipientRK, err := HybridDecapsulate(ephPub, mlkemCt, x25519Priv, wrongMLKEMDK)
	if err != nil {
		t.Fatal(err)
	}

	if senderRK == recipientRK {
		t.Fatal("root keys should differ with wrong ML-KEM key")
	}
}

func TestHybrid_EphPubSize(t *testing.T) {
	x25519Priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	mlkemDK, _ := mlkem.GenerateKey768()

	ephPub, _, _, err := HybridEncapsulate(
		x25519Priv.PublicKey(), mlkemDK.EncapsulationKey(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(ephPub) != 32 {
		t.Fatalf("ephemeral X25519 pub key length = %d, want 32", len(ephPub))
	}
}

func TestHybrid_MLKEMCiphertextSize(t *testing.T) {
	x25519Priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	mlkemDK, _ := mlkem.GenerateKey768()

	_, mlkemCt, _, err := HybridEncapsulate(
		x25519Priv.PublicKey(), mlkemDK.EncapsulationKey(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(mlkemCt) != 1088 {
		t.Fatalf("ML-KEM-768 ciphertext length = %d, want 1088", len(mlkemCt))
	}
}
