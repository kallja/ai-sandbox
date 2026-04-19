package wire

import (
	"testing"
)

func TestOuterEnvelopeConsistency(t *testing.T) {
	if EphKeySize+NonceSize+OuterCiphertextSize != OuterEnvelopeSize {
		t.Fatalf("outer envelope: %d + %d + %d = %d, want %d",
			EphKeySize, NonceSize, OuterCiphertextSize,
			EphKeySize+NonceSize+OuterCiphertextSize, OuterEnvelopeSize)
	}
	if OuterCiphertextSize-AEADOverhead != OuterPlaintextSize {
		t.Fatalf("outer plaintext: %d - %d = %d, want %d",
			OuterCiphertextSize, AEADOverhead,
			OuterCiphertextSize-AEADOverhead, OuterPlaintextSize)
	}
	if RoutingHeaderSize+InnerEnvelopeSize != OuterPlaintextSize {
		t.Fatalf("outer plaintext split: %d + %d = %d, want %d",
			RoutingHeaderSize, InnerEnvelopeSize,
			RoutingHeaderSize+InnerEnvelopeSize, OuterPlaintextSize)
	}
}

func TestRoutingHeaderConsistency(t *testing.T) {
	sum := MessageIDSize + 2*FingerprintSize + SignatureSize + RoutingPaddingSize
	if sum != RoutingHeaderSize {
		t.Fatalf("routing header fields sum to %d, want %d", sum, RoutingHeaderSize)
	}
	if RoutingPaddingOffset+RoutingPaddingSize != RoutingHeaderSize {
		t.Fatalf("routing padding end: %d + %d = %d, want %d",
			RoutingPaddingOffset, RoutingPaddingSize,
			RoutingPaddingOffset+RoutingPaddingSize, RoutingHeaderSize)
	}
}

func TestHandshakeInnerConsistency(t *testing.T) {
	if HandshakeHeaderSize+HandshakeAEADCtSize != InnerEnvelopeSize {
		t.Fatalf("handshake: %d + %d = %d, want %d",
			HandshakeHeaderSize, HandshakeAEADCtSize,
			HandshakeHeaderSize+HandshakeAEADCtSize, InnerEnvelopeSize)
	}
	if HandshakeAEADCtSize-AEADOverhead != HandshakePlaintextMax {
		t.Fatalf("handshake plaintext: %d - %d = %d, want %d",
			HandshakeAEADCtSize, AEADOverhead,
			HandshakeAEADCtSize-AEADOverhead, HandshakePlaintextMax)
	}
	if HandshakeTypeSize+HandshakeEphKeySize+HandshakeMLKEMCtSize != HandshakeHeaderSize {
		t.Fatal("handshake header field sizes don't sum to HandshakeHeaderSize")
	}
}

func TestRatchetInnerConsistency(t *testing.T) {
	if RatchetHeaderSize+RatchetAEADCtSize != InnerEnvelopeSize {
		t.Fatalf("ratchet: %d + %d = %d, want %d",
			RatchetHeaderSize, RatchetAEADCtSize,
			RatchetHeaderSize+RatchetAEADCtSize, InnerEnvelopeSize)
	}
	if RatchetAEADCtSize-AEADOverhead != RatchetPlaintextMax {
		t.Fatalf("ratchet plaintext: %d - %d = %d, want %d",
			RatchetAEADCtSize, AEADOverhead,
			RatchetAEADCtSize-AEADOverhead, RatchetPlaintextMax)
	}
	if RatchetTypeSize+RatchetEphKeySize+RatchetMsgNumSize+RatchetPrevChainSize != RatchetHeaderSize {
		t.Fatal("ratchet header field sizes don't sum to RatchetHeaderSize")
	}
}

func TestResponseConsistency(t *testing.T) {
	if ResponseNonceSize+ResponseCiphertextSize != ResponseSize {
		t.Fatalf("response: %d + %d = %d, want %d",
			ResponseNonceSize, ResponseCiphertextSize,
			ResponseNonceSize+ResponseCiphertextSize, ResponseSize)
	}
	if ResponseCiphertextSize-AEADOverhead != ResponsePlaintextSize {
		t.Fatalf("response plaintext: %d - %d = %d, want %d",
			ResponseCiphertextSize, AEADOverhead,
			ResponseCiphertextSize-AEADOverhead, ResponsePlaintextSize)
	}
	if StatusHeaderSize+ResponsePayloadSize != ResponsePlaintextSize {
		t.Fatalf("response plaintext split: %d + %d = %d, want %d",
			StatusHeaderSize, ResponsePayloadSize,
			StatusHeaderSize+ResponsePayloadSize, ResponsePlaintextSize)
	}
}

func TestExpectedValues(t *testing.T) {
	// Verify the exact numeric values match the spec.
	checks := []struct {
		name string
		got  int
		want int
	}{
		{"OuterEnvelopeSize", OuterEnvelopeSize, 4096},
		{"OuterCiphertextSize", OuterCiphertextSize, 4040},
		{"OuterPlaintextSize", OuterPlaintextSize, 4024},
		{"RoutingHeaderSize", RoutingHeaderSize, 256},
		{"InnerEnvelopeSize", InnerEnvelopeSize, 3768},
		{"HandshakeHeaderSize", HandshakeHeaderSize, 1121},
		{"HandshakeAEADCtSize", HandshakeAEADCtSize, 2647},
		{"HandshakePlaintextMax", HandshakePlaintextMax, 2631},
		{"HandshakeMLKEMCtSize", HandshakeMLKEMCtSize, 1088},
		{"RatchetHeaderSize", RatchetHeaderSize, 41},
		{"RatchetAEADCtSize", RatchetAEADCtSize, 3727},
		{"RatchetPlaintextMax", RatchetPlaintextMax, 3711},
		{"ResponseSize", ResponseSize, 4096},
		{"ResponseCiphertextSize", ResponseCiphertextSize, 4072},
		{"ResponsePlaintextSize", ResponsePlaintextSize, 4056},
		{"StatusHeaderSize", StatusHeaderSize, 256},
		{"ResponsePayloadSize", ResponsePayloadSize, 3800},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestPadToSize(t *testing.T) {
	t.Run("exact size", func(t *testing.T) {
		data := make([]byte, 100)
		data[0] = 0x42
		out, err := PadToSize(data, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 100 {
			t.Fatalf("got len %d, want 100", len(out))
		}
		if out[0] != 0x42 {
			t.Fatal("data not preserved")
		}
	})

	t.Run("smaller data padded", func(t *testing.T) {
		data := []byte{0x01, 0x02, 0x03}
		out, err := PadToSize(data, 256)
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 256 {
			t.Fatalf("got len %d, want 256", len(out))
		}
		if out[0] != 0x01 || out[1] != 0x02 || out[2] != 0x03 {
			t.Fatal("original data not preserved")
		}
		// Padding should not be all zeros (random).
		allZero := true
		for _, b := range out[3:] {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Fatal("padding is all zeros, expected random bytes")
		}
	})

	t.Run("data too large", func(t *testing.T) {
		data := make([]byte, 300)
		_, err := PadToSize(data, 256)
		if err == nil {
			t.Fatal("expected error for oversized data")
		}
	})

	t.Run("empty data", func(t *testing.T) {
		out, err := PadToSize(nil, 32)
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 32 {
			t.Fatalf("got len %d, want 32", len(out))
		}
	})
}

func TestValidateSize(t *testing.T) {
	if err := ValidateSize(make([]byte, 4096), 4096, "test"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := ValidateSize(make([]byte, 100), 4096, "test"); err == nil {
		t.Fatal("expected error for wrong size")
	}
}
