// Package e2etest contains end-to-end tests that build and run the actual
// relay, client, and keygen binaries as subprocesses.
package e2etest

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ecrypto "github.com/kallja/ai-sandbox/secure-message-exchange/crypto"
)

var (
	relayBin  string
	clientBin string
	keygenBin string
)

func TestMain(m *testing.M) {
	// Build binaries to a temp dir.
	tmpDir, err := os.MkdirTemp("", "e2e-bins-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	relayBin = filepath.Join(tmpDir, "relay")
	clientBin = filepath.Join(tmpDir, "client")
	keygenBin = filepath.Join(tmpDir, "keygen")

	// Find module root (parent of this test directory).
	modRoot, err := findModRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "find module root: %v\n", err)
		os.Exit(1)
	}

	for _, build := range []struct {
		bin, pkg string
	}{
		{relayBin, "./cmd/relay/"},
		{clientBin, "./cmd/client/"},
		{keygenBin, "./cmd/keygen/"},
	} {
		cmd := exec.Command("go", "build", "-o", build.bin, build.pkg)
		cmd.Dir = modRoot
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "build %s: %v\n", build.pkg, err)
			os.Exit(1)
		}
	}

	os.Exit(m.Run())
}

func TestKeygen(t *testing.T) {
	dir := t.TempDir()

	cmd := exec.Command(keygenBin, "--dir", dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("keygen failed: %v\n%s", err, out)
	}

	// Verify expected files exist.
	for _, name := range []string{"ed25519.pem", "ed25519.pub", "x25519.pem", "x25519.pub", "mlkem768.key", "mlkem768.pub", "fingerprint.txt"} {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("expected file %s: %v", name, err)
		}
		// Private keys must be 0600.
		if strings.Contains(name, ".pem") || name == "mlkem768.key" {
			if info.Mode().Perm() != 0600 {
				t.Fatalf("%s has perms %04o, want 0600", name, info.Mode().Perm())
			}
		}
	}

	// Verify fingerprint file is non-empty.
	fp, _ := os.ReadFile(filepath.Join(dir, "fingerprint.txt"))
	if len(strings.TrimSpace(string(fp))) != 64 {
		t.Fatalf("fingerprint length = %d, want 64 hex chars", len(strings.TrimSpace(string(fp))))
	}
}

func TestSendPollRoundTrip(t *testing.T) {
	// Generate keys for relay, alice, bob.
	relayDir := t.TempDir()
	aliceDir := t.TempDir()
	bobDir := t.TempDir()

	for _, dir := range []string{relayDir, aliceDir, bobDir} {
		cmd := exec.Command(keygenBin, "--dir", dir)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("keygen: %v\n%s", err, out)
		}
	}

	// Create client keys dir for the relay (so it knows about alice and bob).
	clientKeysDir := t.TempDir()
	for _, pair := range []struct{ name, dir string }{
		{"alice", aliceDir},
		{"bob", bobDir},
	} {
		peerDir := filepath.Join(clientKeysDir, pair.name)
		os.MkdirAll(peerDir, 0700)
		// Copy ed25519.pub.
		data, _ := os.ReadFile(filepath.Join(pair.dir, "ed25519.pub"))
		os.WriteFile(filepath.Join(peerDir, "ed25519.pub"), data, 0644)
	}

	// Start relay server on a random port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relayAddr := listener.Addr().String()
	listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	relayCmd := exec.CommandContext(ctx, relayBin,
		"--addr", relayAddr,
		"--store", "memory",
		"--key-dir", relayDir,
		"--client-keys-dir", clientKeysDir,
		"--pow-difficulty", "8",
	)
	relayCmd.Stderr = os.Stderr
	if err := relayCmd.Start(); err != nil {
		t.Fatalf("start relay: %v", err)
	}
	defer relayCmd.Process.Kill()

	// Wait for relay to be ready.
	relayURL := "http://" + relayAddr
	waitForRelay(t, relayURL, 5*time.Second)

	// Build peer config files.
	aliceCfg := buildPeerConfig(t, bobDir, relayDir, relayURL)
	bobCfg := buildPeerConfig(t, aliceDir, relayDir, relayURL)

	aliceCfgPath := filepath.Join(t.TempDir(), "alice-config.json")
	bobCfgPath := filepath.Join(t.TempDir(), "bob-config.json")
	os.WriteFile(aliceCfgPath, aliceCfg, 0644)
	os.WriteFile(bobCfgPath, bobCfg, 0644)

	// Alice sends a message.
	sendCmd := exec.CommandContext(ctx, clientBin, "send",
		"--config", aliceCfgPath,
		"--identity", aliceDir,
		"--peer", "peer",
		"--message", "hello from alice",
		"--pow-difficulty", "8",
	)
	if out, err := sendCmd.CombinedOutput(); err != nil {
		t.Fatalf("client send: %v\n%s", err, out)
	}

	// Bob polls.
	pollCmd := exec.CommandContext(ctx, clientBin, "poll",
		"--config", bobCfgPath,
		"--identity", bobDir,
		"--pow-difficulty", "8",
		"--timeout", "10s",
	)
	out, err := pollCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("client poll: %v\n%s", err, out)
	}

	if !strings.Contains(string(out), "hello from alice") {
		t.Fatalf("expected message in output, got: %s", out)
	}
}

func waitForRelay(t *testing.T, url string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		// Just try to connect. Any response (even dropped) means the server is up.
		resp, err := http.Post(url, "application/octet-stream", bytes.NewReader(make([]byte, 10)))
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("relay did not start in time")
}

func buildPeerConfig(t *testing.T, peerDir, relayDir, relayURL string) []byte {
	t.Helper()

	// Read peer public keys.
	edPub, _ := ecrypto.LoadEd25519Public(filepath.Join(peerDir, "ed25519.pub"))
	x25519Pub, _ := ecrypto.LoadX25519Public(filepath.Join(peerDir, "x25519.pub"))
	mlkemPub, _ := ecrypto.LoadMLKEM768Public(filepath.Join(peerDir, "mlkem768.pub"))

	// Read relay public keys.
	relayEdPub, _ := ecrypto.LoadEd25519Public(filepath.Join(relayDir, "ed25519.pub"))
	relayX25519Pub, _ := ecrypto.LoadX25519Public(filepath.Join(relayDir, "x25519.pub"))

	cfg := map[string]interface{}{
		"peers": map[string]interface{}{
			"peer": map[string]string{
				"ed25519":  base64.StdEncoding.EncodeToString(edPub),
				"x25519":   base64.StdEncoding.EncodeToString(x25519Pub.Bytes()),
				"mlkem768": base64.StdEncoding.EncodeToString(mlkemPub.Bytes()),
			},
		},
		"relay": map[string]string{
			"url":     relayURL,
			"x25519":  base64.StdEncoding.EncodeToString(relayX25519Pub.Bytes()),
			"ed25519": base64.StdEncoding.EncodeToString(relayEdPub),
		},
	}

	data, _ := json.Marshal(cfg)
	return data
}

// findModRoot walks up from the current directory to find go.mod.
func findModRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found")
		}
		dir = parent
	}
}

// Suppress unused import warnings for types used only in buildPeerConfig.
var _ *ecdh.PublicKey
var _ ed25519.PublicKey
var _ *mlkem.EncapsulationKey768
