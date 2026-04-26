// Command client is the E2EE Relay Protocol CLI for sending and polling messages.
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

	"github.com/kallja/ai-sandbox/secure-message-exchange/client"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <send|poll> [flags]\n", os.Args[0])
		os.Exit(1)
	}

	subcmd := os.Args[1]
	switch subcmd {
	case "send":
		cmdSend(os.Args[2:])
	case "poll":
		cmdPoll(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown subcommand: %s\nUsage: %s <send|poll> [flags]\n", subcmd, os.Args[0])
		os.Exit(1)
	}
}

func cmdSend(args []string) {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	configPath := fs.String("config", "", "path to peer config JSON")
	identityDir := fs.String("identity", "", "path to identity key directory")
	peerName := fs.String("peer", "", "peer alias to send to")
	message := fs.String("message", "", "message to send")
	powDiff := fs.Int("pow-difficulty", 0, "PoW difficulty (0 = default 20)")
	timeout := fs.Duration("timeout", 60*time.Second, "request timeout")
	fs.Parse(args)

	if *configPath == "" || *identityDir == "" || *peerName == "" || *message == "" {
		fs.Usage()
		os.Exit(1)
	}

	cfg, err := client.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	identity, err := client.LoadIdentity(*identityDir)
	if err != nil {
		log.Fatalf("load identity: %v", err)
	}

	peer, ok := cfg.Peers[*peerName]
	if !ok {
		log.Fatalf("unknown peer: %s", *peerName)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	if err := client.Send(ctx, identity, peer, cfg.Relay, []byte(*message), http.DefaultClient, *powDiff); err != nil {
		log.Fatalf("send: %v", err)
	}

	fmt.Println("Message sent.")
}

func cmdPoll(args []string) {
	fs := flag.NewFlagSet("poll", flag.ExitOnError)
	configPath := fs.String("config", "", "path to peer config JSON")
	identityDir := fs.String("identity", "", "path to identity key directory")
	powDiff := fs.Int("pow-difficulty", 0, "PoW difficulty (0 = default 20)")
	timeout := fs.Duration("timeout", 60*time.Second, "poll timeout")
	fs.Parse(args)

	if *configPath == "" || *identityDir == "" {
		fs.Usage()
		os.Exit(1)
	}

	cfg, err := client.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	identity, err := client.LoadIdentity(*identityDir)
	if err != nil {
		log.Fatalf("load identity: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	results, err := client.Poll(ctx, identity, cfg.Relay, cfg.Peers, http.DefaultClient, *powDiff)
	if err != nil {
		log.Fatalf("poll: %v", err)
	}

	if len(results) == 0 {
		fmt.Println("No messages.")
		return
	}

	for i, r := range results {
		fmt.Printf("[%d] %s\n", i+1, string(r.Message))
	}
}
