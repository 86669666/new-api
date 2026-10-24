//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/QuantumNous/new-api/internal/admissionbroker"
)

func main() {
	// Only a root-protected configuration pathname is accepted. Capabilities and
	// database credentials are never command-line arguments or error text.
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: admission-broker PROTECTED_CONFIG")
		os.Exit(2)
	}
	server, err := admissionbroker.Open(os.Args[1], os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "admission broker startup rejected")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err = server.Serve(ctx, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "admission broker did not drain cleanly")
		os.Exit(1)
	}
}
