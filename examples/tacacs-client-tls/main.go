// Package main provides an example TACACS+ client using TLS 1.3 (RFC 9887).
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/vitalvas/gotacacs"
)

func main() {
	addr := flag.String("addr", "localhost:300", "server address")
	insecure := flag.Bool("insecure", false, "skip TLS certificate verification")
	flag.Parse()

	tlsConfig := &tls.Config{
		InsecureSkipVerify: *insecure,
	}

	client := gotacacs.NewClient(
		gotacacs.WithAddress(*addr),
		gotacacs.WithTLSConfig(tlsConfig),
		gotacacs.WithTimeout(30*time.Second),
	)

	ctx := context.Background()

	// Authentication
	fmt.Println("=== Authentication ===")
	reply, err := client.Authenticate(ctx, "admin", "admin123")
	if err != nil {
		log.Fatalf("Authentication error: %v", err)
	}
	fmt.Printf("Status: %s\n", statusString(reply.IsPass()))
	fmt.Printf("Message: %s\n\n", string(reply.ServerMsg))

	// Authorization
	fmt.Println("=== Authorization ===")
	resp, err := client.Authorize(ctx, "admin", []string{"service=shell", "cmd=show"})
	if err != nil {
		log.Fatalf("Authorization error: %v", err)
	}
	fmt.Printf("Status: %s\n", statusString(resp.IsPass()))
	if args := resp.GetArgs(); len(args) > 0 {
		fmt.Println("Args:")
		for _, arg := range args {
			fmt.Printf("  %s\n", arg)
		}
	}
	fmt.Println()

	// Accounting
	fmt.Println("=== Accounting ===")
	acctReply, err := client.Accounting(ctx, gotacacs.AcctFlagStart, "admin", []string{"task_id=123"})
	if err != nil {
		log.Fatalf("Accounting error: %v", err)
	}
	fmt.Printf("Status: %s\n", statusString(acctReply.IsSuccess()))
}

func statusString(success bool) string {
	if success {
		return "PASS"
	}
	return "FAIL"
}
