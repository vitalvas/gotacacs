// Package main provides an example TACACS+ client CLI.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/vitalvas/gotacacs"
)

func main() {
	var (
		server   = flag.String("server", "localhost:49", "TACACS+ server address (host:port)")
		secret   = flag.String("secret", "", "Shared secret for TACACS+ communication")
		timeout  = flag.Duration("timeout", 30*time.Second, "Connection timeout")
		useTLS   = flag.Bool("tls", false, "Use TLS for secure communication")
		insecure = flag.Bool("insecure", false, "Skip TLS certificate verification")
		mode     = flag.String("mode", "authenticate", "Operation mode: authenticate, authorize, or account")
		user     = flag.String("user", "", "Username for authentication/authorization")
		pass     = flag.String("pass", "", "Password for authentication")
		args     = flag.String("args", "", "Comma-separated arguments for authorization/accounting")
		acctType = flag.String("acct-type", "start", "Accounting type: start, stop, or watchdog")
		verbose  = flag.Bool("verbose", false, "Enable verbose output")
	)
	flag.Parse()

	if *user == "" {
		log.Fatal("Error: -user flag is required")
	}

	opts := []gotacacs.ClientOption{
		gotacacs.WithTimeout(*timeout),
	}

	if *secret != "" {
		opts = append(opts, gotacacs.WithSecret(*secret))
	}

	if *useTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: *insecure,
		}
		opts = append(opts, gotacacs.WithTLSConfig(tlsConfig))
	}

	// Validate mode and required parameters before creating context
	switch *mode {
	case "authenticate":
		if *pass == "" {
			log.Fatal("Error: -pass flag is required for authentication mode")
		}
	case "authorize", "account":
		// No additional validation needed
	default:
		log.Fatalf("Error: unknown mode %q. Use authenticate, authorize, or account", *mode)
	}

	client := gotacacs.NewClient(*server, opts...)

	if *verbose {
		log.Printf("Connecting to %s...", *server)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	switch *mode {
	case "authenticate":
		runAuthentication(ctx, client, *user, *pass, *verbose)

	case "authorize":
		argList := parseArgs(*args)
		runAuthorization(ctx, client, *user, argList, *verbose)

	case "account":
		argList := parseArgs(*args)
		runAccounting(ctx, client, *user, argList, *acctType, *verbose)
	}
}

func parseArgs(argsStr string) []string {
	if argsStr == "" {
		return nil
	}
	return strings.Split(argsStr, ",")
}

func runAuthentication(ctx context.Context, client *gotacacs.Client, user, pass string, verbose bool) {
	if verbose {
		log.Printf("Authenticating user: %s", user)
	}

	reply, err := client.Authenticate(ctx, user, pass)
	if err != nil {
		log.Fatalf("Authentication error: %v", err)
	}

	if reply.IsPass() {
		fmt.Println("Authentication: PASS")
		if len(reply.ServerMsg) > 0 {
			fmt.Printf("Server message: %s\n", string(reply.ServerMsg))
		}
		os.Exit(0)
	}

	fmt.Println("Authentication: FAIL")
	if len(reply.ServerMsg) > 0 {
		fmt.Printf("Server message: %s\n", string(reply.ServerMsg))
	}
	os.Exit(1)
}

func runAuthorization(ctx context.Context, client *gotacacs.Client, user string, args []string, verbose bool) {
	if verbose {
		log.Printf("Authorizing user: %s with args: %v", user, args)
	}

	resp, err := client.Authorize(ctx, user, args)
	if err != nil {
		log.Fatalf("Authorization error: %v", err)
	}

	if resp.IsPass() {
		fmt.Println("Authorization: PASS")
		if respArgs := resp.GetArgs(); len(respArgs) > 0 {
			fmt.Println("Response arguments:")
			for _, arg := range respArgs {
				fmt.Printf("  %s\n", arg)
			}
		}
		if len(resp.ServerMsg) > 0 {
			fmt.Printf("Server message: %s\n", string(resp.ServerMsg))
		}
		os.Exit(0)
	}

	fmt.Println("Authorization: FAIL")
	if len(resp.ServerMsg) > 0 {
		fmt.Printf("Server message: %s\n", string(resp.ServerMsg))
	}
	os.Exit(1)
}

func runAccounting(ctx context.Context, client *gotacacs.Client, user string, args []string, acctType string, verbose bool) {
	if verbose {
		log.Printf("Sending accounting %s for user: %s with args: %v", acctType, user, args)
	}

	var reply *gotacacs.AcctReply
	var err error

	switch acctType {
	case "start":
		reply, err = client.AccountingStart(ctx, user, args)
	case "stop":
		reply, err = client.AccountingStop(ctx, user, args)
	case "watchdog":
		reply, err = client.AccountingWatchdog(ctx, user, args)
	default:
		log.Fatalf("Error: unknown accounting type %q. Use start, stop, or watchdog", acctType)
	}

	if err != nil {
		log.Fatalf("Accounting error: %v", err)
	}

	if reply.IsSuccess() {
		fmt.Printf("Accounting %s: SUCCESS\n", acctType)
		if len(reply.ServerMsg) > 0 {
			fmt.Printf("Server message: %s\n", string(reply.ServerMsg))
		}
		os.Exit(0)
	}

	fmt.Printf("Accounting %s: ERROR\n", acctType)
	if len(reply.ServerMsg) > 0 {
		fmt.Printf("Server message: %s\n", string(reply.ServerMsg))
	}
	os.Exit(1)
}
