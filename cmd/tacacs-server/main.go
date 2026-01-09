// Package main provides an example TACACS+ server CLI.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/vitalvas/gotacacs"
)

func main() {
	var (
		listen   = flag.String("listen", ":49", "Listen address (host:port)")
		secret   = flag.String("secret", "", "Shared secret for TACACS+ communication")
		certFile = flag.String("cert", "", "TLS certificate file")
		keyFile  = flag.String("key", "", "TLS private key file")
		users    = flag.String("users", "admin:admin123,user:user123", "Comma-separated user:password pairs")
		verbose  = flag.Bool("verbose", false, "Enable verbose output")
	)
	flag.Parse()

	// Parse users
	userDB := parseUsers(*users)
	if len(userDB) == 0 {
		log.Println("Warning: No users configured")
	}

	// Create handler
	handler := &exampleHandler{
		users:   userDB,
		verbose: *verbose,
	}

	// Setup listener
	var listener gotacacs.Listener
	var err error

	if *certFile != "" && *keyFile != "" {
		tlsConfig, err := gotacacs.NewTLSConfig(*certFile, *keyFile)
		if err != nil {
			log.Fatalf("Failed to load TLS config: %v", err)
		}
		listener, err = gotacacs.ListenTLS(*listen, tlsConfig)
		if err != nil {
			log.Fatalf("Failed to start TLS listener: %v", err)
		}
		log.Printf("Starting TACACS+ TLS server on %s", *listen)
	} else {
		listener, err = gotacacs.ListenTCP(*listen)
		if err != nil {
			log.Fatalf("Failed to start TCP listener: %v", err)
		}
		log.Printf("Starting TACACS+ server on %s", *listen)
	}

	// Create server options
	opts := []gotacacs.ServerOption{
		gotacacs.WithServerListener(listener),
		gotacacs.WithHandler(handler),
		gotacacs.WithServerReadTimeout(30 * time.Second),
		gotacacs.WithServerWriteTimeout(30 * time.Second),
	}

	if *secret != "" {
		opts = append(opts, gotacacs.WithServerSecret(*secret))
	}

	server := gotacacs.NewServer(opts...)

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()

	// Start server
	if err := server.Serve(); err != nil {
		log.Printf("Server error: %v", err)
	}
	log.Println("Server stopped")
}

func parseUsers(usersStr string) map[string]string {
	users := make(map[string]string)
	if usersStr == "" {
		return users
	}

	pairs := strings.Split(usersStr, ",")
	for _, pair := range pairs {
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) == 2 {
			users[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return users
}

type exampleHandler struct {
	users   map[string]string
	verbose bool
}

func (h *exampleHandler) HandleAuthenStart(_ context.Context, req *gotacacs.AuthenRequest) *gotacacs.AuthenReply {
	user := string(req.Start.User)
	password := string(req.Start.Data)

	if h.verbose {
		log.Printf("Authentication request: user=%s from=%s", user, req.RemoteAddr)
	}

	expectedPass, ok := h.users[user]
	if !ok {
		if h.verbose {
			log.Printf("Authentication failed: unknown user %s", user)
		}
		return &gotacacs.AuthenReply{
			Status:    gotacacs.AuthenStatusFail,
			ServerMsg: []byte("Unknown user"),
		}
	}

	if password != expectedPass {
		if h.verbose {
			log.Printf("Authentication failed: invalid password for user %s", user)
		}
		return &gotacacs.AuthenReply{
			Status:    gotacacs.AuthenStatusFail,
			ServerMsg: []byte("Invalid password"),
		}
	}

	if h.verbose {
		log.Printf("Authentication successful: user=%s", user)
	}
	return &gotacacs.AuthenReply{
		Status:    gotacacs.AuthenStatusPass,
		ServerMsg: []byte("Authentication successful"),
	}
}

func (h *exampleHandler) HandleAuthenContinue(_ context.Context, req *gotacacs.AuthenContinueRequest) *gotacacs.AuthenReply {
	if h.verbose {
		log.Printf("Authentication continue from=%s", req.RemoteAddr)
	}
	return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusPass}
}

func (h *exampleHandler) HandleAuthorRequest(_ context.Context, req *gotacacs.AuthorRequestContext) *gotacacs.AuthorResponse {
	user := string(req.Request.User)

	if h.verbose {
		log.Printf("Authorization request: user=%s args=%v from=%s", user, req.Request.GetArgs(), req.RemoteAddr)
	}

	// Check if user exists
	if _, ok := h.users[user]; !ok {
		if h.verbose {
			log.Printf("Authorization denied: unknown user %s", user)
		}
		return &gotacacs.AuthorResponse{
			Status:    gotacacs.AuthorStatusFail,
			ServerMsg: []byte("Unknown user"),
		}
	}

	// Grant all requests with default privilege level
	if h.verbose {
		log.Printf("Authorization granted: user=%s", user)
	}
	return &gotacacs.AuthorResponse{
		Status: gotacacs.AuthorStatusPassAdd,
		Args:   [][]byte{[]byte("priv-lvl=15")},
	}
}

func (h *exampleHandler) HandleAcctRequest(_ context.Context, req *gotacacs.AcctRequestContext) *gotacacs.AcctReply {
	user := string(req.Request.User)

	var acctType string
	switch {
	case req.Request.IsStart():
		acctType = "start"
	case req.Request.IsStop():
		acctType = "stop"
	case req.Request.IsWatchdog():
		acctType = "watchdog"
	default:
		acctType = "unknown"
	}

	if h.verbose {
		log.Printf("Accounting %s: user=%s args=%v from=%s", acctType, user, req.Request.GetArgs(), req.RemoteAddr)
	}

	return &gotacacs.AcctReply{Status: gotacacs.AcctStatusSuccess}
}
