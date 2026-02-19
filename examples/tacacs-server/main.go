// Package main provides an example TACACS+ server.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vitalvas/gotacacs"
)

func main() {
	addr := flag.String("addr", ":49", "listen address")
	secret := flag.String("secret", "secret", "shared secret")
	flag.Parse()

	users := map[string]string{
		"admin": "admin123",
		"user":  "user123",
	}

	handler := &exampleHandler{users: users}

	listener, err := gotacacs.ListenTCP(*addr)
	if err != nil {
		log.Fatalf("Failed to start listener: %v", err)
	}

	log.Printf("Starting TACACS+ server on %s", *addr)

	secretProvider := gotacacs.SecretProviderFunc(func(_ context.Context, req gotacacs.SecretRequest) gotacacs.SecretResponse {
		return gotacacs.SecretResponse{
			Secret: []byte(*secret),
			UserData: map[string]string{
				"client_ip": req.RemoteAddr.String(),
			},
		}
	})

	server := gotacacs.NewServer(
		gotacacs.WithServerListener(listener),
		gotacacs.WithSecretProvider(secretProvider),
		gotacacs.WithHandler(handler),
		gotacacs.WithServerReadTimeout(30*time.Second),
		gotacacs.WithServerWriteTimeout(30*time.Second),
	)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()

	if err := server.Serve(); err != nil {
		log.Printf("Server error: %v", err)
	}
	log.Println("Server stopped")
}

type exampleHandler struct {
	users map[string]string
}

func (h *exampleHandler) HandleAuthenStart(_ context.Context, req *gotacacs.AuthenRequest) *gotacacs.AuthenReply {
	user := string(req.Start.User)
	password := string(req.Start.Data)

	log.Printf("Authentication: user=%s from=%s userData=%v", user, req.RemoteAddr, req.UserData)

	expectedPass, ok := h.users[user]
	if !ok || password != expectedPass {
		return &gotacacs.AuthenReply{
			Status:    gotacacs.AuthenStatusFail,
			ServerMsg: []byte("Authentication failed"),
		}
	}

	return &gotacacs.AuthenReply{
		Status:    gotacacs.AuthenStatusPass,
		ServerMsg: []byte("Authentication successful"),
	}
}

func (h *exampleHandler) HandleAuthenContinue(_ context.Context, _ *gotacacs.AuthenContinueRequest) *gotacacs.AuthenReply {
	return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusPass}
}

func (h *exampleHandler) HandleAuthorRequest(_ context.Context, req *gotacacs.AuthorRequestContext) *gotacacs.AuthorResponse {
	user := string(req.Request.User)

	log.Printf("Authorization: user=%s args=%v from=%s userData=%v", user, req.Request.GetArgs(), req.RemoteAddr, req.UserData)

	if _, ok := h.users[user]; !ok {
		return &gotacacs.AuthorResponse{
			Status:    gotacacs.AuthorStatusFail,
			ServerMsg: []byte("Unknown user"),
		}
	}

	return &gotacacs.AuthorResponse{
		Status: gotacacs.AuthorStatusPassAdd,
		Args:   [][]byte{[]byte("priv-lvl=15")},
	}
}

func (h *exampleHandler) HandleAcctRequest(_ context.Context, req *gotacacs.AcctRequestContext) *gotacacs.AcctReply {
	user := string(req.Request.User)

	log.Printf("Accounting: user=%s args=%v from=%s userData=%v", user, req.Request.GetArgs(), req.RemoteAddr, req.UserData)

	return &gotacacs.AcctReply{Status: gotacacs.AcctStatusSuccess}
}
