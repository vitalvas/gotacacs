package gotacacs

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// Integration tests for end-to-end client-server communication

// testIntegrationHandler implements Handler interface for integration testing.
type testIntegrationHandler struct {
	users       map[string]string
	permissions map[string][]string
	mu          sync.RWMutex
}

func newTestIntegrationHandler() *testIntegrationHandler {
	return &testIntegrationHandler{
		users: map[string]string{
			"admin":    "admin123",
			"user":     "user123",
			"readonly": "readonly123",
		},
		permissions: map[string][]string{
			"admin":    {"priv-lvl=15", "role=admin"},
			"user":     {"priv-lvl=7", "role=user"},
			"readonly": {"priv-lvl=1", "role=readonly"},
		},
	}
}

func (h *testIntegrationHandler) HandleAuthenStart(_ context.Context, req *AuthenRequest) *AuthenReply {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if expectedPass, ok := h.users[string(req.Start.User)]; ok && expectedPass == string(req.Start.Data) {
		return &AuthenReply{Status: AuthenStatusPass, ServerMsg: []byte("Authentication successful")}
	}
	return &AuthenReply{Status: AuthenStatusFail, ServerMsg: []byte("Invalid credentials")}
}

func (h *testIntegrationHandler) HandleAuthenContinue(_ context.Context, _ *AuthenContinueRequest) *AuthenReply {
	return &AuthenReply{Status: AuthenStatusPass}
}

func (h *testIntegrationHandler) HandleAuthorRequest(_ context.Context, req *AuthorRequestContext) *AuthorResponse {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if perms, ok := h.permissions[string(req.Request.User)]; ok {
		args := make([][]byte, len(perms))
		for i, p := range perms {
			args[i] = []byte(p)
		}
		return &AuthorResponse{Status: AuthorStatusPassAdd, RawArgs: args}
	}
	return &AuthorResponse{Status: AuthorStatusFail, ServerMsg: []byte("User not authorized")}
}

func (h *testIntegrationHandler) HandleAcctRequest(_ context.Context, req *AcctRequestContext) *AcctReply {
	// Accept all accounting requests
	if req.Request.IsStart() || req.Request.IsStop() || req.Request.IsWatchdog() {
		return &AcctReply{Status: AcctStatusSuccess}
	}
	return &AcctReply{Status: AcctStatusError, ServerMsg: []byte("Unknown accounting type")}
}

func TestIntegrationPAPAuthentication(t *testing.T) {
	t.Run("successful PAP authentication", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("sharedsecret"),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("sharedsecret"))

		reply, err := client.Authenticate(context.Background(), "admin", "admin123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reply.IsPass() {
			t.Errorf("expected true")
		}
		if !strings.Contains(string(reply.ServerMsg), "successful") {
			t.Errorf("expected %q to contain %q", string(reply.ServerMsg), "successful")
		}
	})

	t.Run("failed PAP authentication", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("sharedsecret"),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("sharedsecret"))

		reply, err := client.Authenticate(context.Background(), "admin", "wrongpassword")
		if !errors.Is(err, ErrAuthenticationFailed) {
			t.Fatalf("got %v, want ErrAuthenticationFailed", err)
		}
		if !reply.IsFail() {
			t.Errorf("expected true")
		}
	})

	t.Run("nonexistent user authentication", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("sharedsecret"),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("sharedsecret"))

		reply, err := client.Authenticate(context.Background(), "unknownuser", "anypassword")
		if !errors.Is(err, ErrAuthenticationFailed) {
			t.Fatalf("got %v, want ErrAuthenticationFailed", err)
		}
		if !reply.IsFail() {
			t.Errorf("expected true")
		}
	})
}

func TestIntegrationAuthorization(t *testing.T) {
	t.Run("admin authorization", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("sharedsecret"),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("sharedsecret"))

		resp, err := client.Authorize(context.Background(), "admin", []string{"service=shell", "cmd=configure"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.IsPass() {
			t.Errorf("expected true")
		}

		args := resp.Args()
		found15 := false
		for _, a := range args {
			if a == "priv-lvl=15" {
				found15 = true
				break
			}
		}
		if !found15 {
			t.Errorf("expected %v to contain %q", args, "priv-lvl=15")
		}
		foundAdmin := false
		for _, a := range args {
			if a == "role=admin" {
				foundAdmin = true
				break
			}
		}
		if !foundAdmin {
			t.Errorf("expected %v to contain %q", args, "role=admin")
		}
	})

	t.Run("readonly user authorization", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("sharedsecret"),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("sharedsecret"))

		resp, err := client.Authorize(context.Background(), "readonly", []string{"service=shell"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.IsPass() {
			t.Errorf("expected true")
		}

		args := resp.Args()
		found := false
		for _, a := range args {
			if a == "priv-lvl=1" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %v to contain %q", args, "priv-lvl=1")
		}
	})

	t.Run("unknown user authorization denied", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("sharedsecret"),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("sharedsecret"))

		resp, err := client.Authorize(context.Background(), "unknown", []string{"service=shell"})
		if !errors.Is(err, ErrAuthorizationDenied) {
			t.Fatalf("got %v, want ErrAuthorizationDenied", err)
		}
		if !resp.IsFail() {
			t.Errorf("expected true")
		}
	})
}

func TestIntegrationAccounting(t *testing.T) {
	t.Run("accounting start-stop-watchdog sequence", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("sharedsecret"),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("sharedsecret"))

		// Start
		startReply, err := client.Accounting(context.Background(), AcctFlagStart, "admin", []string{"task_id=12345", "service=shell"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !startReply.IsSuccess() {
			t.Errorf("expected true")
		}

		// Watchdog
		watchdogReply, err := client.Accounting(context.Background(), AcctFlagWatchdog, "admin", []string{"task_id=12345", "bytes_in=1024"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !watchdogReply.IsSuccess() {
			t.Errorf("expected true")
		}

		// Stop
		stopReply, err := client.Accounting(context.Background(), AcctFlagStop, "admin", []string{"task_id=12345", "elapsed_time=120"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !stopReply.IsSuccess() {
			t.Errorf("expected true")
		}
	})
}

func TestIntegrationTLS(t *testing.T) {
	t.Run("TLS encrypted communication", func(t *testing.T) {
		cert, err := generateTestCertificate()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		serverConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

		ln, err := ListenTLS("127.0.0.1:0", serverConfig)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		clientConfig := &tls.Config{InsecureSkipVerify: true}
		client := NewClient(
			WithAddress(ln.Addr().String()),
			WithTLSConfig(clientConfig),
		)

		reply, err := client.Authenticate(context.Background(), "admin", "admin123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reply.IsPass() {
			t.Errorf("expected true")
		}
	})
}

func TestIntegrationSingleConnect(t *testing.T) {
	t.Run("multiple requests on single connection", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("sharedsecret"),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(
			WithAddress(ln.Addr().String()),
			WithSecret("sharedsecret"),
			WithSingleConnect(true),
		)
		defer client.Close()

		// Multiple authentication requests
		for range 5 {
			reply, err := client.Authenticate(context.Background(), "admin", "admin123")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reply.IsPass() {
				t.Errorf("expected true")
			}
		}

		// Authorization request
		resp, err := client.Authorize(context.Background(), "admin", []string{"service=shell"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.IsPass() {
			t.Errorf("expected true")
		}

		// Accounting request
		acctReply, err := client.Accounting(context.Background(), AcctFlagStart, "admin", []string{"task_id=1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !acctReply.IsSuccess() {
			t.Errorf("expected true")
		}
	})
}

func TestIntegrationConcurrentClients(t *testing.T) {
	t.Run("multiple concurrent clients", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("sharedsecret"),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		const numClients = 10
		const requestsPerClient = 5

		var wg sync.WaitGroup
		errors := make(chan error, numClients*requestsPerClient)

		for range numClients {
			wg.Add(1)
			go func() {
				defer wg.Done()
				client := NewClient(WithAddress(ln.Addr().String()), WithSecret("sharedsecret"))

				for range requestsPerClient {
					reply, err := client.Authenticate(context.Background(), "user", "user123")
					if err != nil {
						errors <- err
						return
					}
					if !reply.IsPass() {
						errors <- errTest
						return
					}
				}
			}()
		}

		wg.Wait()
		close(errors)

		for err := range errors {
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		}
	})
}

func TestIntegrationPerClientSecret(t *testing.T) {
	t.Run("different secrets for different clients", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Use a secret provider that returns a static secret
		// (In a real scenario, this would be based on the client address)
		provider := SecretProviderFunc(func(_ context.Context, _ SecretRequest) SecretResponse {
			return SecretResponse{Secret: []byte("clientsecret")}
		})

		server := NewServer(
			WithServerListener(ln),
			WithSecretProvider(provider),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("clientsecret"))

		reply, err := client.Authenticate(context.Background(), "admin", "admin123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reply.IsPass() {
			t.Errorf("expected true")
		}
	})
}

func TestIntegrationUnencryptedMode(t *testing.T) {
	t.Run("communication without obfuscation", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Server without secret (unencrypted mode) must opt in to insecure
		// operation per RFC 8907 Section 10.5.2.
		server := NewServer(
			WithServerListener(ln),
			WithServerAllowInsecure(true),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		// Client without secret
		client := NewClient(WithAddress(ln.Addr().String()))

		reply, err := client.Authenticate(context.Background(), "admin", "admin123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reply.IsPass() {
			t.Errorf("expected true")
		}
	})
}

func TestIntegrationRFC9887TLS13(t *testing.T) {
	t.Run("RFC 9887 TLS 1.3 mode with unencrypted flag", func(t *testing.T) {
		cert, err := generateTestCertificate()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Server using TLS 1.3 config
		serverConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
		}

		ln, err := ListenTLS("127.0.0.1:0", serverConfig)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		// Client using RFC 9887 TLS mode
		clientConfig := &tls.Config{
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
		}

		client := NewClient(
			WithAddress(ln.Addr().String()),
			WithTLSConfig(clientConfig),
			WithSingleConnect(true), // Keep connection open to verify TLS state
		)
		defer client.Close()

		// Verify TLS mode is enabled
		if !client.IsTLSMode() {
			t.Errorf("Client should be in TLS mode")
		}

		// Authentication should work without shared secret (TLS provides encryption)
		reply, err := client.Authenticate(context.Background(), "admin", "admin123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reply.IsPass() {
			t.Errorf("expected true")
		}

		// Verify connection is TLS (now that connection is established)
		if !client.IsTLSConnection() {
			t.Errorf("Connection should be TLS")
		}
	})

	t.Run("RFC 9887 authorization and accounting", func(t *testing.T) {
		cert, err := generateTestCertificate()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		serverConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}

		ln, err := ListenTLS("127.0.0.1:0", serverConfig)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		clientConfig := &tls.Config{
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
		}

		client := NewClient(
			WithAddress(ln.Addr().String()),
			WithTLSConfig(clientConfig),
		)

		// Authorization
		resp, err := client.Authorize(context.Background(), "admin", []string{"service=shell"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.IsPass() {
			t.Errorf("expected true")
		}
		foundPriv := false
		for _, a := range resp.Args() {
			if a == "priv-lvl=15" {
				foundPriv = true
				break
			}
		}
		if !foundPriv {
			t.Errorf("expected %v to contain %q", resp.Args(), "priv-lvl=15")
		}

		// Accounting
		acctReply, err := client.Accounting(context.Background(), AcctFlagStart, "admin", []string{"task_id=1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !acctReply.IsSuccess() {
			t.Errorf("expected true")
		}
	})

	t.Run("RFC 9887 single-connect mode over TLS", func(t *testing.T) {
		cert, err := generateTestCertificate()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		serverConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}

		ln, err := ListenTLS("127.0.0.1:0", serverConfig)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		clientConfig := &tls.Config{
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
		}

		client := NewClient(
			WithAddress(ln.Addr().String()),
			WithTLSConfig(clientConfig),
			WithSingleConnect(true),
		)
		defer client.Close()

		// Multiple requests over single TLS connection
		for i := range 5 {
			reply, err := client.Authenticate(context.Background(), "user", "user123")
			if err != nil {
				t.Fatalf("unexpected error: %v: Request %d should succeed", err, i)
			}
			if !reply.IsPass() {
				t.Errorf("expected true")
			}
		}
	})
}

func TestIntegrationRFC9887BugFixes(t *testing.T) {
	t.Run("WithTLSConfig enforces TLS 1.3 MinVersion", func(t *testing.T) {
		// Bug #1: Verify that WithTLSConfig enforces TLS 1.3
		clientConfig := &tls.Config{
			InsecureSkipVerify: true,
			// Intentionally not setting MinVersion to test enforcement
		}

		client := NewClient(
			WithAddress("localhost:300"),
			WithTLSConfig(clientConfig),
		)

		// The client should have TLS mode enabled
		if !client.IsTLSMode() {
			t.Errorf("expected true")
		}

		// Access the dialer to verify TLS config was modified
		if tlsDialer, ok := client.dialer.(*TLSDialer); ok {
			if tlsDialer.Config.MinVersion != uint16(tls.VersionTLS13) {
				t.Errorf("got %v, want %v: WithTLSConfig should enforce TLS 1.3 MinVersion",
					tlsDialer.Config.MinVersion, uint16(tls.VersionTLS13))
			}
		}
	})

	t.Run("TLS listener rejects TLS 1.2", func(t *testing.T) {
		cert, err := generateTestCertificate()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Server TLS listener enforces TLS 1.3
		serverConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12, // Allow TLS 1.2 at TLS level
		}

		ln, err := ListenTLS("127.0.0.1:0", serverConfig)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		// Client forcing TLS 1.2 should be rejected.
		// Use WithDialer directly to bypass WithTLSConfig's TLS 1.3 enforcement.
		clientConfig := &tls.Config{
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS12, // Force TLS 1.2
			InsecureSkipVerify: true,
		}

		client := NewClient(
			WithAddress(ln.Addr().String()),
			WithDialer(&TLSDialer{Config: clientConfig}),
			WithSecret("test"),
		)

		_, err = client.Authenticate(context.Background(), "admin", "admin123")
		// Should fail because listener enforces TLS 1.3
		if err == nil {
			t.Errorf("expected an error: TLS 1.2 connection should be rejected by TLS 1.3 listener")
		}
	})

	t.Run("TLS listener accepts TLS 1.3", func(t *testing.T) {
		cert, err := generateTestCertificate()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		serverConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}

		ln, err := ListenTLS("127.0.0.1:0", serverConfig)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		// Client using TLS 1.3 should work
		clientConfig := &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
		}

		client := NewClient(
			WithAddress(ln.Addr().String()),
			WithTLSConfig(clientConfig),
		)

		reply, err := client.Authenticate(context.Background(), "admin", "admin123")
		if err != nil {
			t.Fatalf("unexpected error: %v: TLS 1.3 connection should work with TLS 1.3 listener", err)
		}
		if !reply.IsPass() {
			t.Errorf("expected true")
		}
	})
}

func TestIntegrationFullWorkflow(t *testing.T) {
	t.Run("complete AAA workflow", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("sharedsecret"),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("sharedsecret"))

		// 1. Authenticate user
		authenReply, err := client.Authenticate(context.Background(), "user", "user123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !authenReply.IsPass() {
			t.Fatal("Authentication should pass")
		}

		// 2. Authorize user for a service
		authorResp, err := client.Authorize(context.Background(), "user", []string{"service=shell", "cmd=show"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !authorResp.IsPass() {
			t.Fatal("Authorization should pass")
		}

		// Verify privilege level
		args := authorResp.Args()
		found := false
		for _, a := range args {
			if a == "priv-lvl=7" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %v to contain %q", args, "priv-lvl=7")
		}

		// 3. Start accounting for the session
		acctStartReply, err := client.Accounting(context.Background(), AcctFlagStart, "user", []string{
			"task_id=session123",
			"service=shell",
			"start_time=1234567890",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !acctStartReply.IsSuccess() {
			t.Fatal("Accounting start should succeed")
		}

		// 4. Send watchdog update
		acctWatchdogReply, err := client.Accounting(context.Background(), AcctFlagWatchdog, "user", []string{
			"task_id=session123",
			"bytes_in=2048",
			"bytes_out=4096",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !acctWatchdogReply.IsSuccess() {
			t.Fatal("Accounting watchdog should succeed")
		}

		// 5. Stop accounting when session ends
		acctStopReply, err := client.Accounting(context.Background(), AcctFlagStop, "user", []string{
			"task_id=session123",
			"elapsed_time=3600",
			"stop_time=1234571490",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !acctStopReply.IsSuccess() {
			t.Fatal("Accounting stop should succeed")
		}
	})
}
