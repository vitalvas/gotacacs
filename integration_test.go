package gotacacs

import (
	"context"
	"crypto/tls"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		return &AuthorResponse{Status: AuthorStatusPassAdd, Args: args}
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
		require.NoError(t, err)

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("sharedsecret"),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(ln.Addr().String(), WithSecret("sharedsecret"))

		reply, err := client.Authenticate(context.Background(), "admin", "admin123")
		require.NoError(t, err)
		assert.True(t, reply.IsPass())
		assert.Contains(t, string(reply.ServerMsg), "successful")
	})

	t.Run("failed PAP authentication", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("sharedsecret"),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(ln.Addr().String(), WithSecret("sharedsecret"))

		reply, err := client.Authenticate(context.Background(), "admin", "wrongpassword")
		require.NoError(t, err)
		assert.True(t, reply.IsFail())
	})

	t.Run("nonexistent user authentication", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("sharedsecret"),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(ln.Addr().String(), WithSecret("sharedsecret"))

		reply, err := client.Authenticate(context.Background(), "unknownuser", "anypassword")
		require.NoError(t, err)
		assert.True(t, reply.IsFail())
	})
}

func TestIntegrationAuthorization(t *testing.T) {
	t.Run("admin authorization", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("sharedsecret"),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(ln.Addr().String(), WithSecret("sharedsecret"))

		resp, err := client.Authorize(context.Background(), "admin", []string{"service=shell", "cmd=configure"})
		require.NoError(t, err)
		assert.True(t, resp.IsPass())

		args := resp.GetArgs()
		assert.Contains(t, args, "priv-lvl=15")
		assert.Contains(t, args, "role=admin")
	})

	t.Run("readonly user authorization", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("sharedsecret"),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(ln.Addr().String(), WithSecret("sharedsecret"))

		resp, err := client.Authorize(context.Background(), "readonly", []string{"service=shell"})
		require.NoError(t, err)
		assert.True(t, resp.IsPass())

		args := resp.GetArgs()
		assert.Contains(t, args, "priv-lvl=1")
	})

	t.Run("unknown user authorization denied", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("sharedsecret"),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(ln.Addr().String(), WithSecret("sharedsecret"))

		resp, err := client.Authorize(context.Background(), "unknown", []string{"service=shell"})
		require.NoError(t, err)
		assert.True(t, resp.IsFail())
	})
}

func TestIntegrationAccounting(t *testing.T) {
	t.Run("accounting start-stop-watchdog sequence", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("sharedsecret"),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(ln.Addr().String(), WithSecret("sharedsecret"))

		// Start
		startReply, err := client.Accounting(context.Background(), AcctFlagStart, "admin", []string{"task_id=12345", "service=shell"})
		require.NoError(t, err)
		assert.True(t, startReply.IsSuccess())

		// Watchdog
		watchdogReply, err := client.Accounting(context.Background(), AcctFlagWatchdog, "admin", []string{"task_id=12345", "bytes_in=1024"})
		require.NoError(t, err)
		assert.True(t, watchdogReply.IsSuccess())

		// Stop
		stopReply, err := client.Accounting(context.Background(), AcctFlagStop, "admin", []string{"task_id=12345", "elapsed_time=120"})
		require.NoError(t, err)
		assert.True(t, stopReply.IsSuccess())
	})
}

func TestIntegrationTLS(t *testing.T) {
	t.Run("TLS encrypted communication", func(t *testing.T) {
		cert, err := generateTestCertificate()
		require.NoError(t, err)

		serverConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

		ln, err := ListenTLS("127.0.0.1:0", serverConfig)
		require.NoError(t, err)

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("sharedsecret"),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		clientConfig := &tls.Config{InsecureSkipVerify: true}
		client := NewClient(ln.Addr().String(),
			WithSecret("sharedsecret"),
			WithTLSConfig(clientConfig),
		)

		reply, err := client.Authenticate(context.Background(), "admin", "admin123")
		require.NoError(t, err)
		assert.True(t, reply.IsPass())
	})
}

func TestIntegrationSingleConnect(t *testing.T) {
	t.Run("multiple requests on single connection", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("sharedsecret"),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(ln.Addr().String(),
			WithSecret("sharedsecret"),
			WithSingleConnect(true),
		)
		defer client.Close()

		// Multiple authentication requests
		for range 5 {
			reply, err := client.Authenticate(context.Background(), "admin", "admin123")
			require.NoError(t, err)
			assert.True(t, reply.IsPass())
		}

		// Authorization request
		resp, err := client.Authorize(context.Background(), "admin", []string{"service=shell"})
		require.NoError(t, err)
		assert.True(t, resp.IsPass())

		// Accounting request
		acctReply, err := client.Accounting(context.Background(), AcctFlagStart, "admin", []string{"task_id=1"})
		require.NoError(t, err)
		assert.True(t, acctReply.IsSuccess())
	})
}

func TestIntegrationConcurrentClients(t *testing.T) {
	t.Run("multiple concurrent clients", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
				client := NewClient(ln.Addr().String(), WithSecret("sharedsecret"))

				for range requestsPerClient {
					reply, err := client.Authenticate(context.Background(), "user", "user123")
					if err != nil {
						errors <- err
						return
					}
					if !reply.IsPass() {
						errors <- assert.AnError
						return
					}
				}
			}()
		}

		wg.Wait()
		close(errors)

		for err := range errors {
			assert.NoError(t, err)
		}
	})
}

func TestIntegrationPerClientSecret(t *testing.T) {
	t.Run("different secrets for different clients", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

		// Use a secret provider that returns a static secret
		// (In a real scenario, this would be based on the client address)
		provider := StaticSecretProvider([]byte("clientsecret"))

		server := NewServer(
			WithServerListener(ln),
			WithSecretProvider(provider),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(ln.Addr().String(), WithSecret("clientsecret"))

		reply, err := client.Authenticate(context.Background(), "admin", "admin123")
		require.NoError(t, err)
		assert.True(t, reply.IsPass())
	})
}

func TestIntegrationUnencryptedMode(t *testing.T) {
	t.Run("communication without obfuscation", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

		// Server without secret (unencrypted mode)
		server := NewServer(
			WithServerListener(ln),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		// Client without secret
		client := NewClient(ln.Addr().String())

		reply, err := client.Authenticate(context.Background(), "admin", "admin123")
		require.NoError(t, err)
		assert.True(t, reply.IsPass())
	})
}

func TestIntegrationFullWorkflow(t *testing.T) {
	t.Run("complete AAA workflow", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("sharedsecret"),
			WithHandler(newTestIntegrationHandler()),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(ln.Addr().String(), WithSecret("sharedsecret"))

		// 1. Authenticate user
		authenReply, err := client.Authenticate(context.Background(), "user", "user123")
		require.NoError(t, err)
		require.True(t, authenReply.IsPass(), "Authentication should pass")

		// 2. Authorize user for a service
		authorResp, err := client.Authorize(context.Background(), "user", []string{"service=shell", "cmd=show"})
		require.NoError(t, err)
		require.True(t, authorResp.IsPass(), "Authorization should pass")

		// Verify privilege level
		args := authorResp.GetArgs()
		assert.Contains(t, args, "priv-lvl=7")

		// 3. Start accounting for the session
		acctStartReply, err := client.Accounting(context.Background(), AcctFlagStart, "user", []string{
			"task_id=session123",
			"service=shell",
			"start_time=1234567890",
		})
		require.NoError(t, err)
		require.True(t, acctStartReply.IsSuccess(), "Accounting start should succeed")

		// 4. Send watchdog update
		acctWatchdogReply, err := client.Accounting(context.Background(), AcctFlagWatchdog, "user", []string{
			"task_id=session123",
			"bytes_in=2048",
			"bytes_out=4096",
		})
		require.NoError(t, err)
		require.True(t, acctWatchdogReply.IsSuccess(), "Accounting watchdog should succeed")

		// 5. Stop accounting when session ends
		acctStopReply, err := client.Accounting(context.Background(), AcctFlagStop, "user", []string{
			"task_id=session123",
			"elapsed_time=3600",
			"stop_time=1234571490",
		})
		require.NoError(t, err)
		require.True(t, acctStopReply.IsSuccess(), "Accounting stop should succeed")
	})
}
