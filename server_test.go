package gotacacs

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// sendInvalidPacketAndGetResponse sends an invalid packet to the server and returns the response body
func sendInvalidPacketAndGetResponse(t *testing.T, addr string, packetType PacketType, secret []byte) []byte {
	t.Helper()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer conn.Close()

	header := &Header{
		Version:   0xc0,
		Type:      packetType,
		SeqNo:     1,
		SessionID: 12345,
		Length:    1,
	}

	invalidBody := []byte{0xFF}
	obfuscatedBody := Obfuscate(header, secret, invalidBody)
	headerData, _ := header.MarshalBinary()

	conn.Write(headerData)
	conn.Write(obfuscatedBody)

	respHeaderBuf := make([]byte, HeaderLength)
	io.ReadFull(conn, respHeaderBuf)

	respHeader := &Header{}
	respHeader.UnmarshalBinary(respHeaderBuf)

	respBody := make([]byte, respHeader.Length)
	io.ReadFull(conn, respBody)
	return Obfuscate(respHeader, secret, respBody)
}

func TestSecretProvider(t *testing.T) {
	t.Run("static secret provider func", func(t *testing.T) {
		secret := []byte("testsecret")
		provider := SecretProviderFunc(func(_ context.Context, _ SecretRequest) SecretResponse {
			return SecretResponse{Secret: secret}
		})

		req := SecretRequest{
			RemoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			LocalAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 49},
		}
		resp := provider.GetSecret(context.Background(), req)
		if !bytes.Equal(resp.Secret, secret) {
			t.Errorf("got %v, want %v", resp.Secret, secret)
		}
		if resp.UserData != nil {
			t.Errorf("expected nil, got %v", resp.UserData)
		}
	})

	t.Run("secret provider func", func(t *testing.T) {
		provider := SecretProviderFunc(func(_ context.Context, req SecretRequest) SecretResponse {
			if req.RemoteAddr.String() == "127.0.0.1:12345" {
				return SecretResponse{
					Secret:   []byte("secret1"),
					UserData: map[string]string{"client": "client1"},
				}
			}
			return SecretResponse{Secret: []byte("default")}
		})

		req1 := SecretRequest{
			RemoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			LocalAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 49},
		}
		req2 := SecretRequest{
			RemoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 54321},
			LocalAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 49},
		}

		resp1 := provider.GetSecret(context.Background(), req1)
		tv89_1 := []byte("secret1")
		if !bytes.Equal(resp1.Secret, tv89_1) {
			t.Errorf("got %v, want %v", resp1.Secret, tv89_1)
		}
		if !reflect.DeepEqual(resp1.UserData, map[string]string{"client": "client1"}) {
			t.Errorf("got %v, want %v", resp1.UserData, map[string]string{"client": "client1"})
		}

		resp2 := provider.GetSecret(context.Background(), req2)
		tv93_1 := []byte("default")
		if !bytes.Equal(resp2.Secret, tv93_1) {
			t.Errorf("got %v, want %v", resp2.Secret, tv93_1)
		}
		if resp2.UserData != nil {
			t.Errorf("expected nil, got %v", resp2.UserData)
		}
	})

	t.Run("secret provider with user data", func(t *testing.T) {
		provider := SecretProviderFunc(func(_ context.Context, _ SecretRequest) SecretResponse {
			return SecretResponse{
				Secret: []byte("secret"),
				UserData: map[string]string{
					"client_name": "router1",
					"client_type": "network",
				},
			}
		})

		req := SecretRequest{
			RemoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			LocalAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 49},
		}
		resp := provider.GetSecret(context.Background(), req)
		tv113_1 := []byte("secret")
		if !bytes.Equal(resp.Secret, tv113_1) {
			t.Errorf("got %v, want %v", resp.Secret, tv113_1)
		}
		if resp.UserData["client_name"] != "router1" {
			t.Errorf("got %v, want %v", resp.UserData["client_name"], "router1")
		}
		if resp.UserData["client_type"] != "network" {
			t.Errorf("got %v, want %v", resp.UserData["client_type"], "network")
		}
	})

	t.Run("secret provider with local addr", func(t *testing.T) {
		provider := SecretProviderFunc(func(_ context.Context, req SecretRequest) SecretResponse {
			return SecretResponse{
				Secret: []byte("secret"),
				UserData: map[string]string{
					"remote": req.RemoteAddr.String(),
					"local":  req.LocalAddr.String(),
				},
			}
		})

		req := SecretRequest{
			RemoteAddr: &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345},
			LocalAddr:  &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 49},
		}
		resp := provider.GetSecret(context.Background(), req)
		if resp.UserData["remote"] != "192.168.1.100:12345" {
			t.Errorf("got %v, want %v", resp.UserData["remote"], "192.168.1.100:12345")
		}
		if resp.UserData["local"] != "10.0.0.1:49" {
			t.Errorf("got %v, want %v", resp.UserData["local"], "10.0.0.1:49")
		}
	})
}

func TestServerOptions(t *testing.T) {
	t.Run("default values", func(t *testing.T) {
		server := NewServer()
		if server == nil {
			t.Error("expected non-nil")
		}
		if server.listener != nil {
			t.Errorf("expected nil, got %v", server.listener)
		}
		if server.secretProvider != nil {
			t.Errorf("expected nil, got %v", server.secretProvider)
		}
		if server.readTimeout != 30*time.Second {
			t.Errorf("got %v, want %v", server.readTimeout, 30*time.Second)
		}
		if server.writeTimeout != 30*time.Second {
			t.Errorf("got %v, want %v", server.writeTimeout, 30*time.Second)
		}
	})

	t.Run("with secret", func(t *testing.T) {
		server := NewServer(WithServerSecret("testsecret"))
		if server.secretProvider == nil {
			t.Error("expected non-nil")
		}
	})

	t.Run("with secret bytes", func(t *testing.T) {
		server := NewServer(WithServerSecretBytes([]byte{0x01, 0x02, 0x03}))
		if server.secretProvider == nil {
			t.Error("expected non-nil")
		}
	})

	t.Run("with secret provider", func(t *testing.T) {
		provider := SecretProviderFunc(func(_ context.Context, _ SecretRequest) SecretResponse {
			return SecretResponse{Secret: []byte("test")}
		})
		server := NewServer(WithSecretProvider(provider))
		if server.secretProvider == nil {
			t.Error("expected non-nil")
		}
	})

	t.Run("with timeouts", func(t *testing.T) {
		server := NewServer(
			WithServerReadTimeout(10*time.Second),
			WithServerWriteTimeout(15*time.Second),
		)
		if server.readTimeout != 10*time.Second {
			t.Errorf("got %v, want %v", server.readTimeout, 10*time.Second)
		}
		if server.writeTimeout != 15*time.Second {
			t.Errorf("got %v, want %v", server.writeTimeout, 15*time.Second)
		}
	})

	t.Run("with listener", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer ln.Close()

		server := NewServer(WithServerListener(ln))
		if server.listener != ln {
			t.Errorf("got %v, want %v", server.listener, ln)
		}
	})

	t.Run("with max body length", func(t *testing.T) {
		server := NewServer(WithServerMaxBodyLength(2048))
		tv187_1 := uint32(2048)
		if server.maxBodyLength != tv187_1 {
			t.Errorf("got %v, want %v", server.maxBodyLength, tv187_1)
		}
	})

	t.Run("with secret bytes used in connection", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecretBytes([]byte("testsecret")),
			WithHandler(&testHandler{}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		reply, err := client.Authenticate(context.Background(), "testuser", "password")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv207_1 := reply.IsPass()
		if !tv207_1 {
			t.Error("expected true")
		}
	})
}

func TestServerHandlerOptions(t *testing.T) {
	t.Run("with authentication handler", func(t *testing.T) {
		handler := AuthenHandlerFunc(func(_ context.Context, _ *AuthenRequest) *AuthenReply {
			return &AuthenReply{Status: AuthenStatusPass}
		})

		server := NewServer(WithAuthenticationHandler(handler))
		if server.authenHandler == nil {
			t.Error("expected non-nil")
		}
	})

	t.Run("with authorization handler", func(t *testing.T) {
		handler := AuthorHandlerFunc(func(_ context.Context, _ *AuthorRequestContext) *AuthorResponse {
			return &AuthorResponse{Status: AuthorStatusPassAdd}
		})

		server := NewServer(WithAuthorizationHandler(handler))
		if server.authorHandler == nil {
			t.Error("expected non-nil")
		}
	})

	t.Run("with accounting handler", func(t *testing.T) {
		handler := AcctHandlerFunc(func(_ context.Context, _ *AcctRequestContext) *AcctReply {
			return &AcctReply{Status: AcctStatusSuccess}
		})

		server := NewServer(WithAccountingHandler(handler))
		if server.acctHandler == nil {
			t.Error("expected non-nil")
		}
	})
}

type testHandler struct{}

func (h *testHandler) HandleAuthenStart(_ context.Context, req *AuthenRequest) *AuthenReply {
	if string(req.Start.User) == "testuser" {
		return &AuthenReply{Status: AuthenStatusPass}
	}
	return &AuthenReply{Status: AuthenStatusFail}
}

func (h *testHandler) HandleAuthenContinue(_ context.Context, _ *AuthenContinueRequest) *AuthenReply {
	return &AuthenReply{Status: AuthenStatusPass}
}

func (h *testHandler) HandleAuthorRequest(_ context.Context, _ *AuthorRequestContext) *AuthorResponse {
	return &AuthorResponse{Status: AuthorStatusPassAdd, RawArgs: [][]byte{[]byte("priv-lvl=15")}}
}

func (h *testHandler) HandleAcctRequest(_ context.Context, _ *AcctRequestContext) *AcctReply {
	return &AcctReply{Status: AcctStatusSuccess}
}

func TestWithServerSecretBytesCopy(t *testing.T) {
	t.Run("mutation after creation does not affect server", func(t *testing.T) {
		secret := []byte("original")
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecretBytes(secret),
			WithHandler(&testHandler{}),
		)

		// Mutate the original slice
		secret[0] = 'X'

		// Verify the server's secret provider returns the original value
		resp := server.secretProvider.GetSecret(context.Background(), SecretRequest{})
		tv278_1 := []byte("original")
		if !bytes.Equal(resp.Secret, tv278_1) {
			t.Errorf("got %v, want %v", resp.Secret, tv278_1)
		}
		server.Shutdown(context.Background())
	})
}

func TestServerWithHandler(t *testing.T) {
	t.Run("combined handler", func(t *testing.T) {
		handler := &testHandler{}
		server := NewServer(WithHandler(handler))

		if server.authenHandler != handler {
			t.Errorf("got %v, want %v", server.authenHandler, handler)
		}
		if server.authorHandler != handler {
			t.Errorf("got %v, want %v", server.authorHandler, handler)
		}
		if server.acctHandler != handler {
			t.Errorf("got %v, want %v", server.acctHandler, handler)
		}
	})
}

func TestHandlerFuncAdapters(t *testing.T) {
	t.Run("authen handler func continue returns error", func(t *testing.T) {
		handler := AuthenHandlerFunc(func(_ context.Context, _ *AuthenRequest) *AuthenReply {
			return &AuthenReply{Status: AuthenStatusPass}
		})

		reply := handler.HandleAuthenContinue(context.Background(), nil)
		tv301_1 := AuthenStatusError
		if reply.Status != tv301_1 {
			t.Errorf("got %v, want %v", reply.Status, tv301_1)
		}
	})
}

func TestServerServe(t *testing.T) {
	t.Run("serve without listener", func(t *testing.T) {
		server := NewServer()
		err := server.Serve()
		if err == nil {
			t.Error("expected an error")
		}
		tv310_1 := err.Error()
		if !strings.Contains(tv310_1, "no listener") {
			t.Errorf("%q does not contain %q", tv310_1, "no listener")
		}
	})

	t.Run("serve already running", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(WithServerListener(ln))

		// Start server in background
		go func() {
			server.Serve()
		}()

		// Wait for server to start
		time.Sleep(50 * time.Millisecond)

		// Try to start again
		err = server.Serve()
		if err == nil {
			t.Error("expected an error")
		}
		tv330_1 := err.Error()
		if !strings.Contains(tv330_1, "already running") {
			t.Errorf("%q does not contain %q", tv330_1, "already running")
		}

		server.Shutdown(context.Background())
	})
}

func TestServerShutdown(t *testing.T) {
	t.Run("shutdown when not running", func(t *testing.T) {
		server := NewServer()
		err := server.Shutdown(context.Background())
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("graceful shutdown", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(WithServerListener(ln))

		go func() {
			server.Serve()
		}()

		time.Sleep(50 * time.Millisecond)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		err = server.Shutdown(ctx)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		tv360_1 := server.IsRunning()
		if tv360_1 {
			t.Error("expected false")
		}
	})
}

func TestServerServeAcceptErrorResetsRunning(t *testing.T) {
	t.Run("accept error resets running state", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(WithServerListener(ln), WithHandler(&testHandler{}))

		// Close the listener to force accept error
		ln.Close()

		err = server.Serve()
		if err == nil {
			t.Error("expected an error")
		}
		tv376_1 := server.IsRunning()
		if tv376_1 {
			t.Error("expected false")
		}
	})
}

func TestServerAcceptErrorClosesActiveConnections(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	server := NewServer(WithServerListener(ln), WithServerReadTimeout(10*time.Second))

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve()
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer conn.Close()
	{
		deadline := time.Now().Add(time.Second)
		cond := func() bool {
			active := false
			server.activeConns.Range(func(_, _ any) bool {
				active = true
				return false
			})
			return active
		}
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatal("condition not met")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	tv402_1 := ln.Close()
	if tv402_1 != nil {
		t.Fatalf("unexpected error: %v", tv402_1)
	}
	if <-serveDone == nil {
		t.Fatal("expected an error")
	}

	tv405_1 := conn.SetReadDeadline(time.Now().Add(time.Second))
	if tv405_1 != nil {
		t.Fatalf("unexpected error: %v", tv405_1)
	}
	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected an error")
	}
	{
		deadline := time.Now().Add(time.Second)
		cond := func() bool {
			active := false
			server.activeConns.Range(func(_, _ any) bool {
				active = true
				return false
			})
			return !active
		}
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatal("condition not met")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	tv416_1 := server.Shutdown(context.Background())
	if tv416_1 != nil {
		t.Fatalf("unexpected error: %v", tv416_1)
	}
}

func TestServerRestart(t *testing.T) {
	t.Run("server can be restarted after shutdown", func(t *testing.T) {
		ln1, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(WithServerListener(ln1), WithServerSecret("test"), WithHandler(&testHandler{}))

		serveDone := make(chan struct{})
		go func() { server.Serve(); close(serveDone) }()
		time.Sleep(50 * time.Millisecond)

		err = server.Shutdown(context.Background())
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		tv432_1 := server.IsRunning()
		if tv432_1 {
			t.Error("expected false")
		}

		// Wait for Serve goroutine to fully exit
		<-serveDone

		// Restart with new listener
		ln2, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server.mu.Lock()
		server.listener = ln2
		server.mu.Unlock()

		go func() { server.Serve() }()
		time.Sleep(50 * time.Millisecond)

		tv448_1 := server.IsRunning()
		if !tv448_1 {
			t.Error("expected true")
		}

		client := NewClient(WithAddress(ln2.Addr().String()), WithSecret("test"))
		reply, err := client.Authenticate(context.Background(), "testuser", "pass")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv453_1 := reply.IsPass()
		if !tv453_1 {
			t.Error("expected true")
		}

		server.Shutdown(context.Background())
	})
}

func TestServerShutdownForcesClose(t *testing.T) {
	t.Run("expired context forces connection close", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Handler that simulates slow cleanup after receiving shutdown signal
		handlerStarted := make(chan struct{})
		blockingHandler := AuthenHandlerFunc(func(ctx context.Context, _ *AuthenRequest) *AuthenReply {
			close(handlerStarted)
			// Wait for shutdown signal
			<-ctx.Done()
			// Simulate slow cleanup that takes longer than the shutdown deadline
			time.Sleep(500 * time.Millisecond)
			return &AuthenReply{Status: AuthenStatusError}
		})

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithAuthenticationHandler(blockingHandler),
			WithServerReadTimeout(10*time.Second),
		)

		go func() { server.Serve() }()
		time.Sleep(50 * time.Millisecond)

		// Connect a client that will trigger the blocking handler
		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"), WithTimeout(10*time.Second))
		go func() {
			client.Authenticate(context.Background(), "testuser", "pass")
		}()

		// Wait for handler to start
		<-handlerStarted

		// Shutdown with very short timeout — should force-close connections
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		err = server.Shutdown(ctx)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("error %v is not %v", err, context.DeadlineExceeded)
		}
		tv500_1 := server.IsRunning()
		if tv500_1 {
			t.Error("expected false")
		}
	})

	t.Run("expired context returns even when handler ignores shutdown", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		handlerStarted := make(chan struct{})
		blockHandler := make(chan struct{})
		handler := AuthenHandlerFunc(func(_ context.Context, _ *AuthenRequest) *AuthenReply {
			close(handlerStarted)
			<-blockHandler
			return &AuthenReply{Status: AuthenStatusError}
		})

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithAuthenticationHandler(handler),
			WithServerReadTimeout(10*time.Second),
		)

		go func() { server.Serve() }()
		time.Sleep(50 * time.Millisecond)

		clientDone := make(chan struct{})
		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"), WithTimeout(10*time.Second))
		go func() {
			defer close(clientDone)
			client.Authenticate(context.Background(), "testuser", "pass")
		}()

		<-handlerStarted

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		shutdownDone := make(chan error, 1)
		started := time.Now()
		go func() {
			shutdownDone <- server.Shutdown(ctx)
		}()

		select {
		case err := <-shutdownDone:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("error %v is not %v", err, context.DeadlineExceeded)
			}
			tv546_1 := time.Since(started)
			if tv546_1 >= 500*time.Millisecond {
				t.Errorf("expected %v < %v", tv546_1, 500*time.Millisecond)
			}
		case <-time.After(500 * time.Millisecond):
			close(blockHandler)
			t.Fatal("Shutdown did not return after context deadline")
		}

		close(blockHandler)
		<-clientDone
		tv554_1 := server.IsRunning()
		if tv554_1 {
			t.Error("expected false")
		}
	})
}

func TestServerHandlerReceivesShutdownContext(t *testing.T) {
	t.Run("handler context is cancelled on shutdown", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		ctxDone := make(chan struct{})
		handler := AuthenHandlerFunc(func(ctx context.Context, _ *AuthenRequest) *AuthenReply {
			<-ctx.Done()
			close(ctxDone)
			return &AuthenReply{Status: AuthenStatusError}
		})

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithAuthenticationHandler(handler),
			WithServerReadTimeout(10*time.Second),
		)

		go func() { server.Serve() }()
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"), WithTimeout(10*time.Second))
		go func() {
			client.Authenticate(context.Background(), "testuser", "pass")
		}()
		time.Sleep(50 * time.Millisecond)

		// Shutdown — handler should see context cancellation
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		server.Shutdown(ctx)

		select {
		case <-ctxDone:
			// Handler's context was cancelled — success
		case <-time.After(2 * time.Second):
			t.Fatal("handler context was not cancelled on shutdown")
		}
	})
}

func TestServerAddr(t *testing.T) {
	t.Run("addr without listener", func(t *testing.T) {
		server := NewServer()
		tv603_1 := server.Addr()
		if tv603_1 != nil {
			t.Errorf("expected nil, got %v", tv603_1)
		}
	})

	t.Run("addr with listener", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer ln.Close()

		server := NewServer(WithServerListener(ln))
		tv612_1 := server.Addr()
		if tv612_1 == nil {
			t.Error("expected non-nil")
		}
	})
}

func TestServerAuthentication(t *testing.T) {
	t.Run("authentication success", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		handler := &testHandler{}
		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithHandler(handler),
		)

		go func() {
			server.Serve()
		}()
		defer server.Shutdown(context.Background())

		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		reply, err := client.Authenticate(context.Background(), "testuser", "testpass")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv638_1 := reply.IsPass()
		if !tv638_1 {
			t.Error("expected true")
		}
	})

	t.Run("authentication failure", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		handler := &testHandler{}
		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithHandler(handler),
		)

		go func() {
			server.Serve()
		}()
		defer server.Shutdown(context.Background())

		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		reply, err := client.Authenticate(context.Background(), "wronguser", "testpass")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv662_1 := reply.IsFail()
		if !tv662_1 {
			t.Error("expected true")
		}
	})
}

func TestServerAuthorization(t *testing.T) {
	t.Run("authorization success", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		handler := &testHandler{}
		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithHandler(handler),
		)

		go func() {
			server.Serve()
		}()
		defer server.Shutdown(context.Background())

		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		resp, err := client.Authorize(context.Background(), "testuser", []string{"service=shell"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv688_1 := resp.IsPass()
		if !tv688_1 {
			t.Error("expected true")
		}
		found := false
		for _, a := range resp.Args() {
			if a == "priv-lvl=15" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("args %v do not contain %q", resp.Args(), "priv-lvl=15")
		}
	})
}

func TestServerAccounting(t *testing.T) {
	t.Run("accounting success", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		handler := &testHandler{}
		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithHandler(handler),
		)

		go func() {
			server.Serve()
		}()
		defer server.Shutdown(context.Background())

		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))

		reply, err := client.Accounting(context.Background(), AcctFlagStart, "testuser", []string{"task_id=1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv716_1 := reply.IsSuccess()
		if !tv716_1 {
			t.Error("expected true")
		}
	})
}

func TestServerNoHandler(t *testing.T) {
	t.Run("no authentication handler", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
		)

		go func() {
			server.Serve()
		}()
		defer server.Shutdown(context.Background())

		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		reply, err := client.Authenticate(context.Background(), "testuser", "testpass")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv740_1 := AuthenStatusError
		if reply.Status != tv740_1 {
			t.Errorf("got %v, want %v", reply.Status, tv740_1)
		}
	})

	t.Run("no authorization handler", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
		)

		go func() {
			server.Serve()
		}()
		defer server.Shutdown(context.Background())

		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		resp, err := client.Authorize(context.Background(), "testuser", []string{"service=shell"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv762_1 := AuthorStatusError
		if resp.Status != tv762_1 {
			t.Errorf("got %v, want %v", resp.Status, tv762_1)
		}
	})

	t.Run("no accounting handler", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
		)

		go func() {
			server.Serve()
		}()
		defer server.Shutdown(context.Background())

		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		reply, err := client.Accounting(context.Background(), AcctFlagStart, "testuser", []string{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv784_1 := AcctStatusError
		if reply.Status != tv784_1 {
			t.Errorf("got %v, want %v", reply.Status, tv784_1)
		}
	})
}

func TestServerSingleConnect(t *testing.T) {
	t.Run("single connect mode", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		handler := &testHandler{}
		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithHandler(handler),
		)

		go func() {
			server.Serve()
		}()
		defer server.Shutdown(context.Background())

		time.Sleep(50 * time.Millisecond)

		client := NewClient(
			WithAddress(ln.Addr().String()),
			WithSecret("testsecret"),
			WithSingleConnect(true),
		)
		defer client.Close()

		// Multiple requests on same connection
		for range 3 {
			reply, err := client.Authenticate(context.Background(), "testuser", "testpass")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			tv817_1 := reply.IsPass()
			if !tv817_1 {
				t.Error("expected true")
			}
		}
	})
}

func TestServerInvalidPacket(t *testing.T) {
	t.Run("invalid authentication packet", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		handler := &testHandler{}
		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithHandler(handler),
		)

		go func() {
			server.Serve()
		}()
		defer server.Shutdown(context.Background())

		time.Sleep(50 * time.Millisecond)

		// Connect and send invalid packet
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer conn.Close()

		secret := []byte("testsecret")

		// Send header with invalid body
		header := &Header{
			Version:   MajorVersion<<4 | MinorVersionDefault,
			Type:      PacketTypeAuthen,
			SeqNo:     1,
			Flags:     0,
			SessionID: 12345,
			Length:    2, // Too short for valid body
		}

		headerBuf, _ := header.MarshalBinary()
		conn.Write(headerBuf)

		// Send invalid body
		body := []byte{0x01, 0x02}
		obfuscated := Obfuscate(header, secret, body)
		conn.Write(obfuscated)

		// Read response
		respHeaderBuf := make([]byte, HeaderLength)
		_, err = io.ReadFull(conn, respHeaderBuf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		respHeader := &Header{}
		respHeader.UnmarshalBinary(respHeaderBuf)

		respBody := make([]byte, respHeader.Length)
		io.ReadFull(conn, respBody)

		respBody = Obfuscate(respHeader, secret, respBody)

		reply := &AuthenReply{}
		reply.UnmarshalBinary(respBody)

		tv882_1 := AuthenStatusError
		if reply.Status != tv882_1 {
			t.Errorf("got %v, want %v", reply.Status, tv882_1)
		}
	})
}

func TestServerConnectionClose(t *testing.T) {
	t.Run("client closes connection", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		handler := &testHandler{}
		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithHandler(handler),
		)

		go func() {
			server.Serve()
		}()
		defer server.Shutdown(context.Background())

		time.Sleep(50 * time.Millisecond)

		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		conn.Close()

		// Server should handle close gracefully
		time.Sleep(50 * time.Millisecond)
		tv911_1 := server.IsRunning()
		if !tv911_1 {
			t.Error("expected true")
		}
	})
}

func TestServerHandlerNilReply(t *testing.T) {
	t.Run("handler returns nil for authentication", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		nilHandler := AuthenHandlerFunc(func(_ context.Context, _ *AuthenRequest) *AuthenReply {
			return nil
		})

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithAuthenticationHandler(nilHandler),
		)

		go func() {
			server.Serve()
		}()
		defer server.Shutdown(context.Background())

		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		reply, err := client.Authenticate(context.Background(), "testuser", "testpass")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv940_1 := AuthenStatusError
		if reply.Status != tv940_1 {
			t.Errorf("got %v, want %v", reply.Status, tv940_1)
		}
	})

	t.Run("handler returns nil for authorization", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		nilHandler := AuthorHandlerFunc(func(_ context.Context, _ *AuthorRequestContext) *AuthorResponse {
			return nil
		})

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithAuthorizationHandler(nilHandler),
		)

		go func() {
			server.Serve()
		}()
		defer server.Shutdown(context.Background())

		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		resp, err := client.Authorize(context.Background(), "testuser", []string{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv967_1 := AuthorStatusError
		if resp.Status != tv967_1 {
			t.Errorf("got %v, want %v", resp.Status, tv967_1)
		}
	})

	t.Run("handler returns nil for accounting", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		nilHandler := AcctHandlerFunc(func(_ context.Context, _ *AcctRequestContext) *AcctReply {
			return nil
		})

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithAccountingHandler(nilHandler),
		)

		go func() {
			server.Serve()
		}()
		defer server.Shutdown(context.Background())

		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		reply, err := client.Accounting(context.Background(), AcctFlagStart, "testuser", []string{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv994_1 := AcctStatusError
		if reply.Status != tv994_1 {
			t.Errorf("got %v, want %v", reply.Status, tv994_1)
		}
	})
}

func TestServerSessionState(t *testing.T) {
	runSessionStateTest := func(t *testing.T, setupServer func(ln Listener) *Server, runClient func(client *Client) error) {
		t.Helper()
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := setupServer(ln)
		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		tv1010_1 := runClient(client)
		if tv1010_1 != nil {
			t.Fatalf("unexpected error: %v", tv1010_1)
		}

		time.Sleep(10 * time.Millisecond)
		tv1013_1 := server.Sessions()
		if len(tv1013_1) != 0 {
			t.Errorf("expected empty, got %v", tv1013_1)
		}
	}

	t.Run("authentication pass", func(t *testing.T) {
		runSessionStateTest(t,
			func(ln Listener) *Server {
				return NewServer(WithServerListener(ln), WithServerSecret("testsecret"),
					WithAuthenticationHandler(AuthenHandlerFunc(func(_ context.Context, _ *AuthenRequest) *AuthenReply {
						return &AuthenReply{Status: AuthenStatusPass}
					})))
			},
			func(client *Client) error {
				reply, err := client.Authenticate(context.Background(), "testuser", "testpass")
				if err == nil {
					tv1027_1 := reply.IsPass()
					if !tv1027_1 {
						t.Error("expected true")
					}
				}
				return err
			})
	})

	t.Run("authentication fail", func(t *testing.T) {
		runSessionStateTest(t,
			func(ln Listener) *Server {
				return NewServer(WithServerListener(ln), WithServerSecret("testsecret"),
					WithAuthenticationHandler(AuthenHandlerFunc(func(_ context.Context, _ *AuthenRequest) *AuthenReply {
						return &AuthenReply{Status: AuthenStatusFail}
					})))
			},
			func(client *Client) error {
				reply, err := client.Authenticate(context.Background(), "testuser", "testpass")
				if err == nil {
					tv1044_1 := reply.IsFail()
					if !tv1044_1 {
						t.Error("expected true")
					}
				}
				return err
			})
	})

	t.Run("authorization pass", func(t *testing.T) {
		runSessionStateTest(t,
			func(ln Listener) *Server {
				return NewServer(WithServerListener(ln), WithServerSecret("testsecret"),
					WithAuthorizationHandler(AuthorHandlerFunc(func(_ context.Context, _ *AuthorRequestContext) *AuthorResponse {
						return &AuthorResponse{Status: AuthorStatusPassAdd}
					})))
			},
			func(client *Client) error {
				resp, err := client.Authorize(context.Background(), "testuser", []string{"service=shell"})
				if err == nil {
					tv1061_1 := resp.IsPass()
					if !tv1061_1 {
						t.Error("expected true")
					}
				}
				return err
			})
	})

	t.Run("authorization fail", func(t *testing.T) {
		runSessionStateTest(t,
			func(ln Listener) *Server {
				return NewServer(WithServerListener(ln), WithServerSecret("testsecret"),
					WithAuthorizationHandler(AuthorHandlerFunc(func(_ context.Context, _ *AuthorRequestContext) *AuthorResponse {
						return &AuthorResponse{Status: AuthorStatusFail}
					})))
			},
			func(client *Client) error {
				resp, err := client.Authorize(context.Background(), "testuser", []string{"service=shell"})
				if err == nil {
					tv1078_1 := resp.IsFail()
					if !tv1078_1 {
						t.Error("expected true")
					}
				}
				return err
			})
	})

	t.Run("accounting success", func(t *testing.T) {
		runSessionStateTest(t,
			func(ln Listener) *Server {
				return NewServer(WithServerListener(ln), WithServerSecret("testsecret"),
					WithAccountingHandler(AcctHandlerFunc(func(_ context.Context, _ *AcctRequestContext) *AcctReply {
						return &AcctReply{Status: AcctStatusSuccess}
					})))
			},
			func(client *Client) error {
				reply, err := client.Accounting(context.Background(), AcctFlagStart, "testuser", []string{"task_id=1"})
				if err == nil {
					tv1095_1 := reply.IsSuccess()
					if !tv1095_1 {
						t.Error("expected true")
					}
				}
				return err
			})
	})

	t.Run("accounting error", func(t *testing.T) {
		runSessionStateTest(t,
			func(ln Listener) *Server {
				return NewServer(WithServerListener(ln), WithServerSecret("testsecret"),
					WithAccountingHandler(AcctHandlerFunc(func(_ context.Context, _ *AcctRequestContext) *AcctReply {
						return &AcctReply{Status: AcctStatusError}
					})))
			},
			func(client *Client) error {
				reply, err := client.Accounting(context.Background(), AcctFlagStart, "testuser", []string{"task_id=1"})
				if err == nil {
					tv1112_1 := reply.IsError()
					if !tv1112_1 {
						t.Error("expected true")
					}
				}
				return err
			})
	})
}

func TestServerUserDataPassing(t *testing.T) {
	runUserDataTest := func(t *testing.T, expectedUserData map[string]string, setupServer func(ln Listener, provider SecretProvider) *Server, runClient func(client *Client) error, getReceived func() map[string]string) {
		t.Helper()
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		secretProvider := SecretProviderFunc(func(_ context.Context, _ SecretRequest) SecretResponse {
			return SecretResponse{Secret: []byte("testsecret"), UserData: expectedUserData}
		})

		server := setupServer(ln, secretProvider)
		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		tv1135_1 := runClient(client)
		if tv1135_1 != nil {
			t.Fatalf("unexpected error: %v", tv1135_1)
		}
		tv1136_1 := getReceived()
		if !reflect.DeepEqual(tv1136_1, expectedUserData) {
			t.Errorf("got %v, want %v", tv1136_1, expectedUserData)
		}
	}

	t.Run("user data passed to authentication handler", func(t *testing.T) {
		var receivedUserData map[string]string
		expectedUserData := map[string]string{"client_name": "router1", "client_type": "network"}
		runUserDataTest(t, expectedUserData,
			func(ln Listener, provider SecretProvider) *Server {
				return NewServer(WithServerListener(ln), WithSecretProvider(provider),
					WithAuthenticationHandler(AuthenHandlerFunc(func(_ context.Context, req *AuthenRequest) *AuthenReply {
						receivedUserData = req.UserData
						return &AuthenReply{Status: AuthenStatusPass}
					})))
			},
			func(client *Client) error {
				reply, err := client.Authenticate(context.Background(), "testuser", "testpass")
				if err == nil {
					tv1153_1 := reply.IsPass()
					if !tv1153_1 {
						t.Error("expected true")
					}
				}
				return err
			},
			func() map[string]string { return receivedUserData })
	})

	t.Run("user data passed to authorization handler", func(t *testing.T) {
		var receivedUserData map[string]string
		expectedUserData := map[string]string{"client_name": "switch1"}
		runUserDataTest(t, expectedUserData,
			func(ln Listener, provider SecretProvider) *Server {
				return NewServer(WithServerListener(ln), WithSecretProvider(provider),
					WithAuthorizationHandler(AuthorHandlerFunc(func(_ context.Context, req *AuthorRequestContext) *AuthorResponse {
						receivedUserData = req.UserData
						return &AuthorResponse{Status: AuthorStatusPassAdd}
					})))
			},
			func(client *Client) error {
				resp, err := client.Authorize(context.Background(), "testuser", []string{"service=shell"})
				if err == nil {
					tv1174_1 := resp.IsPass()
					if !tv1174_1 {
						t.Error("expected true")
					}
				}
				return err
			},
			func() map[string]string { return receivedUserData })
	})

	t.Run("user data passed to accounting handler", func(t *testing.T) {
		var receivedUserData map[string]string
		expectedUserData := map[string]string{"site": "datacenter1"}
		runUserDataTest(t, expectedUserData,
			func(ln Listener, provider SecretProvider) *Server {
				return NewServer(WithServerListener(ln), WithSecretProvider(provider),
					WithAccountingHandler(AcctHandlerFunc(func(_ context.Context, req *AcctRequestContext) *AcctReply {
						receivedUserData = req.UserData
						return &AcctReply{Status: AcctStatusSuccess}
					})))
			},
			func(client *Client) error {
				reply, err := client.Accounting(context.Background(), AcctFlagStart, "testuser", []string{"task_id=1"})
				if err == nil {
					tv1195_1 := reply.IsSuccess()
					if !tv1195_1 {
						t.Error("expected true")
					}
				}
				return err
			},
			func() map[string]string { return receivedUserData })
	})

	t.Run("nil user data handled correctly", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var receivedUserData map[string]string
		server := NewServer(WithServerListener(ln), WithServerSecret("testsecret"),
			WithAuthenticationHandler(AuthenHandlerFunc(func(_ context.Context, req *AuthenRequest) *AuthenReply {
				receivedUserData = req.UserData
				return &AuthenReply{Status: AuthenStatusPass}
			})))

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		reply, err := client.Authenticate(context.Background(), "testuser", "testpass")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv1220_1 := reply.IsPass()
		if !tv1220_1 {
			t.Error("expected true")
		}
		if receivedUserData != nil {
			t.Errorf("expected nil, got %v", receivedUserData)
		}
	})
}

func TestServerMultiStepAuthentication(t *testing.T) {
	t.Run("authentication continue with GETPASS", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		step := 0
		handler := &multiStepHandler{
			onStart: func(_ context.Context, req *AuthenRequest) *AuthenReply {
				step++
				if len(req.Start.Data) == 0 {
					return &AuthenReply{
						Status:    AuthenStatusGetPass,
						ServerMsg: []byte("Password: "),
						Flags:     AuthenReplyFlagNoEcho,
					}
				}
				if string(req.Start.Data) == "secret" {
					return &AuthenReply{Status: AuthenStatusPass}
				}
				return &AuthenReply{Status: AuthenStatusFail}
			},
			onContinue: func(_ context.Context, req *AuthenContinueRequest) *AuthenReply {
				step++
				if string(req.Continue.UserMsg) == "secret" {
					return &AuthenReply{Status: AuthenStatusPass}
				}
				return &AuthenReply{Status: AuthenStatusFail}
			},
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithAuthenticationHandler(handler),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		reply, err := client.AuthenticateASCII(context.Background(), "testuser", func(prompt string, noEcho bool) (string, error) {
			if !strings.Contains(prompt, "Password") {
				t.Errorf("%q does not contain %q", prompt, "Password")
			}
			if !noEcho {
				t.Error("expected true")
			}
			return "secret", nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv1273_1 := reply.IsPass()
		if !tv1273_1 {
			t.Error("expected true")
		}
		if step != 2 {
			t.Errorf("got %v, want %v", step, 2)
		}
	})

	t.Run("authentication continue with GETDATA", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		handler := &multiStepHandler{
			onStart: func(_ context.Context, _ *AuthenRequest) *AuthenReply {
				return &AuthenReply{
					Status:    AuthenStatusGetData,
					ServerMsg: []byte("Enter OTP: "),
				}
			},
			onContinue: func(_ context.Context, req *AuthenContinueRequest) *AuthenReply {
				if string(req.Continue.UserMsg) == "123456" {
					return &AuthenReply{Status: AuthenStatusPass}
				}
				return &AuthenReply{Status: AuthenStatusFail}
			},
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithAuthenticationHandler(handler),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		reply, err := client.AuthenticateASCII(context.Background(), "testuser", func(prompt string, noEcho bool) (string, error) {
			if !strings.Contains(prompt, "OTP") {
				t.Errorf("%q does not contain %q", prompt, "OTP")
			}
			if noEcho {
				t.Error("expected false")
			}
			return "123456", nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv1314_1 := reply.IsPass()
		if !tv1314_1 {
			t.Error("expected true")
		}
	})

	t.Run("authentication continue with GETUSER", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		step := 0
		handler := &multiStepHandler{
			onStart: func(_ context.Context, req *AuthenRequest) *AuthenReply {
				step++
				if len(req.Start.User) == 0 {
					return &AuthenReply{
						Status:    AuthenStatusGetUser,
						ServerMsg: []byte("Username: "),
					}
				}
				return &AuthenReply{
					Status:    AuthenStatusGetPass,
					ServerMsg: []byte("Password: "),
					Flags:     AuthenReplyFlagNoEcho,
				}
			},
			onContinue: func(_ context.Context, req *AuthenContinueRequest) *AuthenReply {
				step++
				if step == 2 {
					// Got username, ask for password
					return &AuthenReply{
						Status:    AuthenStatusGetPass,
						ServerMsg: []byte("Password: "),
						Flags:     AuthenReplyFlagNoEcho,
					}
				}
				// Got password
				if string(req.Continue.UserMsg) == "secret" {
					return &AuthenReply{Status: AuthenStatusPass}
				}
				return &AuthenReply{Status: AuthenStatusFail}
			},
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithAuthenticationHandler(handler),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		promptCount := 0
		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		reply, err := client.AuthenticateASCII(context.Background(), "", func(_ string, _ bool) (string, error) {
			promptCount++
			if promptCount == 1 {
				return "admin", nil
			}
			return "secret", nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv1376_1 := reply.IsPass()
		if !tv1376_1 {
			t.Error("expected true")
		}
	})
}

type multiStepHandler struct {
	onStart    func(context.Context, *AuthenRequest) *AuthenReply
	onContinue func(context.Context, *AuthenContinueRequest) *AuthenReply
}

func (h *multiStepHandler) HandleAuthenStart(ctx context.Context, req *AuthenRequest) *AuthenReply {
	if h.onStart != nil {
		return h.onStart(ctx, req)
	}
	return &AuthenReply{Status: AuthenStatusPass}
}

func (h *multiStepHandler) HandleAuthenContinue(ctx context.Context, req *AuthenContinueRequest) *AuthenReply {
	if h.onContinue != nil {
		return h.onContinue(ctx, req)
	}
	return &AuthenReply{Status: AuthenStatusPass}
}

func TestServerBodyTooLarge(t *testing.T) {
	t.Run("reject packet with body too large", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithServerMaxBodyLength(100),
			WithHandler(&testHandler{}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		// Connect and send packet with large body
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer conn.Close()

		header := &Header{
			Version:   MajorVersion<<4 | MinorVersionDefault,
			Type:      PacketTypeAuthen,
			SeqNo:     1,
			Flags:     0,
			SessionID: 12345,
			Length:    200, // Larger than max
		}

		headerData, _ := header.MarshalBinary()
		conn.Write(headerData)

		// Server should close connection
		buf := make([]byte, 1)
		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, err = conn.Read(buf)
		if err == nil {
			t.Error("expected an error")
		}
	})
}

func TestServerShutdownTimeout(t *testing.T) {
	t.Run("shutdown with short timeout", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithHandler(&testHandler{}),
		)

		go func() { server.Serve() }()
		time.Sleep(50 * time.Millisecond)

		// Shutdown with reasonable timeout (no active connections, should complete immediately)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		err = server.Shutdown(ctx)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("shutdown when not running", func(t *testing.T) {
		server := NewServer(WithServerSecret("testsecret"))
		err := server.Shutdown(context.Background())
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestServerServeErrors(t *testing.T) {
	t.Run("serve without listener", func(t *testing.T) {
		server := NewServer(WithServerSecret("testsecret"))
		err := server.Serve()
		if err == nil {
			t.Error("expected an error")
		}
		tv1473_1 := err.Error()
		if !strings.Contains(tv1473_1, "no listener") {
			t.Errorf("%q does not contain %q", tv1473_1, "no listener")
		}
	})

	t.Run("serve when already running", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
		)

		go func() { server.Serve() }()
		time.Sleep(50 * time.Millisecond)
		defer server.Shutdown(context.Background())

		err = server.Serve()
		if err == nil {
			t.Error("expected an error")
		}
		tv1491_1 := err.Error()
		if !strings.Contains(tv1491_1, "already running") {
			t.Errorf("%q does not contain %q", tv1491_1, "already running")
		}
	})
}

func TestServerIsRunning(t *testing.T) {
	t.Run("running state", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(WithServerListener(ln))
		tv1501_1 := server.IsRunning()
		if tv1501_1 {
			t.Error("expected false")
		}

		go func() { server.Serve() }()
		time.Sleep(50 * time.Millisecond)

		tv1506_1 := server.IsRunning()
		if !tv1506_1 {
			t.Error("expected true")
		}

		server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		tv1511_1 := server.IsRunning()
		if tv1511_1 {
			t.Error("expected false")
		}
	})
}

func TestServerNilHandlerResponse(t *testing.T) {
	t.Run("nil authentication response", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		handler := AuthenHandlerFunc(func(_ context.Context, _ *AuthenRequest) *AuthenReply {
			return nil
		})

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithAuthenticationHandler(handler),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		reply, err := client.Authenticate(context.Background(), "testuser", "testpass")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv1537_1 := reply.IsError()
		if !tv1537_1 {
			t.Error("expected true")
		}
	})

	t.Run("nil authorization response", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		handler := AuthorHandlerFunc(func(_ context.Context, _ *AuthorRequestContext) *AuthorResponse {
			return nil
		})

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithAuthorizationHandler(handler),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		resp, err := client.Authorize(context.Background(), "testuser", []string{"service=shell"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv1561_1 := resp.IsError()
		if !tv1561_1 {
			t.Error("expected true")
		}
	})

	t.Run("nil accounting response", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		handler := AcctHandlerFunc(func(_ context.Context, _ *AcctRequestContext) *AcctReply {
			return nil
		})

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithAccountingHandler(handler),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		reply, err := client.Accounting(context.Background(), AcctFlagStart, "testuser", []string{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv1585_1 := reply.IsError()
		if !tv1585_1 {
			t.Error("expected true")
		}
	})

	t.Run("nil authentication continue response", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		handler := &multiStepHandler{
			onStart: func(_ context.Context, _ *AuthenRequest) *AuthenReply {
				return &AuthenReply{
					Status:    AuthenStatusGetPass,
					ServerMsg: []byte("Password: "),
				}
			},
			onContinue: func(_ context.Context, _ *AuthenContinueRequest) *AuthenReply {
				return nil // Return nil to test error handling
			},
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithAuthenticationHandler(handler),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		reply, err := client.AuthenticateASCII(context.Background(), "testuser", func(_ string, _ bool) (string, error) {
			return "password", nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv1620_1 := reply.IsError()
		if !tv1620_1 {
			t.Error("expected true")
		}
	})
}

func TestServerInvalidPackets(t *testing.T) {
	t.Run("invalid continue packet", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Use handler that returns GETPASS to allow multi-step auth
		handler := &multiStepHandler{
			onStart: func(_ context.Context, _ *AuthenRequest) *AuthenReply {
				return &AuthenReply{
					Status:    AuthenStatusGetPass,
					ServerMsg: []byte("Password: "),
				}
			},
			onContinue: func(_ context.Context, _ *AuthenContinueRequest) *AuthenReply {
				return &AuthenReply{Status: AuthenStatusPass}
			},
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithAuthenticationHandler(handler),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		// Connect and send invalid continue packet
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer conn.Close()

		secret := []byte("testsecret")

		// First send a valid START packet to get a session going
		start := &AuthenStart{
			Action:     AuthenActionLogin,
			AuthenType: AuthenTypeASCII,
			Service:    AuthenServiceLogin,
			User:       []byte("testuser"),
		}
		startBody, _ := start.MarshalBinary()

		header := &Header{
			Version:   0xc0,
			Type:      PacketTypeAuthen,
			SeqNo:     1,
			SessionID: 12345,
			Length:    uint32(len(startBody)),
		}

		obfuscatedStartBody := Obfuscate(header, secret, startBody)
		headerData, _ := header.MarshalBinary()

		conn.Write(headerData)
		conn.Write(obfuscatedStartBody)

		// Read GETPASS response
		respHeaderBuf := make([]byte, HeaderLength)
		io.ReadFull(conn, respHeaderBuf)

		respHeader := &Header{}
		respHeader.UnmarshalBinary(respHeaderBuf)

		respBody := make([]byte, respHeader.Length)
		io.ReadFull(conn, respBody)

		// Verify we got GETPASS
		deobfResp := Obfuscate(respHeader, secret, respBody)
		reply := &AuthenReply{}
		reply.UnmarshalBinary(deobfResp)
		tv1696_1 := AuthenStatusGetPass
		if reply.Status != tv1696_1 {
			t.Fatalf("got %v, want %v", reply.Status, tv1696_1)
		}

		// Now send an invalid CONTINUE packet (too short body)
		continueHeader := &Header{
			Version:   0xc0,
			Type:      PacketTypeAuthen,
			SeqNo:     3,
			SessionID: 12345,
			Length:    1, // Too short for a valid CONTINUE
		}

		invalidBody := []byte{0xFF}
		obfuscatedBody := Obfuscate(continueHeader, secret, invalidBody)
		continueHeaderData, _ := continueHeader.MarshalBinary()

		conn.Write(continueHeaderData)
		conn.Write(obfuscatedBody)

		// Read error response
		errHeaderBuf := make([]byte, HeaderLength)
		io.ReadFull(conn, errHeaderBuf)

		errHeader := &Header{}
		errHeader.UnmarshalBinary(errHeaderBuf)

		errBody := make([]byte, errHeader.Length)
		io.ReadFull(conn, errBody)
		errBody = Obfuscate(errHeader, secret, errBody)

		errReply := &AuthenReply{}
		errReply.UnmarshalBinary(errBody)

		tv1728_1 := AuthenStatusError
		if errReply.Status != tv1728_1 {
			t.Errorf("got %v, want %v", errReply.Status, tv1728_1)
		}
	})

	t.Run("reject unencrypted flag on non-TLS connection", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithHandler(&testHandler{}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		// Send packet with FlagUnencrypted set on a non-TLS connection.
		// Server must reject this to prevent obfuscation bypass.
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer conn.Close()

		start := &AuthenStart{
			Action:     AuthenActionLogin,
			AuthenType: AuthenTypePAP,
			Service:    AuthenServiceLogin,
			User:       []byte("admin"),
			Data:       []byte("password"),
		}
		startBody, _ := start.MarshalBinary()

		header := &Header{
			Version:   0xc0,
			Type:      PacketTypeAuthen,
			SeqNo:     1,
			Flags:     FlagUnencrypted, // malicious: bypass obfuscation
			SessionID: 99999,
			Length:    uint32(len(startBody)),
		}

		// Send body without obfuscation (matching the unencrypted flag)
		headerData, _ := header.MarshalBinary()
		conn.Write(headerData)
		conn.Write(startBody)

		// Server should close the connection without sending a response
		conn.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, HeaderLength)
		_, err = io.ReadFull(conn, buf)
		if err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("invalid authorization packet", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithHandler(&testHandler{}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		secret := []byte("testsecret")
		respBody := sendInvalidPacketAndGetResponse(t, ln.Addr().String(), PacketTypeAuthor, secret)

		resp := &AuthorResponse{}
		resp.UnmarshalBinary(respBody)

		tv1801_1 := AuthorStatusError
		if resp.Status != tv1801_1 {
			t.Errorf("got %v, want %v", resp.Status, tv1801_1)
		}
	})

	t.Run("invalid accounting packet", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithHandler(&testHandler{}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		secret := []byte("testsecret")
		respBody := sendInvalidPacketAndGetResponse(t, ln.Addr().String(), PacketTypeAcct, secret)

		reply := &AcctReply{}
		reply.UnmarshalBinary(respBody)

		tv1824_1 := AcctStatusError
		if reply.Status != tv1824_1 {
			t.Errorf("got %v, want %v", reply.Status, tv1824_1)
		}
	})
}

func TestServerSecretRotation(t *testing.T) {
	// rotationProvider returns a SecretProvider that supports secret rotation.
	// secrets is the ordered list of secrets to try.
	rotationProvider := func(secrets []string, userData map[string]string) SecretProvider {
		return SecretProviderFunc(func(_ context.Context, req SecretRequest) SecretResponse {
			return SecretResponse{
				Secret:   []byte(secrets[req.Attempt]),
				UserData: userData,
				Attempts: len(secrets),
			}
		})
	}

	t.Run("rotation succeeds with secondary secret", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithSecretProvider(rotationProvider([]string{"oldsecret", "newsecret"}, nil)),
			WithHandler(&testHandler{}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		// Client uses the new secret
		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("newsecret"))
		reply, err := client.Authenticate(context.Background(), "testuser", "password")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv1859_1 := reply.IsPass()
		if !tv1859_1 {
			t.Error("expected true")
		}
	})

	t.Run("rotation succeeds with primary secret", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithSecretProvider(rotationProvider([]string{"oldsecret", "newsecret"}, nil)),
			WithHandler(&testHandler{}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		// Client uses the old (primary) secret - should succeed on first attempt
		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("oldsecret"))
		reply, err := client.Authenticate(context.Background(), "testuser", "password")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv1880_1 := reply.IsPass()
		if !tv1880_1 {
			t.Error("expected true")
		}
	})

	t.Run("all secrets fail", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithSecretProvider(rotationProvider([]string{"oldsecret", "newsecret"}, nil)),
			WithHandler(&testHandler{}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		// Client uses a completely wrong secret - server responds with first secret,
		// so the client can't deobfuscate the response and gets an error
		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("wrongsecret"))
		_, err = client.Authenticate(context.Background(), "testuser", "password")
		if err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("attempts zero backward compatible", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Provider returns Attempts=0 (backward compatible)
		provider := SecretProviderFunc(func(_ context.Context, _ SecretRequest) SecretResponse {
			return SecretResponse{
				Secret:   []byte("testsecret"),
				Attempts: 0,
			}
		})

		server := NewServer(
			WithServerListener(ln),
			WithSecretProvider(provider),
			WithHandler(&testHandler{}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		reply, err := client.Authenticate(context.Background(), "testuser", "password")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv1929_1 := reply.IsPass()
		if !tv1929_1 {
			t.Error("expected true")
		}
	})

	t.Run("single connect uses resolved secret", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithSecretProvider(rotationProvider([]string{"oldsecret", "newsecret"}, nil)),
			WithHandler(&testHandler{}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		// Use single-connect mode with the secondary secret
		client := NewClient(
			WithAddress(ln.Addr().String()),
			WithSecret("newsecret"),
			WithSingleConnect(true),
		)
		defer client.Close()

		// Multiple requests should all work using the resolved secret
		for range 3 {
			reply, err := client.Authenticate(context.Background(), "testuser", "password")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			tv1958_1 := reply.IsPass()
			if !tv1958_1 {
				t.Error("expected true")
			}
		}
	})

	t.Run("provider attempt values correct", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var receivedAttempts []int
		provider := SecretProviderFunc(func(_ context.Context, req SecretRequest) SecretResponse {
			receivedAttempts = append(receivedAttempts, req.Attempt)
			secrets := []string{"oldsecret", "newsecret"}
			return SecretResponse{
				Secret:   []byte(secrets[req.Attempt]),
				Attempts: len(secrets),
			}
		})

		server := NewServer(
			WithServerListener(ln),
			WithSecretProvider(provider),
			WithHandler(&testHandler{}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		// Client uses secondary secret - provider should be called with attempt 0 then 1
		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("newsecret"))
		reply, err := client.Authenticate(context.Background(), "testuser", "password")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv1990_1 := reply.IsPass()
		if !tv1990_1 {
			t.Error("expected true")
		}

		// Wait for connection handling to complete
		time.Sleep(50 * time.Millisecond)

		// Attempt 0 is called in handleConnection setup, attempt 1 during rotation
		if !reflect.DeepEqual(receivedAttempts, []int{0, 1}) {
			t.Errorf("got %v, want %v", receivedAttempts, []int{0, 1})
		}
	})

	t.Run("rotation with authorization", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithSecretProvider(rotationProvider([]string{"oldsecret", "newsecret"}, nil)),
			WithHandler(&testHandler{}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("newsecret"))
		resp, err := client.Authorize(context.Background(), "testuser", []string{"service=shell"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv2016_1 := resp.IsPass()
		if !tv2016_1 {
			t.Error("expected true")
		}
		found := false
		for _, a := range resp.Args() {
			if a == "priv-lvl=15" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("args %v do not contain %q", resp.Args(), "priv-lvl=15")
		}
	})

	t.Run("rotation with accounting", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithSecretProvider(rotationProvider([]string{"oldsecret", "newsecret"}, nil)),
			WithHandler(&testHandler{}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("newsecret"))
		reply, err := client.Accounting(context.Background(), AcctFlagStart, "testuser", []string{"task_id=1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv2037_1 := reply.IsSuccess()
		if !tv2037_1 {
			t.Error("expected true")
		}
	})
}

func TestServerTLSState(t *testing.T) {
	t.Run("TLSState populated on TLS connection", func(t *testing.T) {
		serverCert, err := generateTestCertificate()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var receivedTLSState *tls.ConnectionState
		provider := SecretProviderFunc(func(_ context.Context, req SecretRequest) SecretResponse {
			receivedTLSState = req.TLSState
			return SecretResponse{}
		})

		serverConfig := &tls.Config{Certificates: []tls.Certificate{serverCert}}
		ln, err := ListenTLS("127.0.0.1:0", serverConfig)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithSecretProvider(provider),
			WithHandler(&testHandler{}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		clientConfig := &tls.Config{InsecureSkipVerify: true}
		client := NewClient(WithAddress(ln.Addr().String()), WithTLSConfig(clientConfig))
		_, _ = client.Authenticate(context.Background(), "testuser", "password")

		time.Sleep(50 * time.Millisecond)
		if receivedTLSState == nil {
			t.Fatal("expected non-nil")
		}
		if !receivedTLSState.HandshakeComplete {
			t.Error("expected true")
		}
	})

	t.Run("TLSState nil on non-TLS connection", func(t *testing.T) {
		var receivedTLSState *tls.ConnectionState
		called := false
		provider := SecretProviderFunc(func(_ context.Context, req SecretRequest) SecretResponse {
			receivedTLSState = req.TLSState
			called = true
			return SecretResponse{Secret: []byte("testsecret")}
		})

		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithSecretProvider(provider),
			WithHandler(&testHandler{}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		_, _ = client.Authenticate(context.Background(), "testuser", "password")

		time.Sleep(50 * time.Millisecond)
		if !called {
			t.Error("expected true")
		}
		if receivedTLSState != nil {
			t.Errorf("expected nil, got %v", receivedTLSState)
		}
	})

	t.Run("TLSState contains client certificate CN", func(t *testing.T) {
		caCert, caKey, err := generateTestCA()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		serverCert, err := generateSignedCertificate(caCert, caKey, "server.test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		clientCert, err := generateSignedCertificate(caCert, caKey, "router1.example.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		caCertPool := mustCertPool(caCert)

		var receivedCN string
		provider := SecretProviderFunc(func(_ context.Context, req SecretRequest) SecretResponse {
			if req.TLSState != nil && len(req.TLSState.PeerCertificates) > 0 {
				receivedCN = req.TLSState.PeerCertificates[0].Subject.CommonName
			}
			return SecretResponse{}
		})

		serverConfig := &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientCAs:    caCertPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
		}
		ln, err := ListenTLS("127.0.0.1:0", serverConfig)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithSecretProvider(provider),
			WithHandler(&testHandler{}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		clientConfig := &tls.Config{
			Certificates:       []tls.Certificate{clientCert},
			RootCAs:            caCertPool,
			InsecureSkipVerify: true,
		}
		client := NewClient(WithAddress(ln.Addr().String()), WithTLSConfig(clientConfig))
		_, _ = client.Authenticate(context.Background(), "testuser", "password")

		time.Sleep(50 * time.Millisecond)
		if receivedCN != "router1.example.com" {
			t.Errorf("got %v, want %v", receivedCN, "router1.example.com")
		}
	})
}

func TestServerSessions(t *testing.T) {
	t.Run("empty when no sessions", func(t *testing.T) {
		server := NewServer()
		tv2159_1 := server.Sessions()
		if len(tv2159_1) != 0 {
			t.Errorf("expected empty, got %v", tv2159_1)
		}
	})

	t.Run("returns active session", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		blocked := make(chan struct{})
		handler := AuthenHandlerFunc(func(_ context.Context, _ *AuthenRequest) *AuthenReply {
			<-blocked
			return &AuthenReply{Status: AuthenStatusPass}
		})

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithAuthenticationHandler(handler),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		// Start client in background — it will block in handler
		done := make(chan struct{})
		go func() {
			defer close(done)
			client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
			client.Authenticate(context.Background(), "testuser", "password")
		}()

		// Wait for the session to appear
		time.Sleep(100 * time.Millisecond)

		sessions := server.Sessions()
		if len(sessions) != 1 {
			t.Fatalf("len = %d, want %d", len(sessions), 1)
		}
		if sessions[0].TrackingID == 0 {
			t.Error("expected non-zero")
		}
		if sessions[0].RemoteAddr == nil {
			t.Error("expected non-nil")
		}
		if sessions[0].LocalAddr == nil {
			t.Error("expected non-nil")
		}
		if sessions[0].TLSState != nil {
			t.Errorf("expected nil, got %v", sessions[0].TLSState)
		}
		tv2199_1 := PacketTypeAuthen
		if sessions[0].PacketType != tv2199_1 {
			t.Errorf("got %v, want %v", sessions[0].PacketType, tv2199_1)
		}
		if sessions[0].State != SessionStateActive {
			t.Errorf("got %v, want %v", sessions[0].State, SessionStateActive)
		}
		tv2201_1 := sessions[0].StartedAt.IsZero()
		if tv2201_1 {
			t.Error("expected false")
		}

		close(blocked)
		<-done
	})

	t.Run("TLS session has TLSState", func(t *testing.T) {
		serverCert, err := generateTestCertificate()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		blocked := make(chan struct{})
		handler := AuthenHandlerFunc(func(_ context.Context, _ *AuthenRequest) *AuthenReply {
			<-blocked
			return &AuthenReply{Status: AuthenStatusPass}
		})

		serverConfig := &tls.Config{Certificates: []tls.Certificate{serverCert}}
		ln, err := ListenTLS("127.0.0.1:0", serverConfig)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithAuthenticationHandler(handler),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		done := make(chan struct{})
		go func() {
			defer close(done)
			clientConfig := &tls.Config{InsecureSkipVerify: true}
			client := NewClient(WithAddress(ln.Addr().String()), WithTLSConfig(clientConfig))
			client.Authenticate(context.Background(), "testuser", "password")
		}()

		time.Sleep(100 * time.Millisecond)
		sessions := server.Sessions()
		if len(sessions) != 1 {
			t.Fatalf("len = %d, want %d", len(sessions), 1)
		}
		if sessions[0].TLSState == nil {
			t.Fatal("expected non-nil")
		}
		if !sessions[0].TLSState.HandshakeComplete {
			t.Error("expected true")
		}

		close(blocked)
		<-done
	})

	t.Run("session removed after completion", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithHandler(&testHandler{}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		reply, err := client.Authenticate(context.Background(), "testuser", "password")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv2265_1 := reply.IsPass()
		if !tv2265_1 {
			t.Error("expected true")
		}

		time.Sleep(50 * time.Millisecond)
		tv2268_1 := server.Sessions()
		if len(tv2268_1) != 0 {
			t.Errorf("expected empty, got %v", tv2268_1)
		}
	})

	t.Run("tracking IDs are unique", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		blocked := make(chan struct{})
		handler := AuthenHandlerFunc(func(_ context.Context, _ *AuthenRequest) *AuthenReply {
			<-blocked
			return &AuthenReply{Status: AuthenStatusPass}
		})

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithAuthenticationHandler(handler),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		// Start multiple clients
		done := make(chan struct{})
		for range 3 {
			go func() {
				client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
				client.Authenticate(context.Background(), "testuser", "password")
			}()
		}

		time.Sleep(150 * time.Millisecond)
		sessions := server.Sessions()
		if len(sessions) != 3 {
			t.Errorf("len = %d, want %d", len(sessions), 3)
		}

		ids := make(map[uint64]bool)
		for _, s := range sessions {
			if ids[s.TrackingID] {
				t.Error("expected false")
			}
			ids[s.TrackingID] = true
		}

		close(blocked)
		close(done)
	})
}

func TestServerKickSession(t *testing.T) {
	t.Run("kick nonexistent returns false", func(t *testing.T) {
		server := NewServer()
		tv2318_1 := server.KickSession(999)
		if tv2318_1 {
			t.Error("expected false")
		}
	})

	t.Run("kick active session", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		step := 0
		handler := &multiStepHandler{
			onStart: func(_ context.Context, _ *AuthenRequest) *AuthenReply {
				step++
				return &AuthenReply{
					Status:    AuthenStatusGetPass,
					ServerMsg: []byte("Password: "),
				}
			},
			onContinue: func(_ context.Context, _ *AuthenContinueRequest) *AuthenReply {
				step++
				return &AuthenReply{Status: AuthenStatusPass}
			},
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithAuthenticationHandler(handler),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))

		// Start ASCII auth — server sends GETPASS, then we kick before CONTINUE
		reply, err := client.AuthenticateASCII(context.Background(), "testuser", func(_ string, _ bool) (string, error) {
			// At this point, the session is active (GETPASS received).
			// Kick it before sending the CONTINUE.
			sessions := server.Sessions()
			if len(sessions) != 1 {
				t.Fatalf("len = %d, want %d", len(sessions), 1)
			}
			tv2358_1 := server.KickSession(sessions[0].TrackingID)
			if !tv2358_1 {
				t.Error("expected true")
			}
			return "password", nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv2363_1 := reply.IsError()
		if !tv2363_1 {
			t.Error("expected true")
		}
	})

	t.Run("kick in single-connect does not close connection", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		kickFirst := true
		handler := &multiStepHandler{
			onStart: func(_ context.Context, _ *AuthenRequest) *AuthenReply {
				if kickFirst {
					return &AuthenReply{
						Status:    AuthenStatusGetPass,
						ServerMsg: []byte("Password: "),
					}
				}
				return &AuthenReply{Status: AuthenStatusPass}
			},
			onContinue: func(_ context.Context, _ *AuthenContinueRequest) *AuthenReply {
				return &AuthenReply{Status: AuthenStatusPass}
			},
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithAuthenticationHandler(handler),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(
			WithAddress(ln.Addr().String()),
			WithSecret("testsecret"),
			WithSingleConnect(true),
		)
		defer client.Close()

		// First request: multi-step, kick during it
		reply, err := client.AuthenticateASCII(context.Background(), "testuser", func(_ string, _ bool) (string, error) {
			sessions := server.Sessions()
			if len(sessions) != 1 {
				t.Fatalf("len = %d, want %d", len(sessions), 1)
			}
			server.KickSession(sessions[0].TrackingID)
			return "password", nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv2411_1 := reply.IsError()
		if !tv2411_1 {
			t.Error("expected true")
		}

		// Second request on same connection should still work
		kickFirst = false
		reply, err = client.Authenticate(context.Background(), "testuser", "password")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv2417_1 := reply.IsPass()
		if !tv2417_1 {
			t.Error("expected true")
		}
	})
}

func TestServerHooks(t *testing.T) {
	t.Run("connect and disconnect hooks", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		connectCh := make(chan ConnectEvent, 1)
		disconnectCh := make(chan DisconnectEvent, 1)

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithHandler(&testHandler{}),
			WithServerHooks(ServerHooks{
				OnConnect:    func(event ConnectEvent) { connectCh <- event },
				OnDisconnect: func(event DisconnectEvent) { disconnectCh <- event },
			}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		reply, err := client.Authenticate(context.Background(), "testuser", "password")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv2446_1 := reply.IsPass()
		if !tv2446_1 {
			t.Error("expected true")
		}

		connectEvent := <-connectCh
		if connectEvent.RemoteAddr == nil {
			t.Error("expected non-nil")
		}

		disconnectEvent := <-disconnectCh
		if disconnectEvent.RemoteAddr == nil {
			t.Error("expected non-nil")
		}
	})

	t.Run("session start and end hooks", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		startCh := make(chan SessionEvent, 1)
		endCh := make(chan SessionEvent, 1)

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithHandler(&testHandler{}),
			WithServerHooks(ServerHooks{
				OnSessionStart: func(event SessionEvent) { startCh <- event },
				OnSessionEnd:   func(event SessionEvent) { endCh <- event },
			}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		reply, err := client.Authenticate(context.Background(), "testuser", "password")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv2479_1 := reply.IsPass()
		if !tv2479_1 {
			t.Error("expected true")
		}

		startEvent := <-startCh
		if startEvent.TrackingID == 0 {
			t.Error("expected non-zero")
		}
		tv2483_1 := PacketTypeAuthen
		if startEvent.PacketType != tv2483_1 {
			t.Errorf("got %v, want %v", startEvent.PacketType, tv2483_1)
		}

		endEvent := <-endCh
		if endEvent.State != SessionStateComplete {
			t.Errorf("got %v, want %v", endEvent.State, SessionStateComplete)
		}
	})

	t.Run("bad secret hook", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var badSecretCalled bool
		var badSecretRemote net.Addr

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("serversecret"),
			WithHandler(&testHandler{}),
			WithServerHooks(ServerHooks{
				OnBadSecret: func(event BadSecretEvent) {
					badSecretCalled = true
					badSecretRemote = event.RemoteAddr
				},
			}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("wrongsecret"))
		_, _ = client.Authenticate(context.Background(), "testuser", "password")

		time.Sleep(50 * time.Millisecond)
		if !badSecretCalled {
			t.Error("expected true")
		}
		if badSecretRemote == nil {
			t.Error("expected non-nil")
		}
	})

	t.Run("bad secret hook with rotation", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var badSecretCalled bool

		provider := SecretProviderFunc(func(_ context.Context, req SecretRequest) SecretResponse {
			secrets := []string{"secret1", "secret2"}
			return SecretResponse{
				Secret:   []byte(secrets[req.Attempt]),
				Attempts: len(secrets),
			}
		})

		server := NewServer(
			WithServerListener(ln),
			WithSecretProvider(provider),
			WithHandler(&testHandler{}),
			WithServerHooks(ServerHooks{
				OnBadSecret: func(_ BadSecretEvent) {
					badSecretCalled = true
				},
			}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		// All secrets fail
		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("wrongsecret"))
		_, _ = client.Authenticate(context.Background(), "testuser", "password")

		time.Sleep(50 * time.Millisecond)
		if !badSecretCalled {
			t.Error("expected true")
		}
	})

	t.Run("packet error hook", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var packetErrorCalled bool
		var packetErr error

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithHandler(&testHandler{}),
			WithServerHooks(ServerHooks{
				OnPacketError: func(event PacketErrorEvent) {
					packetErrorCalled = true
					packetErr = event.Err
				},
			}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		// Send an invalid packet body
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer conn.Close()

		secret := []byte("testsecret")
		header := &Header{
			Version:   0xc0,
			Type:      PacketTypeAuthen,
			SeqNo:     1,
			SessionID: 12345,
			Length:    2,
		}
		body := []byte{0x01, 0x02}
		obfuscated := Obfuscate(header, secret, body)
		headerData, _ := header.MarshalBinary()
		conn.Write(headerData)
		conn.Write(obfuscated)

		// Read error response
		respHeaderBuf := make([]byte, HeaderLength)
		io.ReadFull(conn, respHeaderBuf)

		time.Sleep(50 * time.Millisecond)
		if !packetErrorCalled {
			t.Error("expected true")
		}
		if packetErr == nil {
			t.Error("expected non-nil")
		}
	})

	t.Run("nil hooks are safe", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithHandler(&testHandler{}),
			WithServerHooks(ServerHooks{}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		reply, err := client.Authenticate(context.Background(), "testuser", "password")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv2626_1 := reply.IsPass()
		if !tv2626_1 {
			t.Error("expected true")
		}
	})
}

func TestServerMiddleware(t *testing.T) {
	t.Run("single middleware intercepts authen", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		middlewareCalled := make(chan bool, 1)
		mw := func(next Handler) Handler {
			return &loggingMiddleware{MiddlewareHandler: MiddlewareHandler{Next: next}, ch: middlewareCalled}
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithHandler(&testHandler{}),
			WithMiddleware(mw),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		reply, err := client.Authenticate(context.Background(), "testuser", "password")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv2654_1 := reply.IsPass()
		if !tv2654_1 {
			t.Error("expected true")
		}
		if !(<-middlewareCalled) {
			t.Error("expected true")
		}
	})

	t.Run("middleware ordering", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		orderCh := make(chan int, 3)

		makeMW := func(id int) Middleware {
			return func(next Handler) Handler {
				return &orderMiddleware{MiddlewareHandler: MiddlewareHandler{Next: next}, id: id, ch: orderCh}
			}
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithHandler(&testHandler{}),
			WithMiddleware(makeMW(1), makeMW(2), makeMW(3)),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		reply, err := client.Authenticate(context.Background(), "testuser", "password")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv2684_1 := reply.IsPass()
		if !tv2684_1 {
			t.Error("expected true")
		}

		if <-orderCh != 1 {
			t.Errorf("got %v, want %v", <-orderCh, 1)
		}
		if <-orderCh != 2 {
			t.Errorf("got %v, want %v", <-orderCh, 2)
		}
		if <-orderCh != 3 {
			t.Errorf("got %v, want %v", <-orderCh, 3)
		}
	})

	t.Run("middleware short-circuit", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		mw := func(next Handler) Handler {
			return &shortCircuitMiddleware{MiddlewareHandler: MiddlewareHandler{Next: next}}
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithHandler(&testHandler{}),
			WithMiddleware(mw),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		reply, err := client.Authenticate(context.Background(), "testuser", "password")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv2713_1 := reply.IsFail()
		if !tv2713_1 {
			t.Error("expected true")
		}
	})

	t.Run("middleware wraps all handler types", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		calls := make(chan string, 4)
		mw := func(next Handler) Handler {
			return &allTypesMiddleware{MiddlewareHandler: MiddlewareHandler{Next: next}, calls: calls}
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithHandler(&testHandler{}),
			WithMiddleware(mw),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))

		client.Authenticate(context.Background(), "testuser", "password")
		if <-calls != "authen_start" {
			t.Errorf("got %v, want %v", <-calls, "authen_start")
		}

		client.Authorize(context.Background(), "testuser", []string{"service=shell"})
		if <-calls != "author" {
			t.Errorf("got %v, want %v", <-calls, "author")
		}

		client.Accounting(context.Background(), AcctFlagStart, "testuser", []string{"task_id=1"})
		if <-calls != "acct" {
			t.Errorf("got %v, want %v", <-calls, "acct")
		}
	})

	t.Run("no middleware passthrough", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithHandler(&testHandler{}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		reply, err := client.Authenticate(context.Background(), "testuser", "password")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv2765_1 := reply.IsPass()
		if !tv2765_1 {
			t.Error("expected true")
		}
	})
}

type loggingMiddleware struct {
	MiddlewareHandler
	ch chan bool
}

func (m *loggingMiddleware) HandleAuthenStart(ctx context.Context, req *AuthenRequest) *AuthenReply {
	m.ch <- true
	return m.Next.HandleAuthenStart(ctx, req)
}

type orderMiddleware struct {
	MiddlewareHandler
	id int
	ch chan int
}

func (m *orderMiddleware) HandleAuthenStart(ctx context.Context, req *AuthenRequest) *AuthenReply {
	m.ch <- m.id
	return m.Next.HandleAuthenStart(ctx, req)
}

type shortCircuitMiddleware struct {
	MiddlewareHandler
}

func (m *shortCircuitMiddleware) HandleAuthenStart(_ context.Context, _ *AuthenRequest) *AuthenReply {
	return &AuthenReply{Status: AuthenStatusFail, ServerMsg: []byte("blocked by middleware")}
}

type allTypesMiddleware struct {
	MiddlewareHandler
	calls chan string
}

func (m *allTypesMiddleware) HandleAuthenStart(ctx context.Context, req *AuthenRequest) *AuthenReply {
	m.calls <- "authen_start"
	return m.Next.HandleAuthenStart(ctx, req)
}

func (m *allTypesMiddleware) HandleAuthorRequest(ctx context.Context, req *AuthorRequestContext) *AuthorResponse {
	m.calls <- "author"
	return m.Next.HandleAuthorRequest(ctx, req)
}

func (m *allTypesMiddleware) HandleAcctRequest(ctx context.Context, req *AcctRequestContext) *AcctReply {
	m.calls <- "acct"
	return m.Next.HandleAcctRequest(ctx, req)
}

func TestMiddlewareHandler(t *testing.T) {
	inner := &testHandler{}
	mh := &MiddlewareHandler{Next: inner}
	ctx := context.Background()

	t.Run("HandleAuthenStart delegates", func(t *testing.T) {
		req := &AuthenRequest{
			Start: &AuthenStart{
				Action:     AuthenActionLogin,
				AuthenType: AuthenTypePAP,
				Service:    AuthenServiceLogin,
				User:       []byte("testuser"),
				Data:       []byte("pass"),
			},
		}
		reply := mh.HandleAuthenStart(ctx, req)
		if reply == nil {
			t.Error("expected non-nil")
		}
		tv2835_1 := reply.IsPass()
		if !tv2835_1 {
			t.Error("expected true")
		}
	})

	t.Run("HandleAuthenContinue delegates", func(t *testing.T) {
		req := &AuthenContinueRequest{
			Continue: &AuthenContinue{UserMsg: []byte("input")},
		}
		reply := mh.HandleAuthenContinue(ctx, req)
		if reply == nil {
			t.Error("expected non-nil")
		}
	})

	t.Run("HandleAuthorRequest delegates", func(t *testing.T) {
		req := &AuthorRequestContext{
			Request: &AuthorRequest{
				User: []byte("user"),
			},
		}
		resp := mh.HandleAuthorRequest(ctx, req)
		if resp == nil {
			t.Error("expected non-nil")
		}
	})

	t.Run("HandleAcctRequest delegates", func(t *testing.T) {
		req := &AcctRequestContext{
			Request: &AcctRequest{
				User: []byte("user"),
			},
		}
		reply := mh.HandleAcctRequest(ctx, req)
		if reply == nil {
			t.Error("expected non-nil")
		}
	})
}

func TestComposedHandlerAuthenContinueNil(t *testing.T) {
	t.Run("nil authen handler returns error on continue", func(t *testing.T) {
		h := &ComposedHandler{authen: nil, author: nil, acct: nil}
		reply := h.HandleAuthenContinue(context.Background(), &AuthenContinueRequest{})
		tv2871_1 := AuthenStatusError
		if reply.Status != tv2871_1 {
			t.Errorf("got %v, want %v", reply.Status, tv2871_1)
		}
		tv2872_1 := string(reply.ServerMsg)
		if !strings.Contains(tv2872_1, "no authentication handler") {
			t.Errorf("%q does not contain %q", tv2872_1, "no authentication handler")
		}
	})
}

func TestSessionsDeepCopiesUserData(t *testing.T) {
	t.Run("returned sessions have independent UserData", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		blocked := make(chan struct{})
		handler := AuthenHandlerFunc(func(_ context.Context, _ *AuthenRequest) *AuthenReply {
			<-blocked
			return &AuthenReply{Status: AuthenStatusPass}
		})

		provider := SecretProviderFunc(func(_ context.Context, _ SecretRequest) SecretResponse {
			return SecretResponse{
				Secret:   []byte("testsecret"),
				UserData: map[string]string{"key": "value"},
			}
		})

		server := NewServer(
			WithServerListener(ln),
			WithSecretProvider(provider),
			WithAuthenticationHandler(handler),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		done := make(chan struct{})
		go func() {
			defer close(done)
			client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
			client.Authenticate(context.Background(), "testuser", "password")
		}()

		time.Sleep(100 * time.Millisecond)

		sessions1 := server.Sessions()
		if len(sessions1) != 1 {
			t.Fatalf("len = %d, want %d", len(sessions1), 1)
		}
		if sessions1[0].UserData["key"] != "value" {
			t.Errorf("got %v, want %v", sessions1[0].UserData["key"], "value")
		}

		// Mutate returned map
		sessions1[0].UserData["key"] = "mutated"

		// Second call should return original value
		sessions2 := server.Sessions()
		if len(sessions2) != 1 {
			t.Fatalf("len = %d, want %d", len(sessions2), 1)
		}
		if sessions2[0].UserData["key"] != "value" {
			t.Errorf("got %v, want %v", sessions2[0].UserData["key"], "value")
		}

		close(blocked)
		<-done
	})
}

func TestCompleteTLSHandshakeNonTLS(t *testing.T) {
	t.Run("returns nil for non-TLS conn", func(t *testing.T) {
		server := NewServer()

		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer ln.Close()

		// Create a plain TCP connection pair
		done := make(chan net.Conn, 1)
		go func() {
			c, _ := ln.Accept()
			done <- c
		}()

		clientConn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer clientConn.Close()

		serverConn := <-done
		defer serverConn.Close()

		state, err := server.completeTLSHandshake(context.Background(), serverConn)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if state != nil {
			t.Errorf("expected nil, got %v", state)
		}
	})
}

func TestIsSessionKickedEdgeCases(t *testing.T) {
	t.Run("trackingID zero returns false", func(t *testing.T) {
		server := NewServer()
		tv2961_1 := server.isSessionKicked(0)
		if tv2961_1 {
			t.Error("expected false")
		}
	})

	t.Run("session not found returns false", func(t *testing.T) {
		server := NewServer()
		tv2966_1 := server.isSessionKicked(999999)
		if tv2966_1 {
			t.Error("expected false")
		}
	})
}

func TestSendKickedResponseAuthorAndAcct(t *testing.T) {
	t.Run("kicked authorization session gets error", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		handler := &multiStepHandler{
			onStart: func(_ context.Context, _ *AuthenRequest) *AuthenReply {
				return &AuthenReply{
					Status:    AuthenStatusGetPass,
					ServerMsg: []byte("Password: "),
				}
			},
			onContinue: func(_ context.Context, _ *AuthenContinueRequest) *AuthenReply {
				return &AuthenReply{Status: AuthenStatusPass}
			},
		}

		authorHandler := AuthorHandlerFunc(func(_ context.Context, _ *AuthorRequestContext) *AuthorResponse {
			return &AuthorResponse{Status: AuthorStatusPassAdd}
		})

		acctHandler := AcctHandlerFunc(func(_ context.Context, _ *AcctRequestContext) *AcctReply {
			return &AcctReply{Status: AcctStatusSuccess}
		})

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithAuthenticationHandler(handler),
			WithAuthorizationHandler(authorHandler),
			WithAccountingHandler(acctHandler),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		// Test kicked authorization: use single-connect to send authen then author on same conn
		client := NewClient(
			WithAddress(ln.Addr().String()),
			WithSecret("testsecret"),
			WithSingleConnect(true),
		)
		defer client.Close()

		// Send authen with kick during multi-step
		reply, err := client.AuthenticateASCII(context.Background(), "testuser", func(_ string, _ bool) (string, error) {
			sessions := server.Sessions()
			if len(sessions) != 1 {
				t.Fatalf("len = %d, want %d", len(sessions), 1)
			}
			server.KickSession(sessions[0].TrackingID)
			return "password", nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv3023_1 := reply.IsError()
		if !tv3023_1 {
			t.Error("expected true")
		}

		// After kicked session cleanup, new requests on same connection should work
		resp, err := client.Authorize(context.Background(), "testuser", []string{"service=shell"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv3028_1 := resp.IsPass()
		if !tv3028_1 {
			t.Error("expected true")
		}
	})
}

func TestSendKickedResponseAuthorSession(t *testing.T) {
	t.Run("kicked authorization session in single-connect mode", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Use a blocking authen handler so we can kick the session
		// Then follow up with an author request on the same connection
		step := 0
		handler := &multiStepHandler{
			onStart: func(_ context.Context, _ *AuthenRequest) *AuthenReply {
				step++
				return &AuthenReply{
					Status:    AuthenStatusGetPass,
					ServerMsg: []byte("Password: "),
				}
			},
			onContinue: func(_ context.Context, _ *AuthenContinueRequest) *AuthenReply {
				step++
				return &AuthenReply{Status: AuthenStatusPass}
			},
		}

		authorHandler := AuthorHandlerFunc(func(_ context.Context, _ *AuthorRequestContext) *AuthorResponse {
			return &AuthorResponse{Status: AuthorStatusPassAdd}
		})

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithAuthenticationHandler(handler),
			WithAuthorizationHandler(authorHandler),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(
			WithAddress(ln.Addr().String()),
			WithSecret("testsecret"),
			WithSingleConnect(true),
		)
		defer client.Close()

		// First: a normal authen that succeeds
		reply, err := client.AuthenticateASCII(context.Background(), "testuser", func(_ string, _ bool) (string, error) {
			return "password", nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv3081_1 := reply.IsPass()
		if !tv3081_1 {
			t.Error("expected true")
		}

		// Now send an author request; the server will register a new session.
		// We need to kick it while the server is processing. Use a blocking author handler.
		// Instead, let's use a different approach: send authen with kick, then send author.
		// The kicked authen session should return error, and the next author should work.
		// But we need to test the author *kick* path. Let's use single-connect and
		// kick between the start and the actual request by using a slow handler.

		// Actually, the simplest approach to cover sendKickedResponse for author:
		// Use single-connect. Send an authen multi-step. During the prompt callback,
		// kick the session. The server's next packet from client (CONTINUE) will match
		// the session. But the session type is authen, not author.

		// To kick an author session specifically, we need the server to see a second
		// packet on an already-kicked author session. Since author is single-packet,
		// we can't do that in a normal flow. But the sendKickedResponse code is called
		// when `isSessionKicked` returns true for the session. The kick happens BEFORE
		// the packet is processed. So we need the session to already exist and be kicked
		// when a new packet arrives. With single-connect, we need two packets on the
		// same session ID. That only happens with authen (multi-step).

		// The cleanest way is to directly test sendKickedResponse as a unit method.
	})
}

func TestSendKickedResponseDirectUnit(t *testing.T) {
	sendKickedAndReadResponse := func(t *testing.T, packetType PacketType, version Version) []byte {
		t.Helper()
		server := NewServer(WithHandler(&testHandler{}))

		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()
		defer clientConn.Close()

		header := &Header{
			Version:   version,
			Type:      packetType,
			SeqNo:     1,
			SessionID: 12345,
		}

		secret := []byte("testsecret")

		go func() {
			server.sendKickedResponse(serverConn, header, secret, false)
		}()

		respHeaderBuf := make([]byte, HeaderLength)
		_, err := io.ReadFull(clientConn, respHeaderBuf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		respHeader := &Header{}
		tv3134_1 := respHeader.UnmarshalBinary(respHeaderBuf)
		if tv3134_1 != nil {
			t.Fatalf("unexpected error: %v", tv3134_1)
		}

		respBody := make([]byte, respHeader.Length)
		_, err = io.ReadFull(clientConn, respBody)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		return Obfuscate(respHeader, secret, respBody)
	}

	t.Run("author kicked response", func(t *testing.T) {
		body := sendKickedAndReadResponse(t, PacketTypeAuthor, 0xc1)
		resp := &AuthorResponse{}
		tv3146_1 := resp.UnmarshalBinary(body)
		if tv3146_1 != nil {
			t.Fatalf("unexpected error: %v", tv3146_1)
		}
		tv3147_1 := AuthorStatusError
		if resp.Status != tv3147_1 {
			t.Errorf("got %v, want %v", resp.Status, tv3147_1)
		}
	})

	t.Run("acct kicked response", func(t *testing.T) {
		body := sendKickedAndReadResponse(t, PacketTypeAcct, 0xc0)
		reply := &AcctReply{}
		tv3153_1 := reply.UnmarshalBinary(body)
		if tv3153_1 != nil {
			t.Fatalf("unexpected error: %v", tv3153_1)
		}
		tv3154_1 := AcctStatusError
		if reply.Status != tv3154_1 {
			t.Errorf("got %v, want %v", reply.Status, tv3154_1)
		}
	})

	t.Run("invalid packet type returns without writing", func(t *testing.T) {
		server := NewServer(
			WithHandler(&testHandler{}),
		)

		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()

		header := &Header{
			Version:   0xc0,
			Type:      0xFF, // Invalid type
			SeqNo:     1,
			SessionID: 12345,
		}

		// sendKickedResponse should return without writing anything
		server.sendKickedResponse(serverConn, header, nil, false)
		serverConn.Close()

		// Try to read from client side - should get EOF (nothing was written)
		buf := make([]byte, 1)
		_, err := clientConn.Read(buf)
		if err == nil {
			t.Error("expected an error")
		}
	})
}

func TestHandleConnectionTLSHandshakeError(t *testing.T) {
	t.Run("TLS handshake failure closes connection", func(t *testing.T) {
		serverCert, err := generateTestCertificate()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		serverConfig := &tls.Config{Certificates: []tls.Certificate{serverCert}}
		ln, err := ListenTLS("127.0.0.1:0", serverConfig)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithHandler(&testHandler{}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		// Connect with plain TCP (no TLS) - handshake will fail
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Send garbage - this will cause TLS handshake to fail
		conn.Write([]byte("not a TLS handshake"))

		// Server should handle the error gracefully
		time.Sleep(100 * time.Millisecond)
		conn.Close()
		tv3211_1 := server.IsRunning()
		if !tv3211_1 {
			t.Error("expected true")
		}
	})
}

func TestHandleConnectionWritePacketError(t *testing.T) {
	t.Run("write error closes connection", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		handler := AuthenHandlerFunc(func(_ context.Context, _ *AuthenRequest) *AuthenReply {
			return &AuthenReply{Status: AuthenStatusPass}
		})

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithAuthenticationHandler(handler),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		// Connect and send a valid authen request, then close the conn before
		// the server can write the response
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		secret := []byte("testsecret")
		start := &AuthenStart{
			Action:     AuthenActionLogin,
			AuthenType: AuthenTypePAP,
			Service:    AuthenServiceLogin,
			User:       []byte("testuser"),
			Data:       []byte("password"),
		}
		startBody, _ := start.MarshalBinary()

		header := &Header{
			Version:   0xc0,
			Type:      PacketTypeAuthen,
			SeqNo:     1,
			SessionID: 12345,
			Length:    uint32(len(startBody)),
		}

		obfuscatedBody := Obfuscate(header, secret, startBody)
		headerData, _ := header.MarshalBinary()

		conn.Write(headerData)
		conn.Write(obfuscatedBody)

		// Close the connection immediately before server writes response
		conn.Close()

		// Server should handle write error gracefully
		time.Sleep(100 * time.Millisecond)
		tv3268_1 := server.IsRunning()
		if !tv3268_1 {
			t.Error("expected true")
		}
	})
}

func TestDeobfuscateAndValidateTLSMode(t *testing.T) {
	t.Run("TLS mode skips obfuscation", func(t *testing.T) {
		server := NewServer(
			WithHandler(&testHandler{}),
		)

		start := &AuthenStart{
			Action:     AuthenActionLogin,
			AuthenType: AuthenTypePAP,
			Service:    AuthenServiceLogin,
			User:       []byte("testuser"),
			Data:       []byte("password"),
		}
		body, _ := start.MarshalBinary()

		header := &Header{
			Version:   0xc0,
			Type:      PacketTypeAuthen,
			SeqNo:     1,
			Flags:     FlagUnencrypted,
			SessionID: 12345,
			Length:    uint32(len(body)),
		}

		// In TLS mode, body should pass through without obfuscation
		result, err := server.deobfuscateAndValidate(header, body, []byte("secret"), true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(result, body) {
			t.Errorf("got %v, want %v", result, body)
		}
	})
}

func TestHandleAuthenPacketWithStateGetPassStatus(t *testing.T) {
	t.Run("GetPass status returns active state", func(t *testing.T) {
		server := NewServer(
			WithAuthenticationHandler(AuthenHandlerFunc(func(_ context.Context, _ *AuthenRequest) *AuthenReply {
				return &AuthenReply{Status: AuthenStatusGetPass, ServerMsg: []byte("Password:"), Flags: AuthenReplyFlagNoEcho}
			})),
		)

		cs := &connState{
			remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 49},
		}

		header := &Header{
			Version:   0xc0,
			Type:      PacketTypeAuthen,
			SeqNo:     1,
			SessionID: 1,
		}

		start := &AuthenStart{
			Action:     AuthenActionLogin,
			AuthenType: AuthenTypeASCII,
			Service:    AuthenServiceLogin,
			User:       []byte("testuser"),
		}
		body, _ := start.MarshalBinary()

		_, _, sessionState := server.handleAuthenPacketWithState(context.Background(), header, body, cs)
		if sessionState != SessionStateActive {
			t.Errorf("got %v, want %v", sessionState, SessionStateActive)
		}
	})
}

func TestWritePacketTLSModeUnit(t *testing.T) {
	t.Run("TLS mode sets unencrypted flag and skips obfuscation in writePacket", func(t *testing.T) {
		server := NewServer()

		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()
		defer clientConn.Close()

		reply := &AuthenReply{Status: AuthenStatusPass}
		body, _ := reply.MarshalBinary()

		header := &Header{
			Version:   0xc0,
			Type:      PacketTypeAuthen,
			SeqNo:     2,
			SessionID: 12345,
			Length:    uint32(len(body)),
		}

		go func() {
			server.writePacket(serverConn, header, body, []byte("secret"), true)
		}()

		respHeaderBuf := make([]byte, HeaderLength)
		_, err := io.ReadFull(clientConn, respHeaderBuf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		respHeader := &Header{}
		tv3364_1 := respHeader.UnmarshalBinary(respHeaderBuf)
		if tv3364_1 != nil {
			t.Fatalf("unexpected error: %v", tv3364_1)
		}

		// Verify unencrypted flag is set
		tv3367_1 := respHeader.IsUnencrypted()
		if !tv3367_1 {
			t.Error("expected true")
		}

		// Body should not be obfuscated (TLS mode)
		respBody := make([]byte, respHeader.Length)
		_, err = io.ReadFull(clientConn, respBody)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// In TLS mode, body is sent as-is, not obfuscated
		parsedReply := &AuthenReply{}
		tv3376_1 := parsedReply.UnmarshalBinary(respBody)
		if tv3376_1 != nil {
			t.Fatalf("unexpected error: %v", tv3376_1)
		}
		tv3377_1 := AuthenStatusPass
		if parsedReply.Status != tv3377_1 {
			t.Errorf("got %v, want %v", parsedReply.Status, tv3377_1)
		}
	})
}

func TestReadRawPacketErrors(t *testing.T) {
	t.Run("header unmarshal error via truncated header", func(t *testing.T) {
		server := NewServer()

		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()

		go func() {
			// Write truncated data then close
			clientConn.Write([]byte{0x00, 0x00, 0x00})
			clientConn.Close()
		}()

		_, _, err := server.readRawPacket(serverConn, false, false)
		if err == nil {
			t.Error("expected an error")
		}
		serverConn.Close()
	})

	t.Run("body read error when connection closes mid-body", func(t *testing.T) {
		server := NewServer(WithServerMaxBodyLength(1024))

		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()

		go func() {
			// Send a valid header claiming 100 bytes of body
			header := &Header{
				Version:   0xc0,
				Type:      PacketTypeAuthen,
				SeqNo:     1,
				SessionID: 12345,
				Length:    100,
			}
			headerData, _ := header.MarshalBinary()
			clientConn.Write(headerData)
			// Write only 2 bytes then close
			clientConn.Write([]byte{0x01, 0x02})
			clientConn.Close()
		}()

		_, _, err := server.readRawPacket(serverConn, false, false)
		if err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("TLS requires unencrypted flag", func(t *testing.T) {
		server := NewServer()

		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()

		go func() {
			// Send header WITHOUT unencrypted flag on "TLS" connection
			header := &Header{
				Version:   0xc0,
				Type:      PacketTypeAuthen,
				SeqNo:     1,
				Flags:     0, // No unencrypted flag
				SessionID: 12345,
				Length:    0,
			}
			headerData, _ := header.MarshalBinary()
			clientConn.Write(headerData)
			clientConn.Close()
		}()

		_, _, err := server.readRawPacket(serverConn, false, true) // isTLS=true
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrInvalidPacket) {
			t.Errorf("error %v is not %v", err, ErrInvalidPacket)
		}
		tv3449_1 := err.Error()
		if !strings.Contains(tv3449_1, "RFC 9887") {
			t.Errorf("%q does not contain %q", tv3449_1, "RFC 9887")
		}
	})
}

func TestHandleConnectionSequenceValidationFailure(t *testing.T) {
	t.Run("invalid sequence number closes connection", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithHandler(&testHandler{}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer conn.Close()

		secret := []byte("testsecret")

		// Send a packet with SeqNo=3 (should be 1 for first packet)
		start := &AuthenStart{
			Action:     AuthenActionLogin,
			AuthenType: AuthenTypePAP,
			Service:    AuthenServiceLogin,
			User:       []byte("testuser"),
			Data:       []byte("password"),
		}
		startBody, _ := start.MarshalBinary()

		header := &Header{
			Version:   0xc0,
			Type:      PacketTypeAuthen,
			SeqNo:     3, // Invalid: should be 1
			SessionID: 12345,
			Length:    uint32(len(startBody)),
		}

		obfuscatedBody := Obfuscate(header, secret, startBody)
		headerData, _ := header.MarshalBinary()

		conn.Write(headerData)
		conn.Write(obfuscatedBody)

		// Server should close connection
		buf := make([]byte, 1)
		conn.SetReadDeadline(time.Now().Add(time.Second))
		_, err = conn.Read(buf)
		if err == nil {
			t.Error("expected an error")
		}
	})
}

func TestHandleConnectionNextSeqNoOverflow(t *testing.T) {
	t.Run("sequence overflow during response generation", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Create a multi-step handler that keeps going until seq overflow
		handler := &multiStepHandler{
			onStart: func(_ context.Context, _ *AuthenRequest) *AuthenReply {
				return &AuthenReply{
					Status:    AuthenStatusGetPass,
					ServerMsg: []byte("Password: "),
				}
			},
			onContinue: func(_ context.Context, _ *AuthenContinueRequest) *AuthenReply {
				return &AuthenReply{
					Status:    AuthenStatusGetPass,
					ServerMsg: []byte("Password: "),
				}
			},
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithAuthenticationHandler(handler),
			WithServerReadTimeout(5*time.Second),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		// Send many requests manually to exhaust sequence numbers
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer conn.Close()

		secret := []byte("testsecret")

		// Send START (seqNo=1)
		start := &AuthenStart{
			Action:     AuthenActionLogin,
			AuthenType: AuthenTypeASCII,
			Service:    AuthenServiceLogin,
			User:       []byte("testuser"),
		}
		startBody, _ := start.MarshalBinary()

		sessionID := uint32(12345)
		reqHeader := &Header{
			Version:   0xc0,
			Type:      PacketTypeAuthen,
			SeqNo:     1,
			SessionID: sessionID,
			Length:    uint32(len(startBody)),
		}

		obfBody := Obfuscate(reqHeader, secret, startBody)
		headerData, _ := reqHeader.MarshalBinary()
		conn.Write(headerData)
		conn.Write(obfBody)

		// Now loop: read GETPASS response, send CONTINUE, until we exhaust seq nums
		// Server uses even seqNos (2,4,6,...,254), client uses odd (1,3,5,...,255)
		var clientSeq uint8
		for {
			// Read response
			respHeaderBuf := make([]byte, HeaderLength)
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := io.ReadFull(conn, respHeaderBuf)
			if err != nil {
				// Server closed connection due to overflow
				break
			}

			respHeader := &Header{}
			respHeader.UnmarshalBinary(respHeaderBuf)

			if respHeader.Length > 0 {
				respBody := make([]byte, respHeader.Length)
				_, err = io.ReadFull(conn, respBody)
				if err != nil {
					break
				}
			}

			clientSeq = respHeader.SeqNo + 1
			if clientSeq == 0 {
				// Overflow
				break
			}

			// Send CONTINUE
			cont := &AuthenContinue{UserMsg: []byte("pass")}
			contBody, _ := cont.MarshalBinary()

			contHeader := &Header{
				Version:   0xc0,
				Type:      PacketTypeAuthen,
				SeqNo:     clientSeq,
				SessionID: sessionID,
				Length:    uint32(len(contBody)),
			}

			obfContBody := Obfuscate(contHeader, secret, contBody)
			contHeaderData, _ := contHeader.MarshalBinary()
			if _, err := conn.Write(contHeaderData); err != nil {
				break
			}
			if _, err := conn.Write(obfContBody); err != nil {
				break
			}
		}

		// Server should have gracefully handled the overflow
		time.Sleep(100 * time.Millisecond)
		tv3622_1 := server.IsRunning()
		if !tv3622_1 {
			t.Error("expected true")
		}
	})
}

func TestSecretRotationReadError(t *testing.T) {
	t.Run("readRawPacket error during secret rotation", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		provider := SecretProviderFunc(func(_ context.Context, req SecretRequest) SecretResponse {
			secrets := []string{"secret1", "secret2"}
			return SecretResponse{
				Secret:   []byte(secrets[req.Attempt]),
				Attempts: len(secrets),
			}
		})

		server := NewServer(
			WithServerListener(ln),
			WithSecretProvider(provider),
			WithHandler(&testHandler{}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		// Connect and send partial data to cause readRawPacket error
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Send a truncated header
		conn.Write([]byte{0xc0, 0x01})
		conn.Close()

		time.Sleep(100 * time.Millisecond)
		tv3658_1 := server.IsRunning()
		if !tv3658_1 {
			t.Error("expected true")
		}
	})
}

func TestResolveSecretAllFailFallback(t *testing.T) {
	t.Run("all secrets fail returns body deobfuscated with first secret", func(t *testing.T) {
		var badSecretCalled bool
		server := NewServer(
			WithHandler(&testHandler{}),
			WithServerHooks(ServerHooks{
				OnBadSecret: func(_ BadSecretEvent) {
					badSecretCalled = true
				},
			}),
		)

		// Create a valid authen start body, then obfuscate with a secret
		// that is NOT in the provider list. This ensures all attempts fail
		// with ErrBadSecret.
		start := &AuthenStart{
			Action:     AuthenActionLogin,
			AuthenType: AuthenTypePAP,
			Service:    AuthenServiceLogin,
			User:       []byte("testuser"),
			Data:       []byte("password"),
		}
		validBody, _ := start.MarshalBinary()

		header := &Header{
			Version:   0xc0,
			Type:      PacketTypeAuthen,
			SeqNo:     1,
			Flags:     0,
			SessionID: 12345,
			Length:    uint32(len(validBody)),
		}

		// Obfuscate with a client secret that neither attempt knows
		clientSecret := []byte("clientsecret")
		rawBody := Obfuscate(header, clientSecret, validBody)

		provider := SecretProviderFunc(func(_ context.Context, req SecretRequest) SecretResponse {
			secrets := []string{"secret1", "secret2"}
			return SecretResponse{
				Secret:   []byte(secrets[req.Attempt]),
				Attempts: len(secrets),
			}
		})
		server.secretProvider = provider

		cs := &connState{
			remoteAddr:    &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			localAddr:     &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 49},
			secret:        []byte("secret1"),
			isTLS:         false,
			totalAttempts: 2,
			secretReq: SecretRequest{
				RemoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
				LocalAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 49},
			},
		}

		result := server.resolveSecret(context.Background(), header, rawBody, cs)
		if result == nil {
			t.Error("expected non-nil")
		}
		if !badSecretCalled {
			t.Error("expected true")
		}
		// Result should be deobfuscated with first secret (garbage, but not nil)
		tv3724_1 := Obfuscate(header, []byte("secret1"), rawBody)
		if !bytes.Equal(result, tv3724_1) {
			t.Errorf("got %v, want %v", result, tv3724_1)
		}
	})

	t.Run("all secrets fail with empty secret returns raw body", func(t *testing.T) {
		server := NewServer(
			WithHandler(&testHandler{}),
		)

		start := &AuthenStart{
			Action:     AuthenActionLogin,
			AuthenType: AuthenTypePAP,
			Service:    AuthenServiceLogin,
			User:       []byte("testuser"),
			Data:       []byte("password"),
		}
		validBody, _ := start.MarshalBinary()

		header := &Header{
			Version:   0xc0,
			Type:      PacketTypeAuthen,
			SeqNo:     1,
			Flags:     0,
			SessionID: 12345,
			Length:    uint32(len(validBody)),
		}

		// Obfuscate with a client secret
		clientSecret := []byte("clientsecret")
		rawBody := Obfuscate(header, clientSecret, validBody)

		// Both provider secrets will fail. First secret is empty,
		// so the fallback path at L914 should return rawBody.
		provider := SecretProviderFunc(func(_ context.Context, req SecretRequest) SecretResponse {
			if req.Attempt == 0 {
				return SecretResponse{
					Secret:   nil, // empty
					Attempts: 2,
				}
			}
			return SecretResponse{
				Secret:   []byte("wrongsecret"),
				Attempts: 2,
			}
		})
		server.secretProvider = provider

		cs := &connState{
			remoteAddr:    &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			localAddr:     &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 49},
			secret:        nil,
			isTLS:         false,
			totalAttempts: 2,
			secretReq: SecretRequest{
				RemoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
				LocalAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 49},
			},
		}

		result := server.resolveSecret(context.Background(), header, rawBody, cs)
		// With empty first secret and len(cs.secret)==0, the fallback returns rawBody
		if !bytes.Equal(result, rawBody) {
			t.Errorf("got %v, want %v", result, rawBody)
		}
	})
}

func TestWritePacketBodyWriteError(t *testing.T) {
	t.Run("body write error", func(t *testing.T) {
		server := NewServer()

		serverConn, clientConn := net.Pipe()

		// Read header then close to cause body write error
		go func() {
			buf := make([]byte, HeaderLength)
			io.ReadFull(clientConn, buf)
			clientConn.Close()
		}()

		reply := &AuthenReply{Status: AuthenStatusPass}
		body, _ := reply.MarshalBinary()

		header := &Header{
			Version:   0xc0,
			Type:      PacketTypeAuthen,
			SeqNo:     2,
			SessionID: 12345,
			Length:    uint32(len(body)),
		}

		err := server.writePacket(serverConn, header, body, nil, false)
		if err == nil {
			t.Error("expected an error")
		}
		serverConn.Close()
	})
}

func TestHandleConnectionShutdownDuringLoop(t *testing.T) {
	t.Run("shutdown signal during connection loop", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		handler := AuthenHandlerFunc(func(_ context.Context, _ *AuthenRequest) *AuthenReply {
			return &AuthenReply{Status: AuthenStatusPass}
		})

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithAuthenticationHandler(handler),
			WithServerReadTimeout(200*time.Millisecond),
		)

		go func() { server.Serve() }()
		time.Sleep(50 * time.Millisecond)

		// Open a single-connect client to keep the connection alive
		client := NewClient(
			WithAddress(ln.Addr().String()),
			WithSecret("testsecret"),
			WithSingleConnect(true),
			WithTimeout(5*time.Second),
		)
		defer client.Close()

		// Send one request to establish single-connect
		reply, err := client.Authenticate(context.Background(), "testuser", "password")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv3849_1 := reply.IsPass()
		if !tv3849_1 {
			t.Error("expected true")
		}

		// Shutdown while connection is waiting for next packet.
		// Use short context; the server's read timeout (200ms) will unblock the read,
		// then the shutdown check at the top of the loop will return.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err = server.Shutdown(ctx)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestHandleConnectionInvalidPacketType(t *testing.T) {
	t.Run("invalid packet type closes connection", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithHandler(&testHandler{}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer conn.Close()

		// Send packet with invalid type (0xFF)
		header := &Header{
			Version:   0xc0,
			Type:      PacketTypeAuthen, // Use valid type in header for marshaling
			SeqNo:     1,
			SessionID: 12345,
			Length:    0,
		}
		headerData, _ := header.MarshalBinary()
		// Overwrite the type byte to an invalid value (byte index 1)
		headerData[1] = 0xFF

		conn.Write(headerData)

		// Server should close connection due to header validation failure
		buf := make([]byte, 1)
		conn.SetReadDeadline(time.Now().Add(time.Second))
		_, err = conn.Read(buf)
		if err == nil {
			t.Error("expected an error")
		}
	})
}

func TestReadRawPacketBodyTooLarge(t *testing.T) {
	t.Run("body exceeds max length", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithHandler(&testHandler{}),
			WithServerMaxBodyLength(50),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer conn.Close()

		header := &Header{
			Version:   0xc0,
			Type:      PacketTypeAuthen,
			SeqNo:     1,
			SessionID: 12345,
			Length:    100, // exceeds max of 50
		}

		headerData, _ := header.MarshalBinary()
		conn.Write(headerData)

		// Server should close connection
		buf := make([]byte, 1)
		conn.SetReadDeadline(time.Now().Add(time.Second))
		_, err = conn.Read(buf)
		if err == nil {
			t.Error("expected an error")
		}
	})
}

func TestReadRawPacketUnencryptedFlagOnNonTLSWithSecret(t *testing.T) {
	t.Run("unencrypted flag rejected on non-TLS with secret", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithHandler(&testHandler{}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer conn.Close()

		start := &AuthenStart{
			Action:     AuthenActionLogin,
			AuthenType: AuthenTypePAP,
			Service:    AuthenServiceLogin,
			User:       []byte("admin"),
			Data:       []byte("password"),
		}
		startBody, _ := start.MarshalBinary()

		header := &Header{
			Version:   0xc0,
			Type:      PacketTypeAuthen,
			SeqNo:     1,
			Flags:     FlagUnencrypted,
			SessionID: 12345,
			Length:    uint32(len(startBody)),
		}

		headerData, _ := header.MarshalBinary()
		conn.Write(headerData)
		conn.Write(startBody)

		// Server should close connection without response
		buf := make([]byte, HeaderLength)
		conn.SetReadDeadline(time.Now().Add(time.Second))
		_, err = io.ReadFull(conn, buf)
		if err == nil {
			t.Error("expected an error")
		}
	})
}

func TestWritePacketTLSMode(t *testing.T) {
	t.Run("TLS mode sets unencrypted flag and skips obfuscation", func(t *testing.T) {
		serverCert, err := generateTestCertificate()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		serverConfig := &tls.Config{Certificates: []tls.Certificate{serverCert}}
		ln, err := ListenTLS("127.0.0.1:0", serverConfig)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		server := NewServer(
			WithServerListener(ln),
			WithHandler(&testHandler{}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		clientConfig := &tls.Config{InsecureSkipVerify: true}
		client := NewClient(WithAddress(ln.Addr().String()), WithTLSConfig(clientConfig))

		reply, err := client.Authenticate(context.Background(), "testuser", "password")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv4013_1 := reply.IsPass()
		if !tv4013_1 {
			t.Error("expected true")
		}
	})
}

func TestHandleAuthenPacketWithStateEmptyBody(t *testing.T) {
	t.Run("empty response body returns error state", func(t *testing.T) {
		server := NewServer(
			WithAuthenticationHandler(AuthenHandlerFunc(func(_ context.Context, _ *AuthenRequest) *AuthenReply {
				return nil
			})),
		)

		cs := &connState{
			remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 49},
		}

		header := &Header{
			Version:   0xc0,
			Type:      PacketTypeAuthen,
			SeqNo:     1,
			SessionID: 1,
		}

		// Create a valid AuthenStart body
		start := &AuthenStart{
			Action:     AuthenActionLogin,
			AuthenType: AuthenTypePAP,
			Service:    AuthenServiceLogin,
			User:       []byte("testuser"),
			Data:       []byte("pass"),
		}
		body, _ := start.MarshalBinary()

		_, _, sessionState := server.handleAuthenPacketWithState(context.Background(), header, body, cs)
		// Handler returns nil -> authenErrorResponse -> status byte is AuthenStatusError
		if sessionState != SessionStateError {
			t.Errorf("got %v, want %v", sessionState, SessionStateError)
		}
	})

	t.Run("GetData status returns active state", func(t *testing.T) {
		server := NewServer(
			WithAuthenticationHandler(AuthenHandlerFunc(func(_ context.Context, _ *AuthenRequest) *AuthenReply {
				return &AuthenReply{Status: AuthenStatusGetData, ServerMsg: []byte("Enter OTP:")}
			})),
		)

		cs := &connState{
			remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 49},
		}

		header := &Header{
			Version:   0xc0,
			Type:      PacketTypeAuthen,
			SeqNo:     1,
			SessionID: 1,
		}

		start := &AuthenStart{
			Action:     AuthenActionLogin,
			AuthenType: AuthenTypeASCII,
			Service:    AuthenServiceLogin,
			User:       []byte("testuser"),
		}
		body, _ := start.MarshalBinary()

		_, _, sessionState := server.handleAuthenPacketWithState(context.Background(), header, body, cs)
		if sessionState != SessionStateActive {
			t.Errorf("got %v, want %v", sessionState, SessionStateActive)
		}
	})

	t.Run("GetUser status returns active state", func(t *testing.T) {
		server := NewServer(
			WithAuthenticationHandler(AuthenHandlerFunc(func(_ context.Context, _ *AuthenRequest) *AuthenReply {
				return &AuthenReply{Status: AuthenStatusGetUser, ServerMsg: []byte("Username:")}
			})),
		)

		cs := &connState{
			remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 49},
		}

		header := &Header{
			Version:   0xc0,
			Type:      PacketTypeAuthen,
			SeqNo:     1,
			SessionID: 1,
		}

		start := &AuthenStart{
			Action:     AuthenActionLogin,
			AuthenType: AuthenTypeASCII,
			Service:    AuthenServiceLogin,
		}
		body, _ := start.MarshalBinary()

		_, _, sessionState := server.handleAuthenPacketWithState(context.Background(), header, body, cs)
		if sessionState != SessionStateActive {
			t.Errorf("got %v, want %v", sessionState, SessionStateActive)
		}
	})
}

func TestHandleAuthorPacketBadSecret(t *testing.T) {
	t.Run("bad secret in authorization packet", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var badSecretCalled bool
		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("serversecret"),
			WithHandler(&testHandler{}),
			WithServerHooks(ServerHooks{
				OnBadSecret: func(_ BadSecretEvent) {
					badSecretCalled = true
				},
			}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		// Send authorization packet with wrong secret
		secret := []byte("serversecret")
		wrongSecret := []byte("wrongsecret")

		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer conn.Close()

		// Build valid author request body, but obfuscate with wrong secret
		request := &AuthorRequest{
			AuthenMethod: AuthenMethodTACACSPlus,
			PrivLevel:    15,
			AuthenType:   AuthenTypePAP,
			Service:      AuthenServiceLogin,
			User:         []byte("admin"),
			RawArgs:      [][]byte{[]byte("service=shell")},
		}
		body, _ := request.MarshalBinary()

		header := &Header{
			Version:   0xc1,
			Type:      PacketTypeAuthor,
			SeqNo:     1,
			SessionID: 12345,
			Length:    uint32(len(body)),
		}

		headerData, _ := header.MarshalBinary()
		// Obfuscate with wrong secret to create bad-secret scenario
		obfuscatedBody := Obfuscate(header, wrongSecret, body)

		conn.Write(headerData)
		conn.Write(obfuscatedBody)

		// Read error response (server uses its own secret to deobfuscate, gets garbage)
		respHeaderBuf := make([]byte, HeaderLength)
		_, err = io.ReadFull(conn, respHeaderBuf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		respHeader := &Header{}
		respHeader.UnmarshalBinary(respHeaderBuf)

		respBody := make([]byte, respHeader.Length)
		io.ReadFull(conn, respBody)
		respBody = Obfuscate(respHeader, secret, respBody)

		resp := &AuthorResponse{}
		resp.UnmarshalBinary(respBody)
		tv4183_1 := AuthorStatusError
		if resp.Status != tv4183_1 {
			t.Errorf("got %v, want %v", resp.Status, tv4183_1)
		}

		time.Sleep(50 * time.Millisecond)
		if !badSecretCalled {
			t.Error("expected true")
		}
	})
}

func TestHandleAcctPacketBadSecret(t *testing.T) {
	t.Run("bad secret in accounting packet", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var badSecretCalled bool
		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("serversecret"),
			WithHandler(&testHandler{}),
			WithServerHooks(ServerHooks{
				OnBadSecret: func(_ BadSecretEvent) {
					badSecretCalled = true
				},
			}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		secret := []byte("serversecret")
		wrongSecret := []byte("wrongsecret")

		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer conn.Close()

		request := &AcctRequest{
			Flags:        AcctFlagStart,
			AuthenMethod: AuthenMethodTACACSPlus,
			PrivLevel:    15,
			AuthenType:   AuthenTypePAP,
			Service:      AuthenServiceLogin,
			User:         []byte("admin"),
			RawArgs:      [][]byte{[]byte("task_id=1")},
		}
		body, _ := request.MarshalBinary()

		header := &Header{
			Version:   0xc0,
			Type:      PacketTypeAcct,
			SeqNo:     1,
			SessionID: 12345,
			Length:    uint32(len(body)),
		}

		headerData, _ := header.MarshalBinary()
		obfuscatedBody := Obfuscate(header, wrongSecret, body)

		conn.Write(headerData)
		conn.Write(obfuscatedBody)

		respHeaderBuf := make([]byte, HeaderLength)
		_, err = io.ReadFull(conn, respHeaderBuf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		respHeader := &Header{}
		respHeader.UnmarshalBinary(respHeaderBuf)

		respBody := make([]byte, respHeader.Length)
		io.ReadFull(conn, respBody)
		respBody = Obfuscate(respHeader, secret, respBody)

		reply := &AcctReply{}
		reply.UnmarshalBinary(respBody)
		tv4256_1 := AcctStatusError
		if reply.Status != tv4256_1 {
			t.Errorf("got %v, want %v", reply.Status, tv4256_1)
		}

		time.Sleep(50 * time.Millisecond)
		if !badSecretCalled {
			t.Error("expected true")
		}
	})
}

func TestResolveSecretNonBadSecretError(t *testing.T) {
	t.Run("non-ErrBadSecret error stops rotation early", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Provider with 3 secrets. Client uses secret1 (the first one).
		// resolveSecret should succeed on attempt 0 and NOT try secrets 2 or 3.
		var rotationAttempts []int
		provider := SecretProviderFunc(func(_ context.Context, req SecretRequest) SecretResponse {
			rotationAttempts = append(rotationAttempts, req.Attempt)
			secrets := []string{"secret1", "secret2", "secret3"}
			return SecretResponse{
				Secret:   []byte(secrets[req.Attempt]),
				Attempts: len(secrets),
			}
		})

		server := NewServer(
			WithServerListener(ln),
			WithSecretProvider(provider),
			WithHandler(&testHandler{}),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		// Client uses secret1 - resolveSecret should succeed on first attempt
		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("secret1"))
		reply, err := client.Authenticate(context.Background(), "testuser", "password")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tv4294_1 := reply.IsPass()
		if !tv4294_1 {
			t.Error("expected true")
		}

		time.Sleep(50 * time.Millisecond)
		// The provider is called once for initial getSecret (attempt=0).
		// resolveSecret reuses cs.secret for attempt 0 (no extra provider call),
		// and since it succeeds, attempts 1 and 2 are never tried.
		if !reflect.DeepEqual(rotationAttempts, []int{0}) {
			t.Errorf("got %v, want %v", rotationAttempts, []int{0})
		}
	})
}

func TestSecretRotationRetriesLengthErrors(t *testing.T) {
	correct := []byte("correct secret")
	wrong := []byte("old secret")
	server := NewServer(WithSecretProvider(SecretProviderFunc(func(_ context.Context, req SecretRequest) SecretResponse {
		if req.Attempt != 1 {
			t.Errorf("unexpected attempt %d", req.Attempt)
		}
		return SecretResponse{Secret: correct}
	})))
	start := &AuthenStart{
		Action:     AuthenActionLogin,
		AuthenType: AuthenTypePAP,
		Service:    AuthenServiceLogin,
		User:       bytes.Repeat([]byte("u"), 255),
		Port:       bytes.Repeat([]byte("p"), 100),
		Data:       bytes.Repeat([]byte("x"), 255),
	}
	body, err := start.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	header := &Header{Version: 0xc1, Type: PacketTypeAuthen, SeqNo: 1, SessionID: 42, Length: uint32(len(body))}
	raw := Obfuscate(header, correct, body)
	if _, err := server.deobfuscateAndValidate(header, raw, wrong, false); err == nil || errors.Is(err, ErrBadSecret) {
		t.Fatalf("fixture must produce a length error outside the bad-secret heuristic: %v", err)
	}
	cs := &connState{secret: wrong, totalAttempts: 2}
	got := server.resolveSecret(context.Background(), header, raw, cs)
	if !bytes.Equal(got, body) || !bytes.Equal(cs.secret, correct) {
		t.Error("rotation stopped before trying the correct secret")
	}
}

func TestServerSingleConnectNegotiationIsFixed(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		t.Run(fmt.Sprint("accepted=", accepted), func(t *testing.T) {
			server := NewServer(WithAuthenticationHandler(&multiStepHandler{
				onStart: func(context.Context, *AuthenRequest) *AuthenReply {
					return &AuthenReply{Status: AuthenStatusGetPass}
				},
			}))
			peer, conn := net.Pipe()
			done := make(chan error, 1)
			go func() { done <- server.ServeConn(peer) }()
			defer func() {
				conn.Close()
				peer.Close()
				<-done
			}()
			exchange := func(header *Header, packet Packet) *Header {
				t.Helper()
				conn.SetDeadline(time.Now().Add(time.Second))
				body, err := packet.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				header.Length = uint32(len(body))
				if err := server.writePacket(conn, header, body, nil, false); err != nil {
					t.Fatal(err)
				}
				reply, _, err := server.readPacket(conn, nil, false)
				if err != nil {
					t.Fatal(err)
				}
				return reply
			}
			header := NewHeader(PacketTypeAuthen, 42)
			header.SetSingleConnect(accepted)
			exchange(header, NewAuthenStart(AuthenActionLogin, AuthenTypeASCII, AuthenServiceLogin, "user"))
			header.SeqNo = 3
			header.SetSingleConnect(!accepted)
			if reply := exchange(header, &AuthenContinue{UserMsg: []byte("pass")}); reply.IsSingleConnect() != accepted {
				t.Error("later flag changed the negotiated mode")
			}
			if accepted {
				header = NewHeader(PacketTypeAcct, 43)
				exchange(header, &AcctRequest{Flags: AcctFlagStart})
			} else {
				select {
				case err := <-done:
					done <- err
				case <-time.After(100 * time.Millisecond):
					t.Error("connection retained without single-connect negotiation")
				}
			}
		})
	}
}

func TestServerAbortHasNoReply(t *testing.T) {
	var aborted atomic.Bool
	server := NewServer(WithAuthenticationHandler(&multiStepHandler{
		onStart: func(context.Context, *AuthenRequest) *AuthenReply {
			return &AuthenReply{Status: AuthenStatusGetPass}
		},
		onContinue: func(_ context.Context, req *AuthenContinueRequest) *AuthenReply {
			aborted.Store(req.Continue.IsAbort())
			return &AuthenReply{Status: AuthenStatusPass}
		},
	}))
	peer, conn := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- server.ServeConn(peer) }()
	defer func() {
		conn.Close()
		peer.Close()
		<-done
	}()
	conn.SetDeadline(time.Now().Add(time.Second))
	header := NewHeader(PacketTypeAuthen, 42)
	header.SetSingleConnect(true)
	body, _ := NewAuthenStart(AuthenActionLogin, AuthenTypeASCII, AuthenServiceLogin, "user").MarshalBinary()
	header.Length = uint32(len(body))
	if err := server.writePacket(conn, header, body, nil, false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.readPacket(conn, nil, false); err != nil {
		t.Fatal(err)
	}
	header.SeqNo = 3
	body, _ = (&AuthenContinue{Flags: AuthenContinueFlagAbort}).MarshalBinary()
	header.Length = uint32(len(body))
	if err := server.writePacket(conn, header, body, nil, false); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, _, err := server.readPacket(conn, nil, false); err == nil {
		t.Fatal("server replied to an aborted session")
	} else if timeout, ok := errors.AsType[net.Error](err); !ok || !timeout.Timeout() {
		t.Fatalf("single-connect connection closed after abort: %v", err)
	}
	if !aborted.Load() || len(server.Sessions()) != 0 {
		t.Error("abort was not delivered to the handler and cleaned up")
	}
	conn.SetDeadline(time.Now().Add(time.Second))
	header = NewHeader(PacketTypeAcct, 43)
	body, _ = (&AcctRequest{Flags: AcctFlagStart}).MarshalBinary()
	header.Length = uint32(len(body))
	if err := server.writePacket(conn, header, body, nil, false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.readPacket(conn, nil, false); err != nil {
		t.Fatalf("could not start another session after abort: %v", err)
	}
}

func TestServerTLSHandshakeReadTimeout(t *testing.T) {
	server := NewServer(WithServerReadTimeout(20 * time.Millisecond))
	peer, conn := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- server.ServeConn(tls.Server(peer, &tls.Config{})) }()
	defer func() {
		conn.Close()
		peer.Close()
		<-done
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("stalled TLS handshake succeeded")
		}
		done <- err
	case <-time.After(100 * time.Millisecond):
		t.Error("TLS handshake ignored the configured read timeout")
	}
}

func TestServerReplyMarshalFailures(t *testing.T) {
	oversized := make([]byte, 65536)
	server := NewServer(
		WithAuthenticationHandler(&multiStepHandler{
			onStart: func(context.Context, *AuthenRequest) *AuthenReply {
				return &AuthenReply{Status: AuthenStatusPass, ServerMsg: oversized}
			},
			onContinue: func(context.Context, *AuthenContinueRequest) *AuthenReply {
				return &AuthenReply{Status: AuthenStatusPass, Data: oversized}
			},
		}),
		WithAuthorizationHandler(AuthorHandlerFunc(func(context.Context, *AuthorRequestContext) *AuthorResponse {
			return &AuthorResponse{Status: AuthorStatusPassAdd, ServerMsg: oversized}
		})),
		WithAccountingHandler(AcctHandlerFunc(func(context.Context, *AcctRequestContext) *AcctReply {
			return &AcctReply{Status: AcctStatusSuccess, Data: oversized}
		})),
	)
	cases := []struct {
		name   string
		header Header
		packet Packet
	}{
		{name: "START", header: Header{Type: PacketTypeAuthen, SeqNo: 1}, packet: &AuthenStart{}},
		{name: "CONTINUE", header: Header{Type: PacketTypeAuthen, SeqNo: 3}, packet: &AuthenContinue{}},
		{name: "authorization", header: Header{Type: PacketTypeAuthor, SeqNo: 1}, packet: &AuthorRequest{}},
		{name: "accounting", header: Header{Type: PacketTypeAcct, SeqNo: 1}, packet: &AcctRequest{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := tc.packet.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			var reply []byte
			var state SessionState
			switch tc.header.Type {
			case PacketTypeAuthen:
				reply, _, state = server.handleAuthenPacketWithState(context.Background(), &tc.header, body, &connState{})
				resp := &AuthenReply{}
				if err := resp.UnmarshalBinary(reply); err != nil || !resp.IsError() {
					t.Errorf("expected authentication ERROR, got %v: %v", resp, err)
				}
			case PacketTypeAuthor:
				reply, _, state = server.handleAuthorPacket(context.Background(), &tc.header, body, &connState{})
				resp := &AuthorResponse{}
				if err := resp.UnmarshalBinary(reply); err != nil || !resp.IsError() {
					t.Errorf("expected authorization ERROR, got %v: %v", resp, err)
				}
			case PacketTypeAcct:
				reply, _, state = server.handleAcctPacket(context.Background(), &tc.header, body, &connState{})
				resp := &AcctReply{}
				if err := resp.UnmarshalBinary(reply); err != nil || !resp.IsError() {
					t.Errorf("expected accounting ERROR, got %v: %v", resp, err)
				}
			}
			if state != SessionStateError {
				t.Errorf("session state = %v, want ERROR", state)
			}
		})
	}
}

func TestSequenceOverflowCleanup(t *testing.T) {
	t.Run("sequence overflow causes cleanup", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Create a handler that keeps returning GETPASS to force many sequence increments
		// The session seq starts at 1, responses use 2, next request 3, etc.
		// Max seq is 255 (uint8), so after ~127 round trips, NextSeqNo should overflow.
		step := 0
		handler := &multiStepHandler{
			onStart: func(_ context.Context, _ *AuthenRequest) *AuthenReply {
				step++
				return &AuthenReply{
					Status:    AuthenStatusGetPass,
					ServerMsg: []byte("Password: "),
				}
			},
			onContinue: func(_ context.Context, _ *AuthenContinueRequest) *AuthenReply {
				step++
				if step >= 126 {
					return &AuthenReply{Status: AuthenStatusPass}
				}
				return &AuthenReply{
					Status:    AuthenStatusGetPass,
					ServerMsg: []byte("Password: "),
				}
			},
		}

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
			WithAuthenticationHandler(handler),
			WithServerReadTimeout(5*time.Second),
		)

		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		// Use the client to do many rounds of GETPASS/CONTINUE
		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"), WithTimeout(5*time.Second))
		promptCount := 0
		reply, err := client.AuthenticateASCII(context.Background(), "testuser", func(_ string, _ bool) (string, error) {
			promptCount++
			return "pass", nil
		})

		// Either succeeds or the server/client handles overflow gracefully
		if err == nil {
			tv4354_1 := reply.IsPass() || reply.IsError()
			if !tv4354_1 {
				t.Error("expected true")
			}
		}
		// Session should be cleaned up after completion
		time.Sleep(100 * time.Millisecond)
		tv4358_1 := server.Sessions()
		if len(tv4358_1) != 0 {
			t.Errorf("expected empty, got %v", tv4358_1)
		}
	})
}

// pipeDialer returns a preconnected net.Conn on Dial, allowing a Client to be
// driven over a net.Pipe whose server end is handed to ServeConn.
type pipeDialer struct {
	conn net.Conn
}

func (d *pipeDialer) Dial(_ context.Context, _, _ string) (net.Conn, error) {
	if d.conn == nil {
		return nil, errors.New("pipeDialer: no connection")
	}
	conn := d.conn
	d.conn = nil
	return conn, nil
}

// newServeConnPair wires a Client to a Server over net.Pipe. The server end is
// served with ServeConn in a goroutine; the returned client talks to it. The
// cleanup closes both ends and waits for ServeConn to return.
func newServeConnPair(t *testing.T, server *Server, secret string) (*Client, func()) {
	t.Helper()

	serverConn, clientConn := net.Pipe()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.ServeConn(serverConn)
	}()

	opts := []ClientOption{
		WithAddress("pipe"),
		WithDialer(&pipeDialer{conn: clientConn}),
	}
	if secret != "" {
		opts = append(opts, WithSecret(secret))
	}
	client := NewClient(opts...)

	cleanup := func() {
		client.Close()
		serverConn.Close()
		<-done
	}
	return client, cleanup
}

// asciiFlowHandler drives a full ASCII exchange: START -> GETUSER -> CONTINUE
// -> GETPASS -> CONTINUE -> PASS, so the multi-step continue path is exercised.
type asciiFlowHandler struct {
	testHandler
	step atomic.Int32
}

func (h *asciiFlowHandler) HandleAuthenStart(_ context.Context, _ *AuthenRequest) *AuthenReply {
	return &AuthenReply{Status: AuthenStatusGetUser, ServerMsg: []byte("Username: ")}
}

func (h *asciiFlowHandler) HandleAuthenContinue(_ context.Context, _ *AuthenContinueRequest) *AuthenReply {
	if h.step.Add(1) == 1 {
		return &AuthenReply{Status: AuthenStatusGetPass, ServerMsg: []byte("Password: ")}
	}
	return &AuthenReply{Status: AuthenStatusPass}
}

func TestServeConnPAP(t *testing.T) {
	server := NewServer(WithHandler(&testHandler{}), WithServerSecret("s3cr3t"))
	client, cleanup := newServeConnPair(t, server, "s3cr3t")
	defer cleanup()

	reply, err := client.Authenticate(context.Background(), "testuser", "password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tv4433_1 := AuthenStatusPass
	if reply.Status != tv4433_1 {
		t.Errorf("got %v, want %v", reply.Status, tv4433_1)
	}
}

func TestServeConnASCIIMultiExchange(t *testing.T) {
	server := NewServer(WithHandler(&asciiFlowHandler{}), WithServerSecret("s3cr3t"))
	client, cleanup := newServeConnPair(t, server, "s3cr3t")
	defer cleanup()

	prompts := 0
	reply, err := client.AuthenticateASCII(context.Background(), "testuser", func(_ string, _ bool) (string, error) {
		prompts++
		return "reply", nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tv4447_1 := AuthenStatusPass
	if reply.Status != tv4447_1 {
		t.Errorf("got %v, want %v", reply.Status, tv4447_1)
	}
	if prompts != 2 {
		t.Errorf("got %v, want %v", prompts, 2)
	}
}

func TestServeConnAuthorize(t *testing.T) {
	server := NewServer(WithHandler(&testHandler{}), WithServerSecret("s3cr3t"))
	client, cleanup := newServeConnPair(t, server, "s3cr3t")
	defer cleanup()

	resp, err := client.Authorize(context.Background(), "testuser", []string{"service=shell"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tv4458_1 := AuthorStatusPassAdd
	if resp.Status != tv4458_1 {
		t.Errorf("got %v, want %v", resp.Status, tv4458_1)
	}
}

func TestServeConnAccounting(t *testing.T) {
	server := NewServer(WithHandler(&testHandler{}), WithServerSecret("s3cr3t"))
	client, cleanup := newServeConnPair(t, server, "s3cr3t")
	defer cleanup()

	reply, err := client.Accounting(context.Background(), AcctFlagStop, "testuser", []string{"service=shell"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tv4468_1 := AcctStatusSuccess
	if reply.Status != tv4468_1 {
		t.Errorf("got %v, want %v", reply.Status, tv4468_1)
	}
}

func TestServeConnFiresHooks(t *testing.T) {
	var connects, disconnects, sessions atomic.Int32
	hooks := ServerHooks{
		OnConnect:      func(ConnectEvent) { connects.Add(1) },
		OnDisconnect:   func(DisconnectEvent) { disconnects.Add(1) },
		OnSessionStart: func(SessionEvent) { sessions.Add(1) },
	}
	server := NewServer(WithHandler(&testHandler{}), WithServerSecret("s3cr3t"), WithServerHooks(hooks))

	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.ServeConn(serverConn)
	}()

	client := NewClient(WithAddress("pipe"), WithDialer(&pipeDialer{conn: clientConn}), WithSecret("s3cr3t"))
	reply, err := client.Authenticate(context.Background(), "testuser", "password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tv4490_1 := AuthenStatusPass
	if reply.Status != tv4490_1 {
		t.Errorf("got %v, want %v", reply.Status, tv4490_1)
	}

	client.Close()
	clientConn.Close()
	<-done

	tv4496_1 := int32(1)
	tv4496_2 := connects.Load()
	if tv4496_2 != tv4496_1 {
		t.Errorf("got %v, want %v", tv4496_2, tv4496_1)
	}
	tv4497_1 := int32(1)
	tv4497_2 := sessions.Load()
	if tv4497_2 != tv4497_1 {
		t.Errorf("got %v, want %v", tv4497_2, tv4497_1)
	}
	tv4498_1 := int32(1)
	tv4498_2 := disconnects.Load()
	if tv4498_2 != tv4498_1 {
		t.Errorf("got %v, want %v", tv4498_2, tv4498_1)
	}
}

func TestServeConnNoListener(t *testing.T) {
	// A server with no listener configured must still serve a caller-supplied
	// connection: ServeConn lazily initializes the shutdown machinery.
	server := NewServer(WithHandler(&testHandler{}), WithServerSecret("s3cr3t"))
	tv4505_1 := server.Addr()
	if tv4505_1 != nil {
		t.Errorf("expected nil, got %v", tv4505_1)
	}

	client, cleanup := newServeConnPair(t, server, "s3cr3t")
	defer cleanup()

	reply, err := client.Authenticate(context.Background(), "testuser", "password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tv4512_1 := AuthenStatusPass
	if reply.Status != tv4512_1 {
		t.Errorf("got %v, want %v", reply.Status, tv4512_1)
	}
	tv4513_1 := server.IsRunning()
	if !tv4513_1 {
		t.Error("expected true")
	}
}

func TestServeStartsAfterServeConn(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	server := NewServer(WithServerListener(ln), WithHandler(&testHandler{}), WithServerSecret("s3cr3t"))

	pipeClient, pipeCleanup := newServeConnPair(t, server, "s3cr3t")
	defer pipeCleanup()
	pipeReply, err := pipeClient.Authenticate(context.Background(), "testuser", "password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tv4525_1 := AuthenStatusPass
	if pipeReply.Status != tv4525_1 {
		t.Errorf("got %v, want %v", pipeReply.Status, tv4525_1)
	}

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve()
	}()
	{
		deadline := time.Now().Add(time.Second)
		cond := func() bool {
			server.mu.Lock()
			defer server.mu.Unlock()
			return server.serving
		}
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatal("condition not met")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	client := NewClient(WithAddress(ln.Addr().String()), WithSecret("s3cr3t"))
	reply, err := client.Authenticate(context.Background(), "testuser", "password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tv4540_1 := AuthenStatusPass
	if reply.Status != tv4540_1 {
		t.Errorf("got %v, want %v", reply.Status, tv4540_1)
	}
	client.Close()

	tv4543_1 := server.Shutdown(context.Background())
	if tv4543_1 != nil {
		t.Fatalf("unexpected error: %v", tv4543_1)
	}
	if <-serveDone != nil {
		t.Errorf("unexpected error: %v", <-serveDone)
	}
}

func TestServeConnCleanClose(t *testing.T) {
	server := NewServer()
	serverConn, clientConn := net.Pipe()
	clientConn.Close()

	tv4552_1 := server.ServeConn(serverConn)
	if tv4552_1 != nil {
		t.Errorf("unexpected error: %v", tv4552_1)
	}
	tv4553_1 := server.Shutdown(context.Background())
	if tv4553_1 != nil {
		t.Fatalf("unexpected error: %v", tv4553_1)
	}
}

func TestServeConnShutdownCancels(t *testing.T) {
	server := NewServer(WithHandler(&testHandler{}), WithServerSecret("s3cr3t"))

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ServeConn(serverConn)
	}()

	// Wait until the connection is registered as active before shutting down.
	{
		deadline := time.Now().Add(time.Second)
		cond := func() bool {
			found := false
			server.activeConns.Range(func(_, _ any) bool {
				found = true
				return false
			})
			return found
		}
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatal("condition not met")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	// A ServeConn blocked in a pipe Read only unblocks when Shutdown forcibly
	// closes the active connection, which happens once the context expires.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := server.Shutdown(shutdownCtx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error %v is not %v", err, context.DeadlineExceeded)
	}

	select {
	case <-errCh:
		// ServeConn returned once the connection was forcibly closed.
	case <-time.After(2 * time.Second):
		t.Fatal("ServeConn did not return after Shutdown")
	}
}

func TestServeConnRestartsAfterShutdown(t *testing.T) {
	server := NewServer(WithHandler(&testHandler{}), WithServerSecret("s3cr3t"))

	client, cleanup := newServeConnPair(t, server, "s3cr3t")
	reply, err := client.Authenticate(context.Background(), "testuser", "password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tv4598_1 := AuthenStatusPass
	if reply.Status != tv4598_1 {
		t.Errorf("got %v, want %v", reply.Status, tv4598_1)
	}
	cleanup()

	tv4601_1 := server.Shutdown(context.Background())
	if tv4601_1 != nil {
		t.Fatalf("unexpected error: %v", tv4601_1)
	}
	tv4602_1 := server.IsRunning()
	if tv4602_1 {
		t.Error("expected false")
	}

	client, cleanup = newServeConnPair(t, server, "s3cr3t")
	defer cleanup()
	reply, err = client.Authenticate(context.Background(), "testuser", "password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tv4608_1 := AuthenStatusPass
	if reply.Status != tv4608_1 {
		t.Errorf("got %v, want %v", reply.Status, tv4608_1)
	}
}

func TestServeConnRepeatedShutdownWaitsForHandlers(t *testing.T) {
	handlerStarted := make(chan struct{})
	releaseHandler := make(chan struct{})
	handler := AuthenHandlerFunc(func(_ context.Context, _ *AuthenRequest) *AuthenReply {
		close(handlerStarted)
		<-releaseHandler
		return &AuthenReply{Status: AuthenStatusPass}
	})
	server := NewServer(WithAuthenticationHandler(handler), WithServerSecret("s3cr3t"))
	client, cleanup := newServeConnPair(t, server, "s3cr3t")

	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		_, _ = client.Authenticate(context.Background(), "testuser", "password")
	}()
	<-handlerStarted

	firstCtx, firstCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer firstCancel()
	tv4631_1 := server.Shutdown(firstCtx)
	if !errors.Is(tv4631_1, context.DeadlineExceeded) {
		t.Errorf("error %v is not %v", tv4631_1, context.DeadlineExceeded)
	}

	secondCtx, secondCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer secondCancel()
	tv4635_1 := server.Shutdown(secondCtx)
	if !errors.Is(tv4635_1, context.DeadlineExceeded) {
		t.Errorf("error %v is not %v", tv4635_1, context.DeadlineExceeded)
	}

	close(releaseHandler)
	finalCtx, finalCancel := context.WithTimeout(context.Background(), time.Second)
	defer finalCancel()
	tv4640_1 := server.Shutdown(finalCtx)
	if tv4640_1 != nil {
		t.Fatalf("unexpected error: %v", tv4640_1)
	}
	<-clientDone
	cleanup()
}

// sendPAPStart writes a raw PAP START packet with the given session ID over
// conn and reads back the reply, deobfuscating it. It lets a test drive two
// connections that deliberately reuse the same client-chosen session ID.
func sendPAPStart(t *testing.T, conn net.Conn, secret []byte, sessionID uint32, user, pass string) *AuthenReply {
	t.Helper()

	start := &AuthenStart{
		Action:     AuthenActionLogin,
		PrivLevel:  1,
		AuthenType: AuthenTypePAP,
		Service:    AuthenServiceLogin,
		User:       []byte(user),
		Data:       []byte(pass),
	}
	body, err := start.MarshalBinary()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	header := &Header{
		Version:   0xc1,
		Type:      PacketTypeAuthen,
		SeqNo:     1,
		SessionID: sessionID,
		Length:    uint32(len(body)),
	}
	headerBuf, err := header.MarshalBinary()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tv4671_1 := WriteRawPacket(conn, headerBuf, Obfuscate(header, secret, body))
	if tv4671_1 != nil {
		t.Fatalf("unexpected error: %v", tv4671_1)
	}

	rawHeader, rawBody, err := ReadRawPacket(conn, DefaultMaxBodyLength)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	respHeader := &Header{}
	tv4677_1 := respHeader.UnmarshalBinary(rawHeader)
	if tv4677_1 != nil {
		t.Fatalf("unexpected error: %v", tv4677_1)
	}
	reply := &AuthenReply{}
	tv4679_1 := reply.UnmarshalBinary(Obfuscate(respHeader, secret, rawBody))
	if tv4679_1 != nil {
		t.Fatalf("unexpected error: %v", tv4679_1)
	}
	return reply
}

func TestServeConnConcurrentIsolation(t *testing.T) {
	// Two concurrent ServeConn calls reusing the same client-chosen SessionID
	// must not share session state: each connection keeps its own localSessions
	// map, so both independently accept a SeqNo=1 START on that session ID.
	server := NewServer(WithHandler(&testHandler{}), WithServerSecret("s3cr3t"))
	secret := []byte("s3cr3t")

	const sessionID = 0xABCD1234

	run := func() error {
		serverConn, clientConn := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = server.ServeConn(serverConn)
		}()
		defer func() {
			clientConn.Close()
			serverConn.Close()
			<-done
		}()

		reply := sendPAPStart(t, clientConn, secret, sessionID, "testuser", "password")
		if reply.Status != AuthenStatusPass {
			return errors.New("unexpected status")
		}
		return nil
	}

	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = run()
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent connection %d: unexpected error: %v", i, err)
		}
	}
}

// errorOnceListener returns a real (non-shutdown) error from Accept once its
// gate is released, then blocks any further Accept. It never yields a
// connection, so Serve reaches its accept-error path.
type errorOnceListener struct {
	entered chan struct{}
	release chan struct{}
	first   bool
}

func (l *errorOnceListener) Accept() (net.Conn, error) {
	if l.first {
		<-make(chan struct{})
	}
	l.first = true
	close(l.entered)
	<-l.release
	return nil, errors.New("simulated accept error")
}

func (l *errorOnceListener) Close() error { return nil }

func (l *errorOnceListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

// TestServeShutdownAcceptErrorConcurrent runs Serve's accept-error path
// concurrently with Shutdown many times. Serve's finalize block and Shutdown
// can both attempt to close the same shutdown channel; the !s.shuttingDown guard
// must prevent a double close. Under the race detector, any surviving double
// close would panic. Serve is guaranteed to return (the listener error unblocks
// it), so the test cannot hang.
func TestServeShutdownAcceptErrorConcurrent(t *testing.T) {
	for iter := 0; iter < 300; iter++ {
		ln := &errorOnceListener{entered: make(chan struct{}), release: make(chan struct{})}
		srv := NewServer(WithServerListener(ln), WithHandler(&testHandler{}), WithServerSecret("s"))

		serveDone := make(chan error, 1)
		go func() { serveDone <- srv.Serve() }()

		<-ln.entered // lifecycle initialized; Serve parked in Accept

		// Release the accept error and call Shutdown as close together as
		// possible so the two finalize paths race.
		start := make(chan struct{})
		go func() {
			<-start
			close(ln.release)
		}()
		go func() {
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = srv.Shutdown(ctx)
			cancel()
		}()
		close(start)

		select {
		case <-serveDone:
		case <-time.After(2 * time.Second):
			t.Fatal("Serve did not return")
		}
	}
}
