package gotacacs

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sendInvalidPacketAndGetResponse sends an invalid packet to the server and returns the response body
func sendInvalidPacketAndGetResponse(t *testing.T, addr string, packetType uint8, secret []byte) []byte {
	t.Helper()

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
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
		assert.Equal(t, secret, resp.Secret)
		assert.Nil(t, resp.UserData)
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
		assert.Equal(t, []byte("secret1"), resp1.Secret)
		assert.Equal(t, map[string]string{"client": "client1"}, resp1.UserData)

		resp2 := provider.GetSecret(context.Background(), req2)
		assert.Equal(t, []byte("default"), resp2.Secret)
		assert.Nil(t, resp2.UserData)
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
		assert.Equal(t, []byte("secret"), resp.Secret)
		assert.Equal(t, "router1", resp.UserData["client_name"])
		assert.Equal(t, "network", resp.UserData["client_type"])
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
		assert.Equal(t, "192.168.1.100:12345", resp.UserData["remote"])
		assert.Equal(t, "10.0.0.1:49", resp.UserData["local"])
	})
}

func TestServerOptions(t *testing.T) {
	t.Run("default values", func(t *testing.T) {
		server := NewServer()
		assert.NotNil(t, server)
		assert.Nil(t, server.listener)
		assert.Nil(t, server.secretProvider)
		assert.NotNil(t, server.sessionStore)
		assert.Equal(t, 30*time.Second, server.readTimeout)
		assert.Equal(t, 30*time.Second, server.writeTimeout)
	})

	t.Run("with secret", func(t *testing.T) {
		server := NewServer(WithServerSecret("testsecret"))
		assert.NotNil(t, server.secretProvider)
	})

	t.Run("with secret bytes", func(t *testing.T) {
		server := NewServer(WithServerSecretBytes([]byte{0x01, 0x02, 0x03}))
		assert.NotNil(t, server.secretProvider)
	})

	t.Run("with secret provider", func(t *testing.T) {
		provider := SecretProviderFunc(func(_ context.Context, _ SecretRequest) SecretResponse {
			return SecretResponse{Secret: []byte("test")}
		})
		server := NewServer(WithSecretProvider(provider))
		assert.NotNil(t, server.secretProvider)
	})

	t.Run("with session store", func(t *testing.T) {
		store := NewMemorySessionStore()
		server := NewServer(WithServerSessionStore(store))
		assert.Equal(t, store, server.sessionStore)
	})

	t.Run("with timeouts", func(t *testing.T) {
		server := NewServer(
			WithServerReadTimeout(10*time.Second),
			WithServerWriteTimeout(15*time.Second),
		)
		assert.Equal(t, 10*time.Second, server.readTimeout)
		assert.Equal(t, 15*time.Second, server.writeTimeout)
	})

	t.Run("with listener", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)
		defer ln.Close()

		server := NewServer(WithServerListener(ln))
		assert.Equal(t, ln, server.listener)
	})

	t.Run("with max body length", func(t *testing.T) {
		server := NewServer(WithServerMaxBodyLength(2048))
		assert.Equal(t, uint32(2048), server.maxBodyLength)
	})

	t.Run("with nil session store keeps default", func(t *testing.T) {
		server := NewServer(WithServerSessionStore(nil))
		assert.NotNil(t, server.sessionStore)
	})

	t.Run("with secret bytes used in connection", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
		assert.True(t, reply.IsPass())
	})
}

func TestServerHandlerOptions(t *testing.T) {
	t.Run("with authentication handler", func(t *testing.T) {
		handler := AuthenHandlerFunc(func(_ context.Context, _ *AuthenRequest) *AuthenReply {
			return &AuthenReply{Status: AuthenStatusPass}
		})

		server := NewServer(WithAuthenticationHandler(handler))
		assert.NotNil(t, server.authenHandler)
	})

	t.Run("with authorization handler", func(t *testing.T) {
		handler := AuthorHandlerFunc(func(_ context.Context, _ *AuthorRequestContext) *AuthorResponse {
			return &AuthorResponse{Status: AuthorStatusPassAdd}
		})

		server := NewServer(WithAuthorizationHandler(handler))
		assert.NotNil(t, server.authorHandler)
	})

	t.Run("with accounting handler", func(t *testing.T) {
		handler := AcctHandlerFunc(func(_ context.Context, _ *AcctRequestContext) *AcctReply {
			return &AcctReply{Status: AcctStatusSuccess}
		})

		server := NewServer(WithAccountingHandler(handler))
		assert.NotNil(t, server.acctHandler)
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
	return &AuthorResponse{Status: AuthorStatusPassAdd, Args: [][]byte{[]byte("priv-lvl=15")}}
}

func (h *testHandler) HandleAcctRequest(_ context.Context, _ *AcctRequestContext) *AcctReply {
	return &AcctReply{Status: AcctStatusSuccess}
}

func TestServerWithHandler(t *testing.T) {
	t.Run("combined handler", func(t *testing.T) {
		handler := &testHandler{}
		server := NewServer(WithHandler(handler))

		assert.Equal(t, handler, server.authenHandler)
		assert.Equal(t, handler, server.authorHandler)
		assert.Equal(t, handler, server.acctHandler)
	})
}

func TestHandlerFuncAdapters(t *testing.T) {
	t.Run("authen handler func continue returns error", func(t *testing.T) {
		handler := AuthenHandlerFunc(func(_ context.Context, _ *AuthenRequest) *AuthenReply {
			return &AuthenReply{Status: AuthenStatusPass}
		})

		reply := handler.HandleAuthenContinue(context.Background(), nil)
		assert.Equal(t, uint8(AuthenStatusError), reply.Status)
	})
}

func TestServerServe(t *testing.T) {
	t.Run("serve without listener", func(t *testing.T) {
		server := NewServer()
		err := server.Serve()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no listener")
	})

	t.Run("serve already running", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

		server := NewServer(WithServerListener(ln))

		// Start server in background
		go func() {
			server.Serve()
		}()

		// Wait for server to start
		time.Sleep(50 * time.Millisecond)

		// Try to start again
		err = server.Serve()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already running")

		server.Shutdown(context.Background())
	})
}

func TestServerShutdown(t *testing.T) {
	t.Run("shutdown when not running", func(t *testing.T) {
		server := NewServer()
		err := server.Shutdown(context.Background())
		assert.NoError(t, err)
	})

	t.Run("graceful shutdown", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

		server := NewServer(WithServerListener(ln))

		go func() {
			server.Serve()
		}()

		time.Sleep(50 * time.Millisecond)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		err = server.Shutdown(ctx)
		assert.NoError(t, err)
		assert.False(t, server.IsRunning())
	})
}

func TestServerAddr(t *testing.T) {
	t.Run("addr without listener", func(t *testing.T) {
		server := NewServer()
		assert.Nil(t, server.Addr())
	})

	t.Run("addr with listener", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)
		defer ln.Close()

		server := NewServer(WithServerListener(ln))
		assert.NotNil(t, server.Addr())
	})
}

func TestServerAuthentication(t *testing.T) {
	t.Run("authentication success", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
		assert.True(t, reply.IsPass())
	})

	t.Run("authentication failure", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
		assert.True(t, reply.IsFail())
	})
}

func TestServerAuthorization(t *testing.T) {
	t.Run("authorization success", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
		assert.True(t, resp.IsPass())
		assert.Contains(t, resp.GetArgs(), "priv-lvl=15")
	})
}

func TestServerAccounting(t *testing.T) {
	t.Run("accounting success", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
		assert.True(t, reply.IsSuccess())
	})
}

func TestServerNoHandler(t *testing.T) {
	t.Run("no authentication handler", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
		assert.Equal(t, uint8(AuthenStatusError), reply.Status)
	})

	t.Run("no authorization handler", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
		assert.Equal(t, uint8(AuthorStatusError), resp.Status)
	})

	t.Run("no accounting handler", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
		assert.Equal(t, uint8(AcctStatusError), reply.Status)
	})
}

func TestServerSingleConnect(t *testing.T) {
	t.Run("single connect mode", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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

		client := NewClient(WithAddress(ln.Addr().String()),
			WithSecret("testsecret"),
			WithSingleConnect(true),
		)
		defer client.Close()

		// Multiple requests on same connection
		for range 3 {
			reply, err := client.Authenticate(context.Background(), "testuser", "testpass")
			require.NoError(t, err)
			assert.True(t, reply.IsPass())
		}
	})
}

func TestServerInvalidPacket(t *testing.T) {
	t.Run("invalid authentication packet", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
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
		require.NoError(t, err)

		respHeader := &Header{}
		respHeader.UnmarshalBinary(respHeaderBuf)

		respBody := make([]byte, respHeader.Length)
		io.ReadFull(conn, respBody)

		respBody = Obfuscate(respHeader, secret, respBody)

		reply := &AuthenReply{}
		reply.UnmarshalBinary(respBody)

		assert.Equal(t, uint8(AuthenStatusError), reply.Status)
	})
}

func TestServerConnectionClose(t *testing.T) {
	t.Run("client closes connection", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
		conn.Close()

		// Server should handle close gracefully
		time.Sleep(50 * time.Millisecond)
		assert.True(t, server.IsRunning())
	})
}

func TestIsNetClosedError(t *testing.T) {
	t.Run("nil error", func(t *testing.T) {
		assert.False(t, isNetClosedError(nil))
	})

	t.Run("non-net error", func(t *testing.T) {
		assert.False(t, isNetClosedError(io.EOF))
	})

	t.Run("net.OpError with closed connection", func(t *testing.T) {
		err := &net.OpError{
			Op:  "read",
			Net: "tcp",
			Err: &closedError{},
		}
		assert.True(t, isNetClosedError(err))
	})

	t.Run("net.OpError with different error", func(t *testing.T) {
		err := &net.OpError{
			Op:  "read",
			Net: "tcp",
			Err: &differentError{},
		}
		assert.False(t, isNetClosedError(err))
	})
}

type closedError struct{}

func (e *closedError) Error() string { return "use of closed network connection" }

type differentError struct{}

func (e *differentError) Error() string { return "some other error" }

func TestServerHandlerNilReply(t *testing.T) {
	t.Run("handler returns nil for authentication", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
		assert.Equal(t, uint8(AuthenStatusError), reply.Status)
	})

	t.Run("handler returns nil for authorization", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
		assert.Equal(t, uint8(AuthorStatusError), resp.Status)
	})

	t.Run("handler returns nil for accounting", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
		assert.Equal(t, uint8(AcctStatusError), reply.Status)
	})
}

func TestServerSessionState(t *testing.T) {
	runSessionStateTest := func(t *testing.T, setupServer func(ln Listener, store SessionStore, captureID *uint32) *Server, runClient func(client *Client) error) {
		t.Helper()
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

		sessionStore := NewMemorySessionStore()
		var capturedSessionID uint32

		server := setupServer(ln, sessionStore, &capturedSessionID)
		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		require.NoError(t, runClient(client))

		time.Sleep(10 * time.Millisecond)
		_, exists := sessionStore.Get(capturedSessionID)
		assert.False(t, exists, "session should be cleaned up")
	}

	t.Run("authentication pass", func(t *testing.T) {
		runSessionStateTest(t,
			func(ln Listener, store SessionStore, captureID *uint32) *Server {
				return NewServer(WithServerListener(ln), WithServerSecret("testsecret"), WithServerSessionStore(store),
					WithAuthenticationHandler(AuthenHandlerFunc(func(_ context.Context, req *AuthenRequest) *AuthenReply {
						*captureID = req.SessionID
						return &AuthenReply{Status: AuthenStatusPass}
					})))
			},
			func(client *Client) error {
				reply, err := client.Authenticate(context.Background(), "testuser", "testpass")
				if err == nil {
					assert.True(t, reply.IsPass())
				}
				return err
			})
	})

	t.Run("authentication fail", func(t *testing.T) {
		runSessionStateTest(t,
			func(ln Listener, store SessionStore, captureID *uint32) *Server {
				return NewServer(WithServerListener(ln), WithServerSecret("testsecret"), WithServerSessionStore(store),
					WithAuthenticationHandler(AuthenHandlerFunc(func(_ context.Context, req *AuthenRequest) *AuthenReply {
						*captureID = req.SessionID
						return &AuthenReply{Status: AuthenStatusFail}
					})))
			},
			func(client *Client) error {
				reply, err := client.Authenticate(context.Background(), "testuser", "testpass")
				if err == nil {
					assert.True(t, reply.IsFail())
				}
				return err
			})
	})

	t.Run("authorization pass", func(t *testing.T) {
		runSessionStateTest(t,
			func(ln Listener, store SessionStore, captureID *uint32) *Server {
				return NewServer(WithServerListener(ln), WithServerSecret("testsecret"), WithServerSessionStore(store),
					WithAuthorizationHandler(AuthorHandlerFunc(func(_ context.Context, req *AuthorRequestContext) *AuthorResponse {
						*captureID = req.SessionID
						return &AuthorResponse{Status: AuthorStatusPassAdd}
					})))
			},
			func(client *Client) error {
				resp, err := client.Authorize(context.Background(), "testuser", []string{"service=shell"})
				if err == nil {
					assert.True(t, resp.IsPass())
				}
				return err
			})
	})

	t.Run("authorization fail", func(t *testing.T) {
		runSessionStateTest(t,
			func(ln Listener, store SessionStore, captureID *uint32) *Server {
				return NewServer(WithServerListener(ln), WithServerSecret("testsecret"), WithServerSessionStore(store),
					WithAuthorizationHandler(AuthorHandlerFunc(func(_ context.Context, req *AuthorRequestContext) *AuthorResponse {
						*captureID = req.SessionID
						return &AuthorResponse{Status: AuthorStatusFail}
					})))
			},
			func(client *Client) error {
				resp, err := client.Authorize(context.Background(), "testuser", []string{"service=shell"})
				if err == nil {
					assert.True(t, resp.IsFail())
				}
				return err
			})
	})

	t.Run("accounting success", func(t *testing.T) {
		runSessionStateTest(t,
			func(ln Listener, store SessionStore, captureID *uint32) *Server {
				return NewServer(WithServerListener(ln), WithServerSecret("testsecret"), WithServerSessionStore(store),
					WithAccountingHandler(AcctHandlerFunc(func(_ context.Context, req *AcctRequestContext) *AcctReply {
						*captureID = req.SessionID
						return &AcctReply{Status: AcctStatusSuccess}
					})))
			},
			func(client *Client) error {
				reply, err := client.Accounting(context.Background(), AcctFlagStart, "testuser", []string{"task_id=1"})
				if err == nil {
					assert.True(t, reply.IsSuccess())
				}
				return err
			})
	})

	t.Run("accounting error", func(t *testing.T) {
		runSessionStateTest(t,
			func(ln Listener, store SessionStore, captureID *uint32) *Server {
				return NewServer(WithServerListener(ln), WithServerSecret("testsecret"), WithServerSessionStore(store),
					WithAccountingHandler(AcctHandlerFunc(func(_ context.Context, req *AcctRequestContext) *AcctReply {
						*captureID = req.SessionID
						return &AcctReply{Status: AcctStatusError}
					})))
			},
			func(client *Client) error {
				reply, err := client.Accounting(context.Background(), AcctFlagStart, "testuser", []string{"task_id=1"})
				if err == nil {
					assert.True(t, reply.IsError())
				}
				return err
			})
	})
}

func TestServerUserDataPassing(t *testing.T) {
	runUserDataTest := func(t *testing.T, expectedUserData map[string]string, setupServer func(ln Listener, provider SecretProvider) *Server, runClient func(client *Client) error, getReceived func() map[string]string) {
		t.Helper()
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

		secretProvider := SecretProviderFunc(func(_ context.Context, _ SecretRequest) SecretResponse {
			return SecretResponse{Secret: []byte("testsecret"), UserData: expectedUserData}
		})

		server := setupServer(ln, secretProvider)
		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		require.NoError(t, runClient(client))
		assert.Equal(t, expectedUserData, getReceived())
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
					assert.True(t, reply.IsPass())
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
					assert.True(t, resp.IsPass())
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
					assert.True(t, reply.IsSuccess())
				}
				return err
			},
			func() map[string]string { return receivedUserData })
	})

	t.Run("nil user data handled correctly", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
		assert.True(t, reply.IsPass())
		assert.Nil(t, receivedUserData)
	})
}

func TestServerMultiStepAuthentication(t *testing.T) {
	t.Run("authentication continue with GETPASS", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
			assert.Contains(t, prompt, "Password")
			assert.True(t, noEcho)
			return "secret", nil
		})

		require.NoError(t, err)
		assert.True(t, reply.IsPass())
		assert.Equal(t, 2, step)
	})

	t.Run("authentication continue with GETDATA", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
			assert.Contains(t, prompt, "OTP")
			assert.False(t, noEcho)
			return "123456", nil
		})

		require.NoError(t, err)
		assert.True(t, reply.IsPass())
	})

	t.Run("authentication continue with GETUSER", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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

		require.NoError(t, err)
		assert.True(t, reply.IsPass())
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
		require.NoError(t, err)

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
		require.NoError(t, err)
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
		assert.Error(t, err)
	})
}

func TestServerShutdownTimeout(t *testing.T) {
	t.Run("shutdown with short timeout", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		assert.NoError(t, err)
	})

	t.Run("shutdown when not running", func(t *testing.T) {
		server := NewServer(WithServerSecret("testsecret"))
		err := server.Shutdown(context.Background())
		assert.NoError(t, err)
	})
}

func TestServerServeErrors(t *testing.T) {
	t.Run("serve without listener", func(t *testing.T) {
		server := NewServer(WithServerSecret("testsecret"))
		err := server.Serve()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no listener")
	})

	t.Run("serve when already running", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

		server := NewServer(
			WithServerListener(ln),
			WithServerSecret("testsecret"),
		)

		go func() { server.Serve() }()
		time.Sleep(50 * time.Millisecond)
		defer server.Shutdown(context.Background())

		err = server.Serve()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already running")
	})
}

func TestServerIsRunning(t *testing.T) {
	t.Run("running state", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

		server := NewServer(WithServerListener(ln))
		assert.False(t, server.IsRunning())

		go func() { server.Serve() }()
		time.Sleep(50 * time.Millisecond)

		assert.True(t, server.IsRunning())

		server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		assert.False(t, server.IsRunning())
	})
}

func TestServerNilHandlerResponse(t *testing.T) {
	t.Run("nil authentication response", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
		assert.True(t, reply.IsError())
	})

	t.Run("nil authorization response", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
		assert.True(t, resp.IsError())
	})

	t.Run("nil accounting response", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
		assert.True(t, reply.IsError())
	})

	t.Run("nil authentication continue response", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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

		require.NoError(t, err)
		assert.True(t, reply.IsError())
	})
}

func TestServerInvalidPackets(t *testing.T) {
	t.Run("invalid continue packet", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
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
		require.Equal(t, uint8(AuthenStatusGetPass), reply.Status)

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

		assert.Equal(t, uint8(AuthenStatusError), errReply.Status)
	})

	t.Run("reject unencrypted flag on non-TLS connection", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
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
		assert.Error(t, err, "server should reject unencrypted flag on non-TLS connection")
	})

	t.Run("invalid authorization packet", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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

		assert.Equal(t, uint8(AuthorStatusError), resp.Status)
	})

	t.Run("invalid accounting packet", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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

		assert.Equal(t, uint8(AcctStatusError), reply.Status)
	})
}
