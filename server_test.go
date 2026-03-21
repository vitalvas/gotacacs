package gotacacs

import (
	"context"
	"crypto/tls"
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
	runSessionStateTest := func(t *testing.T, setupServer func(ln Listener) *Server, runClient func(client *Client) error) {
		t.Helper()
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

		server := setupServer(ln)
		go func() { server.Serve() }()
		defer server.Shutdown(context.Background())
		time.Sleep(50 * time.Millisecond)

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		require.NoError(t, runClient(client))

		time.Sleep(10 * time.Millisecond)
		assert.Empty(t, server.Sessions(), "session should be cleaned up")
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
					assert.True(t, reply.IsPass())
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
					assert.True(t, reply.IsFail())
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
					assert.True(t, resp.IsPass())
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
					assert.True(t, resp.IsFail())
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
					assert.True(t, reply.IsSuccess())
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
		require.NoError(t, err)

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
		require.NoError(t, err)
		assert.True(t, reply.IsPass())
	})

	t.Run("rotation succeeds with primary secret", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
		assert.True(t, reply.IsPass())
	})

	t.Run("all secrets fail", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		assert.Error(t, err)
	})

	t.Run("attempts zero backward compatible", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
		assert.True(t, reply.IsPass())
	})

	t.Run("single connect uses resolved secret", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
			require.NoError(t, err)
			assert.True(t, reply.IsPass())
		}
	})

	t.Run("provider attempt values correct", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
		assert.True(t, reply.IsPass())

		// Wait for connection handling to complete
		time.Sleep(50 * time.Millisecond)

		// Attempt 0 is called in handleConnection setup, attempt 1 during rotation
		assert.Equal(t, []int{0, 1}, receivedAttempts)
	})

	t.Run("rotation with authorization", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
		assert.True(t, resp.IsPass())
		assert.Contains(t, resp.GetArgs(), "priv-lvl=15")
	})

	t.Run("rotation with accounting", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
		assert.True(t, reply.IsSuccess())
	})
}

func TestServerTLSState(t *testing.T) {
	t.Run("TLSState populated on TLS connection", func(t *testing.T) {
		serverCert, err := generateTestCertificate()
		require.NoError(t, err)

		var receivedTLSState *tls.ConnectionState
		provider := SecretProviderFunc(func(_ context.Context, req SecretRequest) SecretResponse {
			receivedTLSState = req.TLSState
			return SecretResponse{}
		})

		serverConfig := &tls.Config{Certificates: []tls.Certificate{serverCert}}
		ln, err := ListenTLS("127.0.0.1:0", serverConfig)
		require.NoError(t, err)

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
		require.NotNil(t, receivedTLSState, "TLSState should be populated for TLS connections")
		assert.True(t, receivedTLSState.HandshakeComplete)
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
		require.NoError(t, err)

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
		assert.True(t, called, "provider should have been called")
		assert.Nil(t, receivedTLSState, "TLSState should be nil for non-TLS connections")
	})

	t.Run("TLSState contains client certificate CN", func(t *testing.T) {
		caCert, caKey, err := generateTestCA()
		require.NoError(t, err)

		serverCert, err := generateSignedCertificate(caCert, caKey, "server.test")
		require.NoError(t, err)

		clientCert, err := generateSignedCertificate(caCert, caKey, "router1.example.com")
		require.NoError(t, err)

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
		require.NoError(t, err)

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
		assert.Equal(t, "router1.example.com", receivedCN)
	})
}

func TestServerSessions(t *testing.T) {
	t.Run("empty when no sessions", func(t *testing.T) {
		server := NewServer()
		assert.Empty(t, server.Sessions())
	})

	t.Run("returns active session", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.Len(t, sessions, 1)
		assert.NotZero(t, sessions[0].TrackingID)
		assert.NotNil(t, sessions[0].RemoteAddr)
		assert.NotNil(t, sessions[0].LocalAddr)
		assert.Nil(t, sessions[0].TLSState)
		assert.Equal(t, uint8(PacketTypeAuthen), sessions[0].PacketType)
		assert.Equal(t, SessionStateActive, sessions[0].State)
		assert.False(t, sessions[0].StartedAt.IsZero())

		close(blocked)
		<-done
	})

	t.Run("TLS session has TLSState", func(t *testing.T) {
		serverCert, err := generateTestCertificate()
		require.NoError(t, err)

		blocked := make(chan struct{})
		handler := AuthenHandlerFunc(func(_ context.Context, _ *AuthenRequest) *AuthenReply {
			<-blocked
			return &AuthenReply{Status: AuthenStatusPass}
		})

		serverConfig := &tls.Config{Certificates: []tls.Certificate{serverCert}}
		ln, err := ListenTLS("127.0.0.1:0", serverConfig)
		require.NoError(t, err)

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
		require.Len(t, sessions, 1)
		require.NotNil(t, sessions[0].TLSState)
		assert.True(t, sessions[0].TLSState.HandshakeComplete)

		close(blocked)
		<-done
	})

	t.Run("session removed after completion", func(t *testing.T) {
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

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		reply, err := client.Authenticate(context.Background(), "testuser", "password")
		require.NoError(t, err)
		assert.True(t, reply.IsPass())

		time.Sleep(50 * time.Millisecond)
		assert.Empty(t, server.Sessions())
	})

	t.Run("tracking IDs are unique", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		assert.Len(t, sessions, 3)

		ids := make(map[uint64]bool)
		for _, s := range sessions {
			assert.False(t, ids[s.TrackingID], "tracking IDs must be unique")
			ids[s.TrackingID] = true
		}

		close(blocked)
		close(done)
	})
}

func TestServerKickSession(t *testing.T) {
	t.Run("kick nonexistent returns false", func(t *testing.T) {
		server := NewServer()
		assert.False(t, server.KickSession(999))
	})

	t.Run("kick active session", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
			require.Len(t, sessions, 1)
			assert.True(t, server.KickSession(sessions[0].TrackingID))
			return "password", nil
		})

		require.NoError(t, err)
		assert.True(t, reply.IsError(), "kicked session should get error response")
	})

	t.Run("kick in single-connect does not close connection", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
			require.Len(t, sessions, 1)
			server.KickSession(sessions[0].TrackingID)
			return "password", nil
		})
		require.NoError(t, err)
		assert.True(t, reply.IsError())

		// Second request on same connection should still work
		kickFirst = false
		reply, err = client.Authenticate(context.Background(), "testuser", "password")
		require.NoError(t, err)
		assert.True(t, reply.IsPass())
	})
}

func TestServerHooks(t *testing.T) {
	t.Run("connect and disconnect hooks", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
		assert.True(t, reply.IsPass())

		connectEvent := <-connectCh
		assert.NotNil(t, connectEvent.RemoteAddr)

		disconnectEvent := <-disconnectCh
		assert.NotNil(t, disconnectEvent.RemoteAddr)
	})

	t.Run("session start and end hooks", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
		assert.True(t, reply.IsPass())

		startEvent := <-startCh
		assert.NotZero(t, startEvent.TrackingID)
		assert.Equal(t, uint8(PacketTypeAuthen), startEvent.PacketType)

		endEvent := <-endCh
		assert.Equal(t, SessionStateComplete, endEvent.State)
	})

	t.Run("bad secret hook", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		assert.True(t, badSecretCalled)
		assert.NotNil(t, badSecretRemote)
	})

	t.Run("bad secret hook with rotation", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		assert.True(t, badSecretCalled)
	})

	t.Run("packet error hook", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
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
		assert.True(t, packetErrorCalled)
		assert.NotNil(t, packetErr)
	})

	t.Run("nil hooks are safe", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
		assert.True(t, reply.IsPass())
	})
}

func TestServerMiddleware(t *testing.T) {
	t.Run("single middleware intercepts authen", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
		assert.True(t, reply.IsPass())
		assert.True(t, <-middlewareCalled)
	})

	t.Run("middleware ordering", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
		assert.True(t, reply.IsPass())

		assert.Equal(t, 1, <-orderCh)
		assert.Equal(t, 2, <-orderCh)
		assert.Equal(t, 3, <-orderCh)
	})

	t.Run("middleware short-circuit", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		require.NoError(t, err)
		assert.True(t, reply.IsFail())
	})

	t.Run("middleware wraps all handler types", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

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
		assert.Equal(t, "authen_start", <-calls)

		client.Authorize(context.Background(), "testuser", []string{"service=shell"})
		assert.Equal(t, "author", <-calls)

		client.Accounting(context.Background(), AcctFlagStart, "testuser", []string{"task_id=1"})
		assert.Equal(t, "acct", <-calls)
	})

	t.Run("no middleware passthrough", func(t *testing.T) {
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

		client := NewClient(WithAddress(ln.Addr().String()), WithSecret("testsecret"))
		reply, err := client.Authenticate(context.Background(), "testuser", "password")
		require.NoError(t, err)
		assert.True(t, reply.IsPass())
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
