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

func TestSecretProvider(t *testing.T) {
	t.Run("static secret provider", func(t *testing.T) {
		secret := []byte("testsecret")
		provider := StaticSecretProvider(secret)

		addr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:12345")
		result := provider.GetSecret(addr)
		assert.Equal(t, secret, result)
	})

	t.Run("secret provider func", func(t *testing.T) {
		provider := SecretProviderFunc(func(addr net.Addr) []byte {
			if addr.String() == "127.0.0.1:12345" {
				return []byte("secret1")
			}
			return []byte("default")
		})

		addr1, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:12345")
		addr2, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:54321")

		assert.Equal(t, []byte("secret1"), provider.GetSecret(addr1))
		assert.Equal(t, []byte("default"), provider.GetSecret(addr2))
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
		provider := StaticSecretProvider([]byte("test"))
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

		client := NewClient(ln.Addr().String(), WithSecret("testsecret"))
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

		client := NewClient(ln.Addr().String(), WithSecret("testsecret"))
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

		client := NewClient(ln.Addr().String(), WithSecret("testsecret"))
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

		client := NewClient(ln.Addr().String(), WithSecret("testsecret"))

		reply, err := client.AccountingStart(context.Background(), "testuser", []string{"task_id=1"})
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

		client := NewClient(ln.Addr().String(), WithSecret("testsecret"))
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

		client := NewClient(ln.Addr().String(), WithSecret("testsecret"))
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

		client := NewClient(ln.Addr().String(), WithSecret("testsecret"))
		reply, err := client.AccountingStart(context.Background(), "testuser", []string{})
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

		client := NewClient(ln.Addr().String(),
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

		respBody = Deobfuscate(respHeader, secret, respBody)

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
}

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

		client := NewClient(ln.Addr().String(), WithSecret("testsecret"))
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

		client := NewClient(ln.Addr().String(), WithSecret("testsecret"))
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

		client := NewClient(ln.Addr().String(), WithSecret("testsecret"))
		reply, err := client.AccountingStart(context.Background(), "testuser", []string{})
		require.NoError(t, err)
		assert.Equal(t, uint8(AcctStatusError), reply.Status)
	})
}
