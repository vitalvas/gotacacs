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

// mockResponseConfig configures how the mock handler should respond
type mockResponseConfig struct {
	packetType uint8
	seqNo      uint8
	sessionMod uint32 // added to session ID (0 = correct, 1+ = mismatch)
	body       []byte
}

// createMockHandler creates a handler that reads a request and sends a configured response
func createMockHandler(secret []byte, cfg mockResponseConfig) func(net.Conn) {
	return func(conn net.Conn) {
		defer conn.Close()

		headerBuf := make([]byte, HeaderLength)
		io.ReadFull(conn, headerBuf)

		header := &Header{}
		header.UnmarshalBinary(headerBuf)

		body := make([]byte, header.Length)
		io.ReadFull(conn, body)

		respHeader := &Header{
			Version:   0xc0,
			Type:      cfg.packetType,
			SeqNo:     cfg.seqNo,
			SessionID: header.SessionID + cfg.sessionMod,
			Length:    uint32(len(cfg.body)),
		}

		obfuscatedBody := Obfuscate(respHeader, secret, cfg.body)
		respHeaderData, _ := respHeader.MarshalBinary()

		conn.Write(respHeaderData)
		conn.Write(obfuscatedBody)
	}
}

func TestNewClient(t *testing.T) {
	t.Run("create with defaults", func(t *testing.T) {
		client := NewClient(WithAddress("localhost:49"))
		assert.NotNil(t, client)
		assert.Equal(t, "localhost:49", client.Address())
		assert.Equal(t, 30*time.Second, client.timeout)
		assert.False(t, client.singleConnect)
	})

	t.Run("create with options", func(t *testing.T) {
		client := NewClient(WithAddress("localhost:49"),
			WithTimeout(10*time.Second),
			WithSecret("testsecret"),
			WithSingleConnect(true),
		)
		assert.Equal(t, 10*time.Second, client.timeout)
		assert.Equal(t, []byte("testsecret"), client.secret)
		assert.True(t, client.singleConnect)
	})

	t.Run("create with TLS", func(t *testing.T) {
		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		client := NewClient(WithAddress("localhost:300"), WithTLSConfig(tlsConfig))
		assert.NotNil(t, client.dialer)
		_, ok := client.dialer.(*TLSDialer)
		assert.True(t, ok)
		assert.True(t, client.IsTLSMode(), "WithTLSConfig should enable RFC 9887 mode")
	})

	t.Run("create with custom dialer", func(t *testing.T) {
		dialer := &TCPDialer{Timeout: 5 * time.Second}
		client := NewClient(WithAddress("localhost:49"), WithDialer(dialer))
		assert.Equal(t, dialer, client.dialer)
	})

	t.Run("with secret bytes", func(t *testing.T) {
		secret := []byte{0x01, 0x02, 0x03}
		client := NewClient(WithAddress("localhost:49"), WithSecretBytes(secret))
		assert.Equal(t, secret, client.secret)
	})

	t.Run("with max body length", func(t *testing.T) {
		client := NewClient(WithAddress("localhost:49"), WithMaxBodyLength(1024))
		assert.Equal(t, uint32(1024), client.maxBodyLength)
	})

	t.Run("WithTLSConfig with nil config does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			client := NewClient(WithAddress("localhost:300"), WithTLSConfig(nil))
			assert.True(t, client.IsTLSMode())
			if tlsDialer, ok := client.dialer.(*TLSDialer); ok {
				assert.NotNil(t, tlsDialer.Config)
				assert.Equal(t, uint16(tls.VersionTLS13), tlsDialer.Config.MinVersion)
			}
		})
	})

	t.Run("WithTLSConfig normalizes MaxVersion below TLS 1.3", func(t *testing.T) {
		// Config with MaxVersion set to TLS 1.2 (invalid for RFC 9887)
		tlsConfig := &tls.Config{
			MaxVersion: tls.VersionTLS12,
		}
		client := NewClient(WithAddress("localhost:300"), WithTLSConfig(tlsConfig))

		if tlsDialer, ok := client.dialer.(*TLSDialer); ok {
			assert.Equal(t, uint16(tls.VersionTLS13), tlsDialer.Config.MinVersion,
				"MinVersion should be TLS 1.3")
			assert.Equal(t, uint16(tls.VersionTLS13), tlsDialer.Config.MaxVersion,
				"MaxVersion should be normalized to TLS 1.3")
		}
	})

	t.Run("WithTLSConfig preserves MaxVersion at or above TLS 1.3", func(t *testing.T) {
		// Config with MaxVersion already at TLS 1.3
		tlsConfig := &tls.Config{
			MaxVersion: tls.VersionTLS13,
		}
		client := NewClient(WithAddress("localhost:300"), WithTLSConfig(tlsConfig))

		if tlsDialer, ok := client.dialer.(*TLSDialer); ok {
			assert.Equal(t, uint16(tls.VersionTLS13), tlsDialer.Config.MaxVersion)
		}
	})
}

func TestClientConnect(t *testing.T) {
	t.Run("connect to server", func(t *testing.T) {
		// Start test server
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer ln.Close()

		go func() {
			conn, _ := ln.Accept()
			if conn != nil {
				time.Sleep(100 * time.Millisecond)
				conn.Close()
			}
		}()

		client := NewClient(WithAddress(ln.Addr().String()), WithTimeout(5*time.Second))
		err = client.Connect(context.Background())
		require.NoError(t, err)
		assert.True(t, client.IsConnected())

		// Second connect should be no-op
		err = client.Connect(context.Background())
		require.NoError(t, err)

		client.Close()
		assert.False(t, client.IsConnected())
	})

	t.Run("connect failure", func(t *testing.T) {
		client := NewClient(WithAddress("127.0.0.1:1"), WithTimeout(100*time.Millisecond))
		err := client.Connect(context.Background())
		assert.Error(t, err)
		assert.False(t, client.IsConnected())
	})

	t.Run("close when not connected", func(t *testing.T) {
		client := NewClient(WithAddress("localhost:49"))
		err := client.Close()
		assert.NoError(t, err)
	})
}

func TestClientAddresses(t *testing.T) {
	t.Run("local and remote addr when not connected", func(t *testing.T) {
		client := NewClient(WithAddress("localhost:49"))
		assert.Nil(t, client.LocalAddr())
		assert.Nil(t, client.RemoteAddr())
	})

	t.Run("local and remote addr when connected", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer ln.Close()

		go func() {
			conn, _ := ln.Accept()
			if conn != nil {
				time.Sleep(100 * time.Millisecond)
				conn.Close()
			}
		}()

		client := NewClient(WithAddress(ln.Addr().String()))
		err = client.Connect(context.Background())
		require.NoError(t, err)
		defer client.Close()

		assert.NotNil(t, client.LocalAddr())
		assert.NotNil(t, client.RemoteAddr())
	})
}

// mockServer creates a mock TACACS+ server for testing
type mockServer struct {
	ln      net.Listener
	handler func(conn net.Conn)
}

func newMockServer(t *testing.T, handler func(conn net.Conn)) *mockServer {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	s := &mockServer{
		ln:      ln,
		handler: handler,
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if s.handler != nil {
				go s.handler(conn)
			}
		}
	}()

	return s
}

func (s *mockServer) Close() {
	s.ln.Close()
}

func (s *mockServer) Addr() string {
	return s.ln.Addr().String()
}

func TestClientAuthenticate(t *testing.T) {
	t.Run("PAP authentication success", func(t *testing.T) {
		secret := []byte("testsecret")

		handler := func(conn net.Conn) {
			defer conn.Close()

			// Read header
			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)

			header := &Header{}
			header.UnmarshalBinary(headerBuf)

			// Read body
			body := make([]byte, header.Length)
			io.ReadFull(conn, body)

			// Deobfuscate (Obfuscate is symmetric)
			body = Obfuscate(header, secret, body)

			// Parse START
			start := &AuthenStart{}
			start.UnmarshalBinary(body)

			// Send PASS reply
			reply := &AuthenReply{Status: AuthenStatusPass}
			replyBody, _ := reply.MarshalBinary()

			respHeader := &Header{
				Version:   0xc0,
				Type:      PacketTypeAuthen,
				SeqNo:     2,
				SessionID: header.SessionID,
				Length:    uint32(len(replyBody)),
			}

			obfuscatedBody := Obfuscate(respHeader, secret, replyBody)
			respHeaderData, _ := respHeader.MarshalBinary()

			conn.Write(respHeaderData)
			conn.Write(obfuscatedBody)
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		reply, err := client.Authenticate(context.Background(), "testuser", "testpass")
		require.NoError(t, err)
		assert.True(t, reply.IsPass())
	})

	t.Run("PAP authentication failure", func(t *testing.T) {
		secret := []byte("testsecret")

		handler := func(conn net.Conn) {
			defer conn.Close()

			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)

			header := &Header{}
			header.UnmarshalBinary(headerBuf)

			body := make([]byte, header.Length)
			io.ReadFull(conn, body)

			reply := &AuthenReply{
				Status:    AuthenStatusFail,
				ServerMsg: []byte("Invalid credentials"),
			}
			replyBody, _ := reply.MarshalBinary()

			respHeader := &Header{
				Version:   0xc0,
				Type:      PacketTypeAuthen,
				SeqNo:     2,
				SessionID: header.SessionID,
				Length:    uint32(len(replyBody)),
			}

			obfuscatedBody := Obfuscate(respHeader, secret, replyBody)
			respHeaderData, _ := respHeader.MarshalBinary()

			conn.Write(respHeaderData)
			conn.Write(obfuscatedBody)
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		reply, err := client.Authenticate(context.Background(), "testuser", "wrongpass")
		require.NoError(t, err)
		assert.True(t, reply.IsFail())
	})
}

func TestClientAuthorize(t *testing.T) {
	t.Run("authorization success", func(t *testing.T) {
		secret := []byte("testsecret")

		handler := func(conn net.Conn) {
			defer conn.Close()

			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)

			header := &Header{}
			header.UnmarshalBinary(headerBuf)

			body := make([]byte, header.Length)
			io.ReadFull(conn, body)

			reply := &AuthorResponse{
				Status:  AuthorStatusPassAdd,
				RawArgs: [][]byte{[]byte("priv-lvl=15")},
			}
			replyBody, _ := reply.MarshalBinary()

			respHeader := &Header{
				Version:   0xc0,
				Type:      PacketTypeAuthor,
				SeqNo:     2,
				SessionID: header.SessionID,
				Length:    uint32(len(replyBody)),
			}

			obfuscatedBody := Obfuscate(respHeader, secret, replyBody)
			respHeaderData, _ := respHeader.MarshalBinary()

			conn.Write(respHeaderData)
			conn.Write(obfuscatedBody)
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		resp, err := client.Authorize(context.Background(), "testuser", []string{"service=shell", "cmd=show"})
		require.NoError(t, err)
		assert.True(t, resp.IsPass())
		assert.Equal(t, []string{"priv-lvl=15"}, resp.Args())
	})
}

func TestClientAccounting(t *testing.T) {
	makeAcctHandler := func(secret []byte) func(conn net.Conn) {
		return func(conn net.Conn) {
			defer conn.Close()

			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)

			header := &Header{}
			header.UnmarshalBinary(headerBuf)

			body := make([]byte, header.Length)
			io.ReadFull(conn, body)

			reply := &AcctReply{Status: AcctStatusSuccess}
			replyBody, _ := reply.MarshalBinary()

			respHeader := &Header{
				Version:   0xc0,
				Type:      PacketTypeAcct,
				SeqNo:     2,
				SessionID: header.SessionID,
				Length:    uint32(len(replyBody)),
			}

			obfuscatedBody := Obfuscate(respHeader, secret, replyBody)
			respHeaderData, _ := respHeader.MarshalBinary()

			conn.Write(respHeaderData)
			conn.Write(obfuscatedBody)
		}
	}

	t.Run("accounting start success", func(t *testing.T) {
		secret := []byte("testsecret")
		server := newMockServer(t, makeAcctHandler(secret))
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		reply, err := client.Accounting(context.Background(), AcctFlagStart, "testuser", []string{"task_id=1"})
		require.NoError(t, err)
		assert.True(t, reply.IsSuccess())
	})

	t.Run("accounting stop", func(t *testing.T) {
		secret := []byte("testsecret")
		server := newMockServer(t, makeAcctHandler(secret))
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		reply, err := client.Accounting(context.Background(), AcctFlagStop, "testuser", []string{"elapsed_time=60"})
		require.NoError(t, err)
		assert.True(t, reply.IsSuccess())
	})

	t.Run("accounting watchdog", func(t *testing.T) {
		secret := []byte("testsecret")
		server := newMockServer(t, makeAcctHandler(secret))
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		reply, err := client.Accounting(context.Background(), AcctFlagWatchdog, "testuser", []string{"bytes_in=1024"})
		require.NoError(t, err)
		assert.True(t, reply.IsSuccess())
	})
}

func TestClientConnectionErrors(t *testing.T) {
	t.Run("server closes connection", func(t *testing.T) {
		handler := func(conn net.Conn) {
			// Close immediately
			conn.Close()
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithTimeout(time.Second))
		_, err := client.Authenticate(context.Background(), "user", "pass")
		assert.Error(t, err)
	})

	t.Run("invalid response type", func(t *testing.T) {
		handler := func(conn net.Conn) {
			defer conn.Close()

			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)

			header := &Header{}
			header.UnmarshalBinary(headerBuf)

			body := make([]byte, header.Length)
			io.ReadFull(conn, body)

			// Send wrong packet type
			respHeader := &Header{
				Version:   0xc0,
				Type:      PacketTypeAcct, // Wrong type for auth
				SeqNo:     2,
				SessionID: header.SessionID,
				Length:    0,
			}

			respHeaderData, _ := respHeader.MarshalBinary()
			conn.Write(respHeaderData)
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()))
		_, err := client.Authenticate(context.Background(), "user", "pass")
		assert.Error(t, err)
	})
}

func TestClientSingleConnect(t *testing.T) {
	t.Run("reuses connection", func(t *testing.T) {
		secret := []byte("testsecret")

		handler := func(conn net.Conn) {
			for {
				headerBuf := make([]byte, HeaderLength)
				_, err := io.ReadFull(conn, headerBuf)
				if err != nil {
					conn.Close()
					return
				}

				header := &Header{}
				header.UnmarshalBinary(headerBuf)

				body := make([]byte, header.Length)
				io.ReadFull(conn, body)

				reply := &AuthenReply{Status: AuthenStatusPass}
				replyBody, _ := reply.MarshalBinary()

				respHeader := &Header{
					Version:   0xc0,
					Type:      PacketTypeAuthen,
					SeqNo:     2,
					SessionID: header.SessionID,
					Length:    uint32(len(replyBody)),
				}

				obfuscatedBody := Obfuscate(respHeader, secret, replyBody)
				respHeaderData, _ := respHeader.MarshalBinary()

				conn.Write(respHeaderData)
				conn.Write(obfuscatedBody)
			}
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()),
			WithSecret("testsecret"),
			WithSingleConnect(true),
		)
		defer client.Close()

		// Multiple authentications should reuse connection
		for range 3 {
			reply, err := client.Authenticate(context.Background(), "user", "pass")
			require.NoError(t, err)
			assert.True(t, reply.IsPass())
		}
	})
}

func TestClientAuthenFollowRestart(t *testing.T) {
	t.Run("authentication follow returns typed error", func(t *testing.T) {
		secret := []byte("testsecret")
		followServer := "alt-server.example.com:49"

		handler := func(conn net.Conn) {
			defer conn.Close()

			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)

			header := &Header{}
			header.UnmarshalBinary(headerBuf)

			body := make([]byte, header.Length)
			io.ReadFull(conn, body)

			reply := &AuthenReply{
				Status:    AuthenStatusFollow,
				ServerMsg: []byte(followServer),
			}
			replyBody, _ := reply.MarshalBinary()

			respHeader := &Header{
				Version:   0xc0,
				Type:      PacketTypeAuthen,
				SeqNo:     2,
				SessionID: header.SessionID,
				Length:    uint32(len(replyBody)),
			}

			obfuscatedBody := Obfuscate(respHeader, secret, replyBody)
			respHeaderData, _ := respHeader.MarshalBinary()

			conn.Write(respHeaderData)
			conn.Write(obfuscatedBody)
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		reply, err := client.Authenticate(context.Background(), "testuser", "testpass")

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrAuthenFollow)
		assert.Contains(t, err.Error(), followServer)
		assert.NotNil(t, reply)
		assert.Equal(t, uint8(AuthenStatusFollow), reply.Status)
	})

	t.Run("authentication restart returns typed error", func(t *testing.T) {
		secret := []byte("testsecret")

		handler := func(conn net.Conn) {
			defer conn.Close()

			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)

			header := &Header{}
			header.UnmarshalBinary(headerBuf)

			body := make([]byte, header.Length)
			io.ReadFull(conn, body)

			reply := &AuthenReply{
				Status:    AuthenStatusRestart,
				ServerMsg: []byte("Please restart authentication"),
			}
			replyBody, _ := reply.MarshalBinary()

			respHeader := &Header{
				Version:   0xc0,
				Type:      PacketTypeAuthen,
				SeqNo:     2,
				SessionID: header.SessionID,
				Length:    uint32(len(replyBody)),
			}

			obfuscatedBody := Obfuscate(respHeader, secret, replyBody)
			respHeaderData, _ := respHeader.MarshalBinary()

			conn.Write(respHeaderData)
			conn.Write(obfuscatedBody)
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		reply, err := client.Authenticate(context.Background(), "testuser", "testpass")

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrAuthenRestart)
		assert.NotNil(t, reply)
		assert.Equal(t, uint8(AuthenStatusRestart), reply.Status)
	})

	t.Run("ASCII authentication follow returns typed error", func(t *testing.T) {
		secret := []byte("testsecret")
		followServer := "backup-server.example.com:49"

		handler := func(conn net.Conn) {
			defer conn.Close()

			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)

			header := &Header{}
			header.UnmarshalBinary(headerBuf)

			body := make([]byte, header.Length)
			io.ReadFull(conn, body)

			reply := &AuthenReply{
				Status:    AuthenStatusFollow,
				ServerMsg: []byte(followServer),
			}
			replyBody, _ := reply.MarshalBinary()

			respHeader := &Header{
				Version:   0xc0,
				Type:      PacketTypeAuthen,
				SeqNo:     2,
				SessionID: header.SessionID,
				Length:    uint32(len(replyBody)),
			}

			obfuscatedBody := Obfuscate(respHeader, secret, replyBody)
			respHeaderData, _ := respHeader.MarshalBinary()

			conn.Write(respHeaderData)
			conn.Write(obfuscatedBody)
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		reply, err := client.AuthenticateASCII(context.Background(), "testuser", func(_ string, _ bool) (string, error) {
			return "password", nil
		})

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrAuthenFollow)
		assert.Contains(t, err.Error(), followServer)
		assert.NotNil(t, reply)
	})

	t.Run("ASCII authentication restart returns typed error", func(t *testing.T) {
		secret := []byte("testsecret")

		handler := func(conn net.Conn) {
			defer conn.Close()

			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)

			header := &Header{}
			header.UnmarshalBinary(headerBuf)

			body := make([]byte, header.Length)
			io.ReadFull(conn, body)

			reply := &AuthenReply{
				Status:    AuthenStatusRestart,
				ServerMsg: []byte("Restart required"),
			}
			replyBody, _ := reply.MarshalBinary()

			respHeader := &Header{
				Version:   0xc0,
				Type:      PacketTypeAuthen,
				SeqNo:     2,
				SessionID: header.SessionID,
				Length:    uint32(len(replyBody)),
			}

			obfuscatedBody := Obfuscate(respHeader, secret, replyBody)
			respHeaderData, _ := respHeader.MarshalBinary()

			conn.Write(respHeaderData)
			conn.Write(obfuscatedBody)
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		reply, err := client.AuthenticateASCII(context.Background(), "testuser", func(_ string, _ bool) (string, error) {
			return "password", nil
		})

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrAuthenRestart)
		assert.NotNil(t, reply)
	})
}

func TestClientErrorPaths(t *testing.T) {
	t.Run("authenticate ascii connection refused", func(t *testing.T) {
		client := NewClient(WithAddress("127.0.0.1:0"), WithSecret("testsecret"))
		_, err := client.AuthenticateASCII(context.Background(), "user", func(_ string, _ bool) (string, error) {
			return "pass", nil
		})
		assert.Error(t, err)
	})

	t.Run("authorize connection refused", func(t *testing.T) {
		client := NewClient(WithAddress("127.0.0.1:0"), WithSecret("testsecret"))
		_, err := client.Authorize(context.Background(), "user", []string{"service=shell"})
		assert.Error(t, err)
	})

	t.Run("accounting connection refused", func(t *testing.T) {
		client := NewClient(WithAddress("127.0.0.1:0"), WithSecret("testsecret"))
		_, err := client.Accounting(context.Background(), AcctFlagStart, "user", []string{"task_id=1"})
		assert.Error(t, err)
	})

	t.Run("authenticate ascii promptHandler error", func(t *testing.T) {
		secret := []byte("testsecret")
		handler := func(conn net.Conn) {
			defer conn.Close()

			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)

			header := &Header{}
			header.UnmarshalBinary(headerBuf)

			body := make([]byte, header.Length)
			io.ReadFull(conn, body)

			// Send GETPASS reply
			reply := &AuthenReply{
				Status:    AuthenStatusGetPass,
				ServerMsg: []byte("Password: "),
				Flags:     AuthenReplyFlagNoEcho,
			}
			replyBody, _ := reply.MarshalBinary()

			respHeader := &Header{
				Version:   0xc0,
				Type:      PacketTypeAuthen,
				SeqNo:     2,
				SessionID: header.SessionID,
				Length:    uint32(len(replyBody)),
			}

			obfuscatedBody := Obfuscate(respHeader, secret, replyBody)
			respHeaderData, _ := respHeader.MarshalBinary()

			conn.Write(respHeaderData)
			conn.Write(obfuscatedBody)

			// Read the CONTINUE (which will be an abort)
			headerBuf2 := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf2)
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		_, err := client.AuthenticateASCII(context.Background(), "testuser", func(_ string, _ bool) (string, error) {
			return "", assert.AnError
		})

		require.Error(t, err)
		assert.ErrorIs(t, err, assert.AnError)
	})

	t.Run("authenticate ascii unexpected status", func(t *testing.T) {
		secret := []byte("testsecret")
		handler := func(conn net.Conn) {
			defer conn.Close()

			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)

			header := &Header{}
			header.UnmarshalBinary(headerBuf)

			body := make([]byte, header.Length)
			io.ReadFull(conn, body)

			// Send reply with unexpected status (invalid value)
			reply := &AuthenReply{
				Status:    0xFF, // Invalid status
				ServerMsg: []byte("Invalid"),
			}
			replyBody, _ := reply.MarshalBinary()

			respHeader := &Header{
				Version:   0xc0,
				Type:      PacketTypeAuthen,
				SeqNo:     2,
				SessionID: header.SessionID,
				Length:    uint32(len(replyBody)),
			}

			obfuscatedBody := Obfuscate(respHeader, secret, replyBody)
			respHeaderData, _ := respHeader.MarshalBinary()

			conn.Write(respHeaderData)
			conn.Write(obfuscatedBody)
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		_, err := client.AuthenticateASCII(context.Background(), "testuser", func(_ string, _ bool) (string, error) {
			return "password", nil
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected authentication status")
	})

	t.Run("authenticate ascii recvPacket error", func(t *testing.T) {
		handler := func(conn net.Conn) {
			defer conn.Close()

			// Read header only then close - simulate incomplete response
			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)

			header := &Header{}
			header.UnmarshalBinary(headerBuf)

			body := make([]byte, header.Length)
			io.ReadFull(conn, body)

			// Close without sending response
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		_, err := client.AuthenticateASCII(context.Background(), "testuser", func(_ string, _ bool) (string, error) {
			return "password", nil
		})

		require.Error(t, err)
	})

	t.Run("authorize recvPacket error", func(t *testing.T) {
		handler := func(conn net.Conn) {
			defer conn.Close()

			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)

			header := &Header{}
			header.UnmarshalBinary(headerBuf)

			body := make([]byte, header.Length)
			io.ReadFull(conn, body)

			// Close without response
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		_, err := client.Authorize(context.Background(), "user", []string{"service=shell"})
		assert.Error(t, err)
	})

	t.Run("accounting recvPacket error", func(t *testing.T) {
		handler := func(conn net.Conn) {
			defer conn.Close()

			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)

			header := &Header{}
			header.UnmarshalBinary(headerBuf)

			body := make([]byte, header.Length)
			io.ReadFull(conn, body)

			// Close without response
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		_, err := client.Accounting(context.Background(), AcctFlagStart, "user", []string{"task_id=1"})
		assert.Error(t, err)
	})

	t.Run("authorize wrong packet type", func(t *testing.T) {
		secret := []byte("testsecret")
		reply := &AuthenReply{Status: AuthenStatusPass}
		replyBody, _ := reply.MarshalBinary()

		handler := createMockHandler(secret, mockResponseConfig{
			packetType: PacketTypeAuthen, // Wrong type!
			seqNo:      2,
			body:       replyBody,
		})

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		_, err := client.Authorize(context.Background(), "user", []string{"service=shell"})

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidType)
	})

	t.Run("accounting wrong packet type", func(t *testing.T) {
		secret := []byte("testsecret")
		reply := &AuthenReply{Status: AuthenStatusPass}
		replyBody, _ := reply.MarshalBinary()

		handler := createMockHandler(secret, mockResponseConfig{
			packetType: PacketTypeAuthen, // Wrong type!
			seqNo:      2,
			body:       replyBody,
		})

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		_, err := client.Accounting(context.Background(), AcctFlagStart, "user", []string{"task_id=1"})

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidType)
	})

	t.Run("authorize session id mismatch", func(t *testing.T) {
		secret := []byte("testsecret")
		resp := &AuthorResponse{Status: AuthorStatusPassAdd}
		respBody, _ := resp.MarshalBinary()

		handler := createMockHandler(secret, mockResponseConfig{
			packetType: PacketTypeAuthor,
			seqNo:      2,
			sessionMod: 1, // Wrong session ID!
			body:       respBody,
		})

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		_, err := client.Authorize(context.Background(), "user", []string{"service=shell"})

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrSessionNotFound)
	})

	t.Run("authorize sequence number mismatch", func(t *testing.T) {
		secret := []byte("testsecret")
		resp := &AuthorResponse{Status: AuthorStatusPassAdd}
		respBody, _ := resp.MarshalBinary()

		handler := createMockHandler(secret, mockResponseConfig{
			packetType: PacketTypeAuthor,
			seqNo:      5, // Wrong sequence! Should be 2
			body:       respBody,
		})

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		_, err := client.Authorize(context.Background(), "user", []string{"service=shell"})

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidSequence)
	})

	t.Run("recvPacket body too large", func(t *testing.T) {
		handler := func(conn net.Conn) {
			defer conn.Close()

			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)

			header := &Header{}
			header.UnmarshalBinary(headerBuf)

			body := make([]byte, header.Length)
			io.ReadFull(conn, body)

			// Send response with body length exceeding max
			respHeader := &Header{
				Version:   0xc0,
				Type:      PacketTypeAuthen,
				SeqNo:     2,
				SessionID: header.SessionID,
				Length:    1024 * 1024, // 1MB - exceeds default max
			}

			respHeaderData, _ := respHeader.MarshalBinary()
			conn.Write(respHeaderData)
			// Don't write body - just the header with large length
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		_, err := client.Authenticate(context.Background(), "user", "pass")

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBodyTooLarge)
	})

	t.Run("recvPacket invalid header version", func(t *testing.T) {
		handler := func(conn net.Conn) {
			defer conn.Close()

			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)

			header := &Header{}
			header.UnmarshalBinary(headerBuf)

			body := make([]byte, header.Length)
			io.ReadFull(conn, body)

			// Send response with invalid version
			respHeader := &Header{
				Version:   0x00, // Invalid version (major should be 0xc)
				Type:      PacketTypeAuthen,
				SeqNo:     2,
				SessionID: header.SessionID,
				Length:    0,
			}

			respHeaderData, _ := respHeader.MarshalBinary()
			conn.Write(respHeaderData)
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		_, err := client.Authenticate(context.Background(), "user", "pass")

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidVersion)
	})

	t.Run("accounting session id mismatch", func(t *testing.T) {
		secret := []byte("testsecret")
		reply := &AcctReply{Status: AcctStatusSuccess}
		replyBody, _ := reply.MarshalBinary()

		handler := createMockHandler(secret, mockResponseConfig{
			packetType: PacketTypeAcct,
			seqNo:      2,
			sessionMod: 1, // Wrong!
			body:       replyBody,
		})

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		_, err := client.Accounting(context.Background(), AcctFlagStart, "user", []string{"task_id=1"})

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrSessionNotFound)
	})

	t.Run("accounting sequence number mismatch", func(t *testing.T) {
		secret := []byte("testsecret")
		reply := &AcctReply{Status: AcctStatusSuccess}
		replyBody, _ := reply.MarshalBinary()

		handler := createMockHandler(secret, mockResponseConfig{
			packetType: PacketTypeAcct,
			seqNo:      5, // Wrong! Should be 2
			body:       replyBody,
		})

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		_, err := client.Accounting(context.Background(), AcctFlagStart, "user", []string{"task_id=1"})

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidSequence)
	})

	t.Run("RFC 9887 tlsMode on non-TLS connection uses obfuscation", func(t *testing.T) {
		// This test verifies that even if tlsMode is set, a non-TLS connection
		// still uses obfuscation (security fix for bug #2)
		secret := []byte("testsecret")

		handler := func(conn net.Conn) {
			defer conn.Close()

			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)

			header := &Header{}
			header.UnmarshalBinary(headerBuf)

			body := make([]byte, header.Length)
			io.ReadFull(conn, body)

			// Deobfuscate the body (client should have obfuscated it)
			body = Obfuscate(header, secret, body)

			// Parse and verify we got a valid START packet
			start := &AuthenStart{}
			err := start.UnmarshalBinary(body)
			if err != nil {
				// If deobfuscation failed, client sent unobfuscated data (bug!)
				return
			}

			reply := &AuthenReply{Status: AuthenStatusPass}
			replyBody, _ := reply.MarshalBinary()

			respHeader := &Header{
				Version:   0xc0,
				Type:      PacketTypeAuthen,
				SeqNo:     2,
				Flags:     0, // No unencrypted flag (obfuscated)
				SessionID: header.SessionID,
				Length:    uint32(len(replyBody)),
			}

			obfuscatedBody := Obfuscate(respHeader, secret, replyBody)
			respHeaderData, _ := respHeader.MarshalBinary()

			conn.Write(respHeaderData)
			conn.Write(obfuscatedBody)
		}

		server := newMockServer(t, handler)
		defer server.Close()

		// Create client with tlsMode enabled but using TCP connection
		// The client should still use obfuscation because connection is not TLS
		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		client.tlsMode = true // This should be ignored for non-TLS connections

		reply, err := client.Authenticate(context.Background(), "user", "pass")

		require.NoError(t, err)
		assert.True(t, reply.IsPass())
	})
}

func TestWithSecretBytesCopy(t *testing.T) {
	t.Run("mutation after creation does not affect client", func(t *testing.T) {
		secret := []byte("original")
		client := NewClient(WithSecretBytes(secret))

		// Mutate the original slice
		secret[0] = 'X'

		assert.Equal(t, []byte("original"), client.secret)
	})
}

func TestASCIIAuthMaxPrompts(t *testing.T) {
	t.Run("exceeds max prompts", func(t *testing.T) {
		secret := []byte("testsecret")

		handler := func(conn net.Conn) {
			defer conn.Close()

			// Read START packet
			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)
			header := &Header{}
			header.UnmarshalBinary(headerBuf)
			body := make([]byte, header.Length)
			io.ReadFull(conn, body)

			seqNo := uint8(2)
			for {
				// Always reply with GETPASS to keep prompting
				reply := &AuthenReply{
					Status:    AuthenStatusGetPass,
					ServerMsg: []byte("Password: "),
				}
				replyBody, _ := reply.MarshalBinary()

				respHeader := &Header{
					Version:   0xc0,
					Type:      PacketTypeAuthen,
					SeqNo:     seqNo,
					SessionID: header.SessionID,
					Length:    uint32(len(replyBody)),
				}

				obfBody := Obfuscate(respHeader, secret, replyBody)
				respHeaderData, _ := respHeader.MarshalBinary()
				if _, err := conn.Write(respHeaderData); err != nil {
					return
				}
				if _, err := conn.Write(obfBody); err != nil {
					return
				}
				seqNo += 2

				// Read CONTINUE
				contHeaderBuf := make([]byte, HeaderLength)
				if _, err := io.ReadFull(conn, contHeaderBuf); err != nil {
					return
				}
				contHeader := &Header{}
				contHeader.UnmarshalBinary(contHeaderBuf)
				contBody := make([]byte, contHeader.Length)
				if _, err := io.ReadFull(conn, contBody); err != nil {
					return
				}
			}
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		_, err := client.AuthenticateASCII(context.Background(), "user", func(_ string, _ bool) (string, error) {
			return "response", nil
		})

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrMaxPrompts)
	})
}

func TestClientIsTLSConnection(t *testing.T) {
	t.Run("nil connection returns false", func(t *testing.T) {
		client := NewClient(WithAddress("localhost:49"))
		assert.False(t, client.IsTLSConnection())
	})
}

func TestClientSendPacketErrors(t *testing.T) {
	t.Run("write error via authenticate on pre-closed connection", func(t *testing.T) {
		handler := func(conn net.Conn) {
			conn.Close()
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"), WithTimeout(time.Second))
		err := client.Connect(context.Background())
		require.NoError(t, err)

		// Close the client's own connection to force write errors
		client.mu.Lock()
		client.conn.Close()
		// Keep conn non-nil so connectLocked thinks we are connected
		// but the underlying fd is closed
		client.mu.Unlock()

		_, err = client.Authenticate(context.Background(), "user", "pass")
		assert.Error(t, err)
	})
}

func TestClientRecvPacketErrors(t *testing.T) {
	t.Run("header read error non-EOF", func(t *testing.T) {
		handler := func(conn net.Conn) {
			defer conn.Close()

			// Read the client request
			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)
			header := &Header{}
			header.UnmarshalBinary(headerBuf)
			body := make([]byte, header.Length)
			io.ReadFull(conn, body)

			// Send partial header (less than HeaderLength bytes) then close
			conn.Write([]byte{0xc0, 0x01})
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"), WithTimeout(time.Second))
		_, err := client.Authenticate(context.Background(), "user", "pass")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read header")
	})

	t.Run("body read error", func(t *testing.T) {
		secret := []byte("testsecret")

		handler := func(conn net.Conn) {
			defer conn.Close()

			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)
			header := &Header{}
			header.UnmarshalBinary(headerBuf)
			body := make([]byte, header.Length)
			io.ReadFull(conn, body)

			// Send valid header with body length > 0, but no body data
			respHeader := &Header{
				Version:   0xc0,
				Type:      PacketTypeAuthen,
				SeqNo:     2,
				SessionID: header.SessionID,
				Length:    100, // Claim 100 bytes body
			}
			respHeaderData, _ := respHeader.MarshalBinary()
			conn.Write(respHeaderData)
			// Write only a few bytes then close
			conn.Write([]byte{0x01, 0x02})
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret(string(secret)), WithTimeout(time.Second))
		_, err := client.Authenticate(context.Background(), "user", "pass")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read body")
	})
}

func TestAuthenticateWithContextErrors(t *testing.T) {
	t.Run("nil authCtx", func(t *testing.T) {
		client := NewClient(WithAddress("localhost:49"))
		_, err := client.AuthenticateWithContext(context.Background(), nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidPacket)
	})

	t.Run("session id mismatch", func(t *testing.T) {
		secret := []byte("testsecret")
		reply := &AuthenReply{Status: AuthenStatusPass}
		replyBody, _ := reply.MarshalBinary()

		handler := createMockHandler(secret, mockResponseConfig{
			packetType: PacketTypeAuthen,
			seqNo:      2,
			sessionMod: 1, // Wrong session ID
			body:       replyBody,
		})

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		_, err := client.AuthenticateWithContext(context.Background(), &AuthenticateContext{
			Username: "user",
			Password: "pass",
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrSessionNotFound)
	})

	t.Run("sequence number mismatch", func(t *testing.T) {
		secret := []byte("testsecret")
		reply := &AuthenReply{Status: AuthenStatusPass}
		replyBody, _ := reply.MarshalBinary()

		handler := createMockHandler(secret, mockResponseConfig{
			packetType: PacketTypeAuthen,
			seqNo:      5, // Wrong seq
			body:       replyBody,
		})

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		_, err := client.AuthenticateWithContext(context.Background(), &AuthenticateContext{
			Username: "user",
			Password: "pass",
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidSequence)
	})

	t.Run("response type mismatch", func(t *testing.T) {
		secret := []byte("testsecret")
		reply := &AuthenReply{Status: AuthenStatusPass}
		replyBody, _ := reply.MarshalBinary()

		handler := createMockHandler(secret, mockResponseConfig{
			packetType: PacketTypeAcct, // Wrong type
			seqNo:      2,
			body:       replyBody,
		})

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		_, err := client.AuthenticateWithContext(context.Background(), &AuthenticateContext{
			Username: "user",
			Password: "pass",
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidType)
	})

	t.Run("unmarshal reply error with truncated body", func(t *testing.T) {
		secret := []byte("testsecret")

		handler := func(conn net.Conn) {
			defer conn.Close()

			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)
			header := &Header{}
			header.UnmarshalBinary(headerBuf)
			body := make([]byte, header.Length)
			io.ReadFull(conn, body)

			// Send body that is too short to unmarshal as AuthenReply (needs >= 6 bytes)
			invalidBody := []byte{0x01, 0x02}
			respHeader := &Header{
				Version:   0xc0,
				Type:      PacketTypeAuthen,
				SeqNo:     2,
				SessionID: header.SessionID,
				Length:    uint32(len(invalidBody)),
			}
			obfBody := Obfuscate(respHeader, secret, invalidBody)
			respHeaderData, _ := respHeader.MarshalBinary()
			conn.Write(respHeaderData)
			conn.Write(obfBody)
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		_, err := client.AuthenticateWithContext(context.Background(), &AuthenticateContext{
			Username: "user",
			Password: "pass",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal REPLY")
	})

	t.Run("authen status error", func(t *testing.T) {
		secret := []byte("testsecret")
		reply := &AuthenReply{Status: AuthenStatusError, ServerMsg: []byte("internal error")}
		replyBody, _ := reply.MarshalBinary()

		handler := createMockHandler(secret, mockResponseConfig{
			packetType: PacketTypeAuthen,
			seqNo:      2,
			body:       replyBody,
		})

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		result, err := client.AuthenticateWithContext(context.Background(), &AuthenticateContext{
			Username: "user",
			Password: "pass",
		})
		require.NoError(t, err)
		assert.True(t, result.IsError())
	})

	t.Run("server rejects single connect for follow", func(t *testing.T) {
		secret := []byte("testsecret")
		reply := &AuthenReply{Status: AuthenStatusFollow, ServerMsg: []byte("other-server:49")}
		replyBody, _ := reply.MarshalBinary()

		handler := createMockHandler(secret, mockResponseConfig{
			packetType: PacketTypeAuthen,
			seqNo:      2,
			body:       replyBody,
		})

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"), WithSingleConnect(true))
		result, err := client.AuthenticateWithContext(context.Background(), &AuthenticateContext{
			Username: "user",
			Password: "pass",
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrAuthenFollow)
		assert.NotNil(t, result)
		// Connection should be closed since server did not echo single-connect flag
		assert.False(t, client.IsConnected())
	})

	t.Run("server rejects single connect for restart", func(t *testing.T) {
		secret := []byte("testsecret")
		reply := &AuthenReply{Status: AuthenStatusRestart}
		replyBody, _ := reply.MarshalBinary()

		handler := createMockHandler(secret, mockResponseConfig{
			packetType: PacketTypeAuthen,
			seqNo:      2,
			body:       replyBody,
		})

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"), WithSingleConnect(true))
		result, err := client.AuthenticateWithContext(context.Background(), &AuthenticateContext{
			Username: "user",
			Password: "pass",
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrAuthenRestart)
		assert.NotNil(t, result)
		assert.False(t, client.IsConnected())
	})
}

func TestAuthenticateASCIIErrors(t *testing.T) {
	t.Run("session id mismatch in ASCII loop", func(t *testing.T) {
		secret := []byte("testsecret")
		reply := &AuthenReply{Status: AuthenStatusGetPass, ServerMsg: []byte("Password: ")}
		replyBody, _ := reply.MarshalBinary()

		handler := createMockHandler(secret, mockResponseConfig{
			packetType: PacketTypeAuthen,
			seqNo:      2,
			sessionMod: 1, // Wrong session ID
			body:       replyBody,
		})

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		_, err := client.AuthenticateASCII(context.Background(), "user", func(_ string, _ bool) (string, error) {
			return "pass", nil
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrSessionNotFound)
	})

	t.Run("sequence number mismatch in ASCII loop", func(t *testing.T) {
		secret := []byte("testsecret")
		reply := &AuthenReply{Status: AuthenStatusGetPass, ServerMsg: []byte("Password: ")}
		replyBody, _ := reply.MarshalBinary()

		handler := createMockHandler(secret, mockResponseConfig{
			packetType: PacketTypeAuthen,
			seqNo:      5, // Wrong sequence
			body:       replyBody,
		})

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		_, err := client.AuthenticateASCII(context.Background(), "user", func(_ string, _ bool) (string, error) {
			return "pass", nil
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidSequence)
	})

	t.Run("unmarshal error in ASCII loop", func(t *testing.T) {
		secret := []byte("testsecret")

		handler := func(conn net.Conn) {
			defer conn.Close()

			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)
			header := &Header{}
			header.UnmarshalBinary(headerBuf)
			body := make([]byte, header.Length)
			io.ReadFull(conn, body)

			// Send body too short for AuthenReply
			invalidBody := []byte{0x01}
			respHeader := &Header{
				Version:   0xc0,
				Type:      PacketTypeAuthen,
				SeqNo:     2,
				SessionID: header.SessionID,
				Length:    uint32(len(invalidBody)),
			}
			obfBody := Obfuscate(respHeader, secret, invalidBody)
			respHeaderData, _ := respHeader.MarshalBinary()
			conn.Write(respHeaderData)
			conn.Write(obfBody)
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		_, err := client.AuthenticateASCII(context.Background(), "user", func(_ string, _ bool) (string, error) {
			return "pass", nil
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal REPLY")
	})

	t.Run("response type mismatch in ASCII loop", func(t *testing.T) {
		secret := []byte("testsecret")
		reply := &AuthenReply{Status: AuthenStatusPass}
		replyBody, _ := reply.MarshalBinary()

		handler := createMockHandler(secret, mockResponseConfig{
			packetType: PacketTypeAcct, // Wrong type
			seqNo:      2,
			body:       replyBody,
		})

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		_, err := client.AuthenticateASCII(context.Background(), "user", func(_ string, _ bool) (string, error) {
			return "pass", nil
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidType)
	})

	t.Run("ASCII pass with single connect rejected", func(t *testing.T) {
		secret := []byte("testsecret")
		reply := &AuthenReply{Status: AuthenStatusPass}
		replyBody, _ := reply.MarshalBinary()

		handler := createMockHandler(secret, mockResponseConfig{
			packetType: PacketTypeAuthen,
			seqNo:      2,
			body:       replyBody,
		})

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"), WithSingleConnect(true))
		result, err := client.AuthenticateASCII(context.Background(), "user", func(_ string, _ bool) (string, error) {
			return "pass", nil
		})
		require.NoError(t, err)
		assert.True(t, result.IsPass())
		assert.False(t, client.IsConnected())
	})

	t.Run("ASCII fail with single connect rejected", func(t *testing.T) {
		secret := []byte("testsecret")
		reply := &AuthenReply{Status: AuthenStatusFail}
		replyBody, _ := reply.MarshalBinary()

		handler := createMockHandler(secret, mockResponseConfig{
			packetType: PacketTypeAuthen,
			seqNo:      2,
			body:       replyBody,
		})

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"), WithSingleConnect(true))
		result, err := client.AuthenticateASCII(context.Background(), "user", func(_ string, _ bool) (string, error) {
			return "pass", nil
		})
		require.NoError(t, err)
		assert.True(t, result.IsFail())
		assert.False(t, client.IsConnected())
	})

	t.Run("ASCII error status", func(t *testing.T) {
		secret := []byte("testsecret")
		reply := &AuthenReply{Status: AuthenStatusError, ServerMsg: []byte("server error")}
		replyBody, _ := reply.MarshalBinary()

		handler := createMockHandler(secret, mockResponseConfig{
			packetType: PacketTypeAuthen,
			seqNo:      2,
			body:       replyBody,
		})

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		result, err := client.AuthenticateASCII(context.Background(), "user", func(_ string, _ bool) (string, error) {
			return "pass", nil
		})
		require.NoError(t, err)
		assert.True(t, result.IsError())
	})

	t.Run("send continue error on closed connection", func(t *testing.T) {
		secret := []byte("testsecret")

		handler := func(conn net.Conn) {
			defer conn.Close()

			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)
			header := &Header{}
			header.UnmarshalBinary(headerBuf)
			body := make([]byte, header.Length)
			io.ReadFull(conn, body)

			// Send GETPASS reply
			reply := &AuthenReply{
				Status:    AuthenStatusGetPass,
				ServerMsg: []byte("Password: "),
			}
			replyBody, _ := reply.MarshalBinary()

			respHeader := &Header{
				Version:   0xc0,
				Type:      PacketTypeAuthen,
				SeqNo:     2,
				SessionID: header.SessionID,
				Length:    uint32(len(replyBody)),
			}
			obfBody := Obfuscate(respHeader, secret, replyBody)
			respHeaderData, _ := respHeader.MarshalBinary()
			conn.Write(respHeaderData)
			conn.Write(obfBody)

			// Close connection before reading CONTINUE
			// This will cause sendPacket to fail
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"), WithTimeout(time.Second))
		_, err := client.AuthenticateASCII(context.Background(), "user", func(_ string, _ bool) (string, error) {
			// Delay slightly so server closes first
			time.Sleep(50 * time.Millisecond)
			return "mypassword", nil
		})
		require.Error(t, err)
	})
}

func TestAuthorizeErrors(t *testing.T) {
	t.Run("unmarshal response error", func(t *testing.T) {
		secret := []byte("testsecret")

		handler := func(conn net.Conn) {
			defer conn.Close()

			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)
			header := &Header{}
			header.UnmarshalBinary(headerBuf)
			body := make([]byte, header.Length)
			io.ReadFull(conn, body)

			// Send body too short for AuthorResponse (needs >= 6 bytes)
			invalidBody := []byte{0x01}
			respHeader := &Header{
				Version:   0xc0,
				Type:      PacketTypeAuthor,
				SeqNo:     2,
				SessionID: header.SessionID,
				Length:    uint32(len(invalidBody)),
			}
			obfBody := Obfuscate(respHeader, secret, invalidBody)
			respHeaderData, _ := respHeader.MarshalBinary()
			conn.Write(respHeaderData)
			conn.Write(obfBody)
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		_, err := client.Authorize(context.Background(), "user", []string{"service=shell"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal RESPONSE")
	})

	t.Run("authorize send error", func(t *testing.T) {
		handler := func(conn net.Conn) {
			conn.Close()
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"), WithTimeout(time.Second))
		err := client.Connect(context.Background())
		require.NoError(t, err)

		// Wait for server to close
		time.Sleep(50 * time.Millisecond)

		_, err = client.Authorize(context.Background(), "user", []string{"service=shell"})
		assert.Error(t, err)
	})

	t.Run("authorize fail status sets error state", func(t *testing.T) {
		secret := []byte("testsecret")
		resp := &AuthorResponse{Status: AuthorStatusFail}
		respBody, _ := resp.MarshalBinary()

		handler := createMockHandler(secret, mockResponseConfig{
			packetType: PacketTypeAuthor,
			seqNo:      2,
			body:       respBody,
		})

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		result, err := client.Authorize(context.Background(), "user", []string{"service=shell"})
		require.NoError(t, err)
		assert.False(t, result.IsPass())
	})
}

func TestAccountingErrors(t *testing.T) {
	t.Run("unmarshal reply error", func(t *testing.T) {
		secret := []byte("testsecret")

		handler := func(conn net.Conn) {
			defer conn.Close()

			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)
			header := &Header{}
			header.UnmarshalBinary(headerBuf)
			body := make([]byte, header.Length)
			io.ReadFull(conn, body)

			// Send body too short for AcctReply (needs >= 5 bytes)
			invalidBody := []byte{0x01}
			respHeader := &Header{
				Version:   0xc0,
				Type:      PacketTypeAcct,
				SeqNo:     2,
				SessionID: header.SessionID,
				Length:    uint32(len(invalidBody)),
			}
			obfBody := Obfuscate(respHeader, secret, invalidBody)
			respHeaderData, _ := respHeader.MarshalBinary()
			conn.Write(respHeaderData)
			conn.Write(obfBody)
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		_, err := client.Accounting(context.Background(), AcctFlagStart, "user", []string{"task_id=1"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal REPLY")
	})

	t.Run("accounting send error", func(t *testing.T) {
		handler := func(conn net.Conn) {
			conn.Close()
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"), WithTimeout(time.Second))
		err := client.Connect(context.Background())
		require.NoError(t, err)

		// Wait for server to close
		time.Sleep(50 * time.Millisecond)

		_, err = client.Accounting(context.Background(), AcctFlagStart, "user", []string{"task_id=1"})
		assert.Error(t, err)
	})

	t.Run("accounting error status sets error state", func(t *testing.T) {
		secret := []byte("testsecret")
		reply := &AcctReply{Status: AcctStatusError}
		replyBody, _ := reply.MarshalBinary()

		handler := createMockHandler(secret, mockResponseConfig{
			packetType: PacketTypeAcct,
			seqNo:      2,
			body:       replyBody,
		})

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		result, err := client.Accounting(context.Background(), AcctFlagStart, "user", []string{"task_id=1"})
		require.NoError(t, err)
		assert.False(t, result.IsSuccess())
	})
}

func TestClientSendPacketWriteDeadlineError(t *testing.T) {
	t.Run("write deadline error on closed connection", func(t *testing.T) {
		serverConn, clientConn := net.Pipe()
		serverConn.Close()
		clientConn.Close()

		client := NewClient(
			WithAddress("localhost:49"),
			WithSecret("testsecret"),
			WithTimeout(time.Second),
		)
		client.conn = clientConn

		header := NewHeader(PacketTypeAuthen, 12345)
		header.SeqNo = 1
		err := client.sendPacket(context.Background(), header, []byte{0x01})

		require.Error(t, err)
	})

	t.Run("writeAll header error without timeout", func(t *testing.T) {
		serverConn, clientConn := net.Pipe()
		serverConn.Close()

		client := NewClient(
			WithAddress("localhost:49"),
			WithSecret("testsecret"),
			WithTimeout(0), // No timeout, so SetWriteDeadline is skipped
		)
		client.conn = clientConn

		header := NewHeader(PacketTypeAuthen, 12345)
		header.SeqNo = 1
		err := client.sendPacket(context.Background(), header, []byte{0x01})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to write header")
		clientConn.Close()
	})

	t.Run("writeAll body error without timeout", func(t *testing.T) {
		serverConn, clientConn := net.Pipe()

		client := NewClient(
			WithAddress("localhost:49"),
			WithSecret("testsecret"),
			WithTimeout(0),
		)
		client.conn = clientConn

		// Read the header on the server side, then close to cause body write error
		go func() {
			buf := make([]byte, HeaderLength)
			io.ReadFull(serverConn, buf)
			serverConn.Close()
		}()

		header := NewHeader(PacketTypeAuthen, 12345)
		header.SeqNo = 1
		err := client.sendPacket(context.Background(), header, []byte{0x01, 0x02, 0x03})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to write body")
		clientConn.Close()
	})
}

func TestClientRecvPacketReadDeadlineError(t *testing.T) {
	t.Run("read deadline error on closed connection", func(t *testing.T) {
		serverConn, clientConn := net.Pipe()
		serverConn.Close()
		clientConn.Close()

		client := NewClient(
			WithAddress("localhost:49"),
			WithSecret("testsecret"),
			WithTimeout(time.Second),
		)
		client.conn = clientConn

		_, _, err := client.recvPacket(context.Background())
		require.Error(t, err)
	})

	t.Run("non-EOF header read error", func(t *testing.T) {
		serverConn, clientConn := net.Pipe()

		client := NewClient(
			WithAddress("localhost:49"),
			WithSecret("testsecret"),
			WithTimeout(0),
		)
		client.conn = clientConn

		// Write partial header then close to cause non-EOF error
		go func() {
			serverConn.Write([]byte{0xc0, 0x01, 0x02})
			serverConn.Close()
		}()

		_, _, err := client.recvPacket(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read header")
		clientConn.Close()
	})

	t.Run("header unmarshal error with invalid version", func(t *testing.T) {
		serverConn, clientConn := net.Pipe()

		client := NewClient(
			WithAddress("localhost:49"),
			WithSecret("testsecret"),
			WithTimeout(0),
		)
		client.conn = clientConn

		// Send a complete header with invalid version
		go func() {
			header := &Header{
				Version:   0xc0,
				Type:      PacketTypeAuthen,
				SeqNo:     2,
				SessionID: 12345,
				Length:    0,
			}
			data, _ := header.MarshalBinary()
			// Corrupt version byte
			data[0] = 0x00
			serverConn.Write(data)
			serverConn.Close()
		}()

		_, _, err := client.recvPacket(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid header")
		clientConn.Close()
	})
}

func TestClientRecvPacketTLSUnencryptedFlagCheck(t *testing.T) {
	t.Run("TLS connection rejects packet without unencrypted flag", func(t *testing.T) {
		cert, err := generateTestCertificate()
		require.NoError(t, err)

		serverConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}

		ln, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
		require.NoError(t, err)
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			// Read client request
			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)
			header := &Header{}
			header.UnmarshalBinary(headerBuf)
			body := make([]byte, header.Length)
			io.ReadFull(conn, body)

			// Send response WITHOUT unencrypted flag (violates RFC 9887)
			reply := &AuthenReply{Status: AuthenStatusPass}
			replyBody, _ := reply.MarshalBinary()

			respHeader := &Header{
				Version:   0xc0,
				Type:      PacketTypeAuthen,
				SeqNo:     2,
				Flags:     0, // Missing FlagUnencrypted - RFC 9887 violation
				SessionID: header.SessionID,
				Length:    uint32(len(replyBody)),
			}

			respHeaderData, _ := respHeader.MarshalBinary()
			conn.Write(respHeaderData)
			conn.Write(replyBody) // Unobfuscated since TLS
		}()

		clientConfig := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		}

		client := NewClient(
			WithAddress(ln.Addr().String()),
			WithTLSConfig(clientConfig),
		)

		_, err = client.Authenticate(context.Background(), "testuser", "password")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidPacket)
		assert.Contains(t, err.Error(), "RFC 9887")
	})
}

func TestClientContextCancellation(t *testing.T) {
	t.Run("cancelled context aborts authentication", func(t *testing.T) {
		secret := []byte("testsecret")

		// Server that delays response
		handler := func(conn net.Conn) {
			defer conn.Close()
			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)
			header := &Header{}
			header.UnmarshalBinary(headerBuf)
			body := make([]byte, header.Length)
			io.ReadFull(conn, body)

			// Wait longer than context deadline before responding
			time.Sleep(2 * time.Second)

			reply := &AuthenReply{Status: AuthenStatusPass}
			replyBody, _ := reply.MarshalBinary()
			respHeader := &Header{
				Version:   0xc0,
				Type:      PacketTypeAuthen,
				SeqNo:     2,
				SessionID: header.SessionID,
				Length:    uint32(len(replyBody)),
			}
			obfBody := Obfuscate(respHeader, secret, replyBody)
			respHeaderData, _ := respHeader.MarshalBinary()
			conn.Write(respHeaderData)
			conn.Write(obfBody)
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"), WithTimeout(10*time.Second))

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		_, err := client.Authenticate(ctx, "user", "pass")
		require.Error(t, err)
	})
}
