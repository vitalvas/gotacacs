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

func TestNewClient(t *testing.T) {
	t.Run("create with defaults", func(t *testing.T) {
		client := NewClient("localhost:49")
		assert.NotNil(t, client)
		assert.Equal(t, "localhost:49", client.Address())
		assert.Equal(t, 30*time.Second, client.timeout)
		assert.False(t, client.singleConnect)
	})

	t.Run("create with options", func(t *testing.T) {
		client := NewClient("localhost:49",
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
		client := NewClient("localhost:49", WithTLSConfig(tlsConfig))
		assert.NotNil(t, client.dialer)
		_, ok := client.dialer.(*TLSDialer)
		assert.True(t, ok)
	})

	t.Run("create with custom dialer", func(t *testing.T) {
		dialer := &TCPDialer{Timeout: 5 * time.Second}
		client := NewClient("localhost:49", WithDialer(dialer))
		assert.Equal(t, dialer, client.dialer)
	})

	t.Run("with secret bytes", func(t *testing.T) {
		secret := []byte{0x01, 0x02, 0x03}
		client := NewClient("localhost:49", WithSecretBytes(secret))
		assert.Equal(t, secret, client.secret)
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

		client := NewClient(ln.Addr().String(), WithTimeout(5*time.Second))
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
		client := NewClient("127.0.0.1:1", WithTimeout(100*time.Millisecond))
		err := client.Connect(context.Background())
		assert.Error(t, err)
		assert.False(t, client.IsConnected())
	})

	t.Run("close when not connected", func(t *testing.T) {
		client := NewClient("localhost:49")
		err := client.Close()
		assert.NoError(t, err)
	})
}

func TestClientAddresses(t *testing.T) {
	t.Run("local and remote addr when not connected", func(t *testing.T) {
		client := NewClient("localhost:49")
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

		client := NewClient(ln.Addr().String())
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

			// Deobfuscate
			body = Deobfuscate(header, secret, body)

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

		client := NewClient(server.Addr(), WithSecret("testsecret"))
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

		client := NewClient(server.Addr(), WithSecret("testsecret"))
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
				Status: AuthorStatusPassAdd,
				Args:   [][]byte{[]byte("priv-lvl=15")},
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

		client := NewClient(server.Addr(), WithSecret("testsecret"))
		resp, err := client.Authorize(context.Background(), "testuser", []string{"service=shell", "cmd=show"})
		require.NoError(t, err)
		assert.True(t, resp.IsPass())
		assert.Equal(t, []string{"priv-lvl=15"}, resp.GetArgs())
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

		client := NewClient(server.Addr(), WithSecret("testsecret"))
		reply, err := client.AccountingStart(context.Background(), "testuser", []string{"task_id=1"})
		require.NoError(t, err)
		assert.True(t, reply.IsSuccess())
	})

	t.Run("accounting stop", func(t *testing.T) {
		secret := []byte("testsecret")
		server := newMockServer(t, makeAcctHandler(secret))
		defer server.Close()

		client := NewClient(server.Addr(), WithSecret("testsecret"))
		reply, err := client.AccountingStop(context.Background(), "testuser", []string{"elapsed_time=60"})
		require.NoError(t, err)
		assert.True(t, reply.IsSuccess())
	})

	t.Run("accounting watchdog", func(t *testing.T) {
		secret := []byte("testsecret")
		server := newMockServer(t, makeAcctHandler(secret))
		defer server.Close()

		client := NewClient(server.Addr(), WithSecret("testsecret"))
		reply, err := client.AccountingWatchdog(context.Background(), "testuser", []string{"bytes_in=1024"})
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

		client := NewClient(server.Addr(), WithTimeout(time.Second))
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

		client := NewClient(server.Addr())
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

		client := NewClient(server.Addr(),
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
