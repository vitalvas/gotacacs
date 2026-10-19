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
	"testing"
	"time"
)

var errTest = errors.New("test error")

// mockResponseConfig configures how the mock handler should respond
type mockResponseConfig struct {
	packetType PacketType
	seqNo      uint8
	flags      HeaderFlag
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
			Flags:     cfg.flags,
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
		if client == nil {
			t.Errorf("expected non-nil")
		}
		if client.Address() != "localhost:49" {
			t.Errorf("got %v, want %v", client.Address(), "localhost:49")
		}
		if client.timeout != 30*time.Second {
			t.Errorf("got %v, want %v", client.timeout, 30*time.Second)
		}
		if client.singleConnect {
			t.Errorf("expected false")
		}
	})

	t.Run("create with options", func(t *testing.T) {
		client := NewClient(
			WithAddress("localhost:49"),
			WithTimeout(10*time.Second),
			WithSecret("testsecret"),
			WithSingleConnect(true),
		)
		if client.timeout != 10*time.Second {
			t.Errorf("got %v, want %v", client.timeout, 10*time.Second)
		}
		if !bytes.Equal(client.secret, []byte("testsecret")) {
			t.Errorf("got %v, want %v", client.secret, []byte("testsecret"))
		}
		if !client.singleConnect {
			t.Errorf("expected true")
		}
	})

	t.Run("create with TLS", func(t *testing.T) {
		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		client := NewClient(WithAddress("localhost:300"), WithTLSConfig(tlsConfig))
		if client.dialer == nil {
			t.Errorf("expected non-nil")
		}
		_, ok := client.dialer.(*TLSDialer)
		if !ok {
			t.Errorf("expected true")
		}
		if !client.IsTLSMode() {
			t.Errorf("WithTLSConfig should enable RFC 9887 mode")
		}
	})

	t.Run("create with custom dialer", func(t *testing.T) {
		dialer := &TCPDialer{Timeout: 5 * time.Second}
		client := NewClient(WithAddress("localhost:49"), WithDialer(dialer))
		if client.dialer != dialer {
			t.Errorf("got %v, want %v", client.dialer, dialer)
		}
	})

	t.Run("with secret bytes", func(t *testing.T) {
		secret := []byte{0x01, 0x02, 0x03}
		client := NewClient(WithAddress("localhost:49"), WithSecretBytes(secret))
		if !bytes.Equal(client.secret, secret) {
			t.Errorf("got %v, want %v", client.secret, secret)
		}
	})

	t.Run("with max body length", func(t *testing.T) {
		client := NewClient(WithAddress("localhost:49"), WithMaxBodyLength(1024))
		if client.maxBodyLength != uint32(1024) {
			t.Errorf("got %v, want %v", client.maxBodyLength, uint32(1024))
		}
	})

	t.Run("WithTLSConfig with nil config does not panic", func(t *testing.T) {
		client := NewClient(WithAddress("localhost:300"), WithTLSConfig(nil))
		if !client.IsTLSMode() {
			t.Errorf("expected true")
		}
		if tlsDialer, ok := client.dialer.(*TLSDialer); ok {
			if tlsDialer.Config == nil {
				t.Errorf("expected non-nil")
			}
			if tlsDialer.Config.MinVersion != uint16(tls.VersionTLS13) {
				t.Errorf("got %v, want %v", tlsDialer.Config.MinVersion, uint16(tls.VersionTLS13))
			}
		}
	})

	t.Run("WithTLSConfig normalizes MaxVersion below TLS 1.3", func(t *testing.T) {
		// Config with MaxVersion set to TLS 1.2 (invalid for RFC 9887)
		tlsConfig := &tls.Config{
			MaxVersion: tls.VersionTLS12,
		}
		client := NewClient(WithAddress("localhost:300"), WithTLSConfig(tlsConfig))

		if tlsDialer, ok := client.dialer.(*TLSDialer); ok {
			if tlsDialer.Config.MinVersion != uint16(tls.VersionTLS13) {
				t.Errorf("MinVersion should be TLS 1.3: got %v, want %v", tlsDialer.Config.MinVersion, uint16(tls.VersionTLS13))
			}
			if tlsDialer.Config.MaxVersion != uint16(tls.VersionTLS13) {
				t.Errorf("MaxVersion should be normalized to TLS 1.3: got %v, want %v", tlsDialer.Config.MaxVersion, uint16(tls.VersionTLS13))
			}
		}
	})

	t.Run("WithTLSConfig preserves MaxVersion at or above TLS 1.3", func(t *testing.T) {
		// Config with MaxVersion already at TLS 1.3
		tlsConfig := &tls.Config{
			MaxVersion: tls.VersionTLS13,
		}
		client := NewClient(WithAddress("localhost:300"), WithTLSConfig(tlsConfig))

		if tlsDialer, ok := client.dialer.(*TLSDialer); ok {
			if tlsDialer.Config.MaxVersion != uint16(tls.VersionTLS13) {
				t.Errorf("got %v, want %v", tlsDialer.Config.MaxVersion, uint16(tls.VersionTLS13))
			}
		}
	})
}

func TestClientConnect(t *testing.T) {
	t.Run("connect to server", func(t *testing.T) {
		// Start test server
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
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
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !client.IsConnected() {
			t.Errorf("expected true")
		}

		// Second connect should be no-op
		err = client.Connect(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		client.Close()
		if client.IsConnected() {
			t.Errorf("expected false")
		}
	})

	t.Run("connect failure", func(t *testing.T) {
		client := NewClient(WithAddress("127.0.0.1:1"), WithTimeout(100*time.Millisecond))
		err := client.Connect(context.Background())
		if err == nil {
			t.Errorf("expected an error")
		}
		if client.IsConnected() {
			t.Errorf("expected false")
		}
	})

	t.Run("close when not connected", func(t *testing.T) {
		client := NewClient(WithAddress("localhost:49"))
		err := client.Close()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestClientAddresses(t *testing.T) {
	t.Run("local and remote addr when not connected", func(t *testing.T) {
		client := NewClient(WithAddress("localhost:49"))
		if client.LocalAddr() != nil {
			t.Errorf("expected nil, got %v", client.LocalAddr())
		}
		if client.RemoteAddr() != nil {
			t.Errorf("expected nil, got %v", client.RemoteAddr())
		}
	})

	t.Run("local and remote addr when connected", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
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
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer client.Close()

		if client.LocalAddr() == nil {
			t.Errorf("expected non-nil")
		}
		if client.RemoteAddr() == nil {
			t.Errorf("expected non-nil")
		}
	})
}

// mockServer creates a mock TACACS+ server for testing
type mockServer struct {
	ln      net.Listener
	handler func(conn net.Conn)
}

func newMockServer(t *testing.T, handler func(conn net.Conn)) *mockServer {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reply.IsPass() {
			t.Errorf("expected true")
		}
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
		if !errors.Is(err, ErrAuthenticationFailed) {
			t.Fatalf("got %v, want ErrAuthenticationFailed", err)
		}
		if !reply.IsFail() {
			t.Errorf("expected true")
		}
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
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.IsPass() {
			t.Errorf("expected true")
		}
		if !reflect.DeepEqual(resp.Args(), []string{"priv-lvl=15"}) {
			t.Errorf("got %v, want %v", resp.Args(), []string{"priv-lvl=15"})
		}
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
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reply.IsSuccess() {
			t.Errorf("expected true")
		}
	})

	t.Run("accounting stop", func(t *testing.T) {
		secret := []byte("testsecret")
		server := newMockServer(t, makeAcctHandler(secret))
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		reply, err := client.Accounting(context.Background(), AcctFlagStop, "testuser", []string{"elapsed_time=60"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reply.IsSuccess() {
			t.Errorf("expected true")
		}
	})

	t.Run("accounting watchdog", func(t *testing.T) {
		secret := []byte("testsecret")
		server := newMockServer(t, makeAcctHandler(secret))
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		reply, err := client.Accounting(context.Background(), AcctFlagWatchdog, "testuser", []string{"bytes_in=1024"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reply.IsSuccess() {
			t.Errorf("expected true")
		}
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
		if err == nil {
			t.Errorf("expected an error")
		}
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
		if err == nil {
			t.Errorf("expected an error")
		}
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

		client := NewClient(
			WithAddress(server.Addr()),
			WithSecret("testsecret"),
			WithSingleConnect(true),
		)
		defer client.Close()

		// Multiple authentications should reuse connection
		for range 3 {
			reply, err := client.Authenticate(context.Background(), "user", "pass")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reply.IsPass() {
				t.Errorf("expected true")
			}
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

		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrAuthenFollow) {
			t.Errorf("error %v is not %v", err, ErrAuthenFollow)
		}
		if !strings.Contains(err.Error(), followServer) {
			t.Errorf("error %q does not contain %q", err.Error(), followServer)
		}
		if reply == nil {
			t.Errorf("expected non-nil")
		}
		if reply.Status != AuthenStatusFollow {
			t.Errorf("got %v, want %v", reply.Status, AuthenStatusFollow)
		}
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

		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrAuthenRestart) {
			t.Errorf("error %v is not %v", err, ErrAuthenRestart)
		}
		if reply == nil {
			t.Errorf("expected non-nil")
		}
		if reply.Status != AuthenStatusRestart {
			t.Errorf("got %v, want %v", reply.Status, AuthenStatusRestart)
		}
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

		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrAuthenFollow) {
			t.Errorf("error %v is not %v", err, ErrAuthenFollow)
		}
		if !strings.Contains(err.Error(), followServer) {
			t.Errorf("error %q does not contain %q", err.Error(), followServer)
		}
		if reply == nil {
			t.Errorf("expected non-nil")
		}
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

		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrAuthenRestart) {
			t.Errorf("error %v is not %v", err, ErrAuthenRestart)
		}
		if reply == nil {
			t.Errorf("expected non-nil")
		}
	})
}

//nolint:gocyclo // exhaustive error-path coverage across many subtests; complexity is inherent
func TestClientErrorPaths(t *testing.T) {
	t.Run("authenticate ascii connection refused", func(t *testing.T) {
		client := NewClient(WithAddress("127.0.0.1:0"), WithSecret("testsecret"))
		_, err := client.AuthenticateASCII(context.Background(), "user", func(_ string, _ bool) (string, error) {
			return "pass", nil
		})
		if err == nil {
			t.Errorf("expected an error")
		}
	})

	t.Run("authorize connection refused", func(t *testing.T) {
		client := NewClient(WithAddress("127.0.0.1:0"), WithSecret("testsecret"))
		_, err := client.Authorize(context.Background(), "user", []string{"service=shell"})
		if err == nil {
			t.Errorf("expected an error")
		}
	})

	t.Run("accounting connection refused", func(t *testing.T) {
		client := NewClient(WithAddress("127.0.0.1:0"), WithSecret("testsecret"))
		_, err := client.Accounting(context.Background(), AcctFlagStart, "user", []string{"task_id=1"})
		if err == nil {
			t.Errorf("expected an error")
		}
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
			return "", errTest
		})

		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, errTest) {
			t.Errorf("error %v is not %v", err, errTest)
		}
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

		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(err.Error(), "unexpected authentication status") {
			t.Errorf("error %q does not contain %q", err.Error(), "unexpected authentication status")
		}
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

		if err == nil {
			t.Fatal("expected an error")
		}
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
		if err == nil {
			t.Errorf("expected an error")
		}
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
		if err == nil {
			t.Errorf("expected an error")
		}
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

		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrInvalidType) {
			t.Errorf("error %v is not %v", err, ErrInvalidType)
		}
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

		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrInvalidType) {
			t.Errorf("error %v is not %v", err, ErrInvalidType)
		}
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

		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("error %v is not %v", err, ErrSessionNotFound)
		}
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

		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrInvalidSequence) {
			t.Errorf("error %v is not %v", err, ErrInvalidSequence)
		}
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

		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrBodyTooLarge) {
			t.Errorf("error %v is not %v", err, ErrBodyTooLarge)
		}
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

		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrInvalidVersion) {
			t.Errorf("error %v is not %v", err, ErrInvalidVersion)
		}
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

		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("error %v is not %v", err, ErrSessionNotFound)
		}
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

		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrInvalidSequence) {
			t.Errorf("error %v is not %v", err, ErrInvalidSequence)
		}
	})

	t.Run("authorize unknown status", func(t *testing.T) {
		secret := []byte("testsecret")
		resp := &AuthorResponse{Status: 0xFF}
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

		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrInvalidPacket) {
			t.Errorf("error %v is not %v", err, ErrInvalidPacket)
		}
		if result == nil {
			t.Errorf("expected non-nil")
		}
		if result.Status != 0xFF {
			t.Errorf("got %v, want %v", result.Status, 0xFF)
		}
		if client.IsConnected() {
			t.Errorf("expected false")
		}
	})

	t.Run("accounting unknown status", func(t *testing.T) {
		secret := []byte("testsecret")
		reply := &AcctReply{Status: 0xFF}
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

		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrInvalidPacket) {
			t.Errorf("error %v is not %v", err, ErrInvalidPacket)
		}
		if result == nil {
			t.Errorf("expected non-nil")
		}
		if result.Status != 0xFF {
			t.Errorf("got %v, want %v", result.Status, 0xFF)
		}
		if client.IsConnected() {
			t.Errorf("expected false")
		}
	})

	t.Run("sendPacket obfuscates non-TLS connections regardless of tlsMode", func(t *testing.T) {
		// Exercise the low-level safeguard against sending unobfuscated data
		// even if the internal mode flag is changed on an existing connection.
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

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		if err := client.Connect(context.Background()); err != nil {
			t.Fatal(err)
		}
		client.tlsMode = true

		reply, err := client.Authenticate(context.Background(), "user", "pass")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reply.IsPass() {
			t.Errorf("expected true")
		}
	})

	t.Run("non-TLS response cannot bypass obfuscation with unencrypted flag", func(t *testing.T) {
		secret := []byte("testsecret")
		reply := &AuthenReply{Status: AuthenStatusPass}
		replyBody, _ := reply.MarshalBinary()

		handler := createMockHandler(secret, mockResponseConfig{
			packetType: PacketTypeAuthen,
			seqNo:      2,
			flags:      FlagUnencrypted,
			body:       replyBody,
		})

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		_, err := client.Authenticate(context.Background(), "user", "pass")

		// RFC 8907 10.5.2: a secret-configured client that receives a
		// response with the unencrypted flag set MUST process it as a FAIL.
		if !errors.Is(err, ErrAuthenticationFailed) {
			t.Errorf("error %v is not ErrAuthenticationFailed", err)
		}
		if client.IsConnected() {
			t.Error("client must close the session on the flag mismatch")
		}
	})
}

func TestWithSecretBytesCopy(t *testing.T) {
	t.Run("mutation after creation does not affect client", func(t *testing.T) {
		secret := []byte("original")
		client := NewClient(WithSecretBytes(secret))

		// Mutate the original slice
		secret[0] = 'X'

		if !bytes.Equal(client.secret, []byte("original")) {
			t.Errorf("got %v, want %v", client.secret, []byte("original"))
		}
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

		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrMaxPrompts) {
			t.Errorf("error %v is not %v", err, ErrMaxPrompts)
		}
	})
}

func TestClientIsTLSConnection(t *testing.T) {
	t.Run("nil connection returns false", func(t *testing.T) {
		client := NewClient(WithAddress("localhost:49"))
		if client.IsTLSConnection() {
			t.Errorf("expected false")
		}
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
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Close the client's own connection to force write errors
		client.mu.Lock()
		client.conn.Close()
		// Keep conn non-nil so connectLocked thinks we are connected
		// but the underlying fd is closed
		client.mu.Unlock()

		_, err = client.Authenticate(context.Background(), "user", "pass")
		if err == nil {
			t.Errorf("expected an error")
		}
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
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(err.Error(), "failed to read header") {
			t.Errorf("error %q does not contain %q", err.Error(), "failed to read header")
		}
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
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(err.Error(), "failed to read body") {
			t.Errorf("error %q does not contain %q", err.Error(), "failed to read body")
		}
	})
}

//nolint:gocyclo // exhaustive error-path coverage across many subtests; complexity is inherent
func TestAuthenticateWithContextErrors(t *testing.T) {
	t.Run("nil authCtx", func(t *testing.T) {
		client := NewClient(WithAddress("localhost:49"))
		_, err := client.AuthenticateWithContext(context.Background(), nil)
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrInvalidPacket) {
			t.Errorf("error %v is not %v", err, ErrInvalidPacket)
		}
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
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("error %v is not %v", err, ErrSessionNotFound)
		}
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
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrInvalidSequence) {
			t.Errorf("error %v is not %v", err, ErrInvalidSequence)
		}
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
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrInvalidType) {
			t.Errorf("error %v is not %v", err, ErrInvalidType)
		}
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
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(err.Error(), "failed to unmarshal REPLY") {
			t.Errorf("error %q does not contain %q", err.Error(), "failed to unmarshal REPLY")
		}
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
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.IsError() {
			t.Errorf("expected true")
		}
	})

	t.Run("interactive status in non-interactive authenticate is invalid", func(t *testing.T) {
		secret := []byte("testsecret")
		reply := &AuthenReply{Status: AuthenStatusGetPass, ServerMsg: []byte("Password: ")}
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
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrInvalidPacket) {
			t.Errorf("error %v is not %v", err, ErrInvalidPacket)
		}
		if result == nil {
			t.Errorf("expected non-nil")
		}
		if result.Status != AuthenStatusGetPass {
			t.Errorf("got %v, want %v", result.Status, AuthenStatusGetPass)
		}
		if client.IsConnected() {
			t.Errorf("expected false")
		}
	})

	t.Run("unknown status in non-interactive authenticate is invalid", func(t *testing.T) {
		secret := []byte("testsecret")
		reply := &AuthenReply{Status: 0xFF}
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
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrInvalidPacket) {
			t.Errorf("error %v is not %v", err, ErrInvalidPacket)
		}
		if result == nil {
			t.Errorf("expected non-nil")
		}
		if result.Status != 0xFF {
			t.Errorf("got %v, want %v", result.Status, 0xFF)
		}
		if client.IsConnected() {
			t.Errorf("expected false")
		}
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
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrAuthenFollow) {
			t.Errorf("error %v is not %v", err, ErrAuthenFollow)
		}
		if result == nil {
			t.Errorf("expected non-nil")
		}
		// Connection should be closed since server did not echo single-connect flag
		if client.IsConnected() {
			t.Errorf("expected false")
		}
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
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrAuthenRestart) {
			t.Errorf("error %v is not %v", err, ErrAuthenRestart)
		}
		if result == nil {
			t.Errorf("expected non-nil")
		}
		if client.IsConnected() {
			t.Errorf("expected false")
		}
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
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("error %v is not %v", err, ErrSessionNotFound)
		}
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
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrInvalidSequence) {
			t.Errorf("error %v is not %v", err, ErrInvalidSequence)
		}
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
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(err.Error(), "failed to unmarshal REPLY") {
			t.Errorf("error %q does not contain %q", err.Error(), "failed to unmarshal REPLY")
		}
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
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrInvalidType) {
			t.Errorf("error %v is not %v", err, ErrInvalidType)
		}
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
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.IsPass() {
			t.Errorf("expected true")
		}
		if client.IsConnected() {
			t.Errorf("expected false")
		}
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
		if !errors.Is(err, ErrAuthenticationFailed) {
			t.Fatalf("got %v, want ErrAuthenticationFailed", err)
		}
		if !result.IsFail() {
			t.Errorf("expected true")
		}
		if client.IsConnected() {
			t.Errorf("expected false")
		}
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
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.IsError() {
			t.Errorf("expected true")
		}
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
		if err == nil {
			t.Fatal("expected an error")
		}
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
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(err.Error(), "failed to unmarshal RESPONSE") {
			t.Errorf("error %q does not contain %q", err.Error(), "failed to unmarshal RESPONSE")
		}
	})

	t.Run("authorize send error", func(t *testing.T) {
		handler := func(conn net.Conn) {
			conn.Close()
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"), WithTimeout(time.Second))
		err := client.Connect(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Wait for server to close
		time.Sleep(50 * time.Millisecond)

		_, err = client.Authorize(context.Background(), "user", []string{"service=shell"})
		if err == nil {
			t.Errorf("expected an error")
		}
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
		if !errors.Is(err, ErrAuthorizationDenied) {
			t.Fatalf("got %v, want ErrAuthorizationDenied", err)
		}
		if result.IsPass() {
			t.Errorf("expected false")
		}
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
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(err.Error(), "failed to unmarshal REPLY") {
			t.Errorf("error %q does not contain %q", err.Error(), "failed to unmarshal REPLY")
		}
	})

	t.Run("accounting send error", func(t *testing.T) {
		handler := func(conn net.Conn) {
			conn.Close()
		}

		server := newMockServer(t, handler)
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"), WithTimeout(time.Second))
		err := client.Connect(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Wait for server to close
		time.Sleep(50 * time.Millisecond)

		_, err = client.Accounting(context.Background(), AcctFlagStart, "user", []string{"task_id=1"})
		if err == nil {
			t.Errorf("expected an error")
		}
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
		if !errors.Is(err, ErrAccountingFailed) {
			t.Fatalf("got %v, want ErrAccountingFailed", err)
		}
		if result.IsSuccess() {
			t.Errorf("expected false")
		}
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

		if err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("deadline reset error without timeout", func(t *testing.T) {
		serverConn, clientConn := net.Pipe()
		serverConn.Close()

		client := NewClient(
			WithAddress("localhost:49"),
			WithSecret("testsecret"),
			WithTimeout(0), // Clear any deadline from a previous operation.
		)
		client.conn = clientConn

		header := NewHeader(PacketTypeAuthen, 12345)
		header.SeqNo = 1
		err := client.sendPacket(context.Background(), header, []byte{0x01})

		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(err.Error(), "failed to set write deadline") {
			t.Errorf("error %q does not contain %q", err.Error(), "failed to set write deadline")
		}
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

		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(err.Error(), "failed to write body") {
			t.Errorf("error %q does not contain %q", err.Error(), "failed to write body")
		}
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
		if err == nil {
			t.Fatal("expected an error")
		}
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
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(err.Error(), "failed to read header") {
			t.Errorf("error %q does not contain %q", err.Error(), "failed to read header")
		}
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
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(err.Error(), "invalid header") {
			t.Errorf("error %q does not contain %q", err.Error(), "invalid header")
		}
		clientConn.Close()
	})
}

func TestClientRecvPacketTLSUnencryptedFlagCheck(t *testing.T) {
	t.Run("TLS connection rejects packet without unencrypted flag", func(t *testing.T) {
		cert, err := generateTestCertificate()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		serverConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}

		ln, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
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
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrInvalidPacket) {
			t.Errorf("error %v is not %v", err, ErrInvalidPacket)
		}
		if !strings.Contains(err.Error(), "RFC 9887") {
			t.Errorf("error %q does not contain %q", err.Error(), "RFC 9887")
		}
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
		if err == nil {
			t.Fatal("expected an error")
		}
	})
}

func TestClientPAPVersion(t *testing.T) {
	var version Version
	server := NewServer(WithServerAllowInsecure(true), WithAuthenticationHandler(AuthenHandlerFunc(func(_ context.Context, req *AuthenRequest) *AuthenReply {
		version = req.Header.Version
		return &AuthenReply{Status: AuthenStatusPass}
	})))
	client, cleanup := newServeConnPair(t, server, "")
	defer cleanup()
	if _, err := client.Authenticate(context.Background(), "user", "pass"); err != nil {
		t.Fatal(err)
	}
	if version != MajorVersion<<4|MinorVersionOne {
		t.Errorf("PAP version = %#x, want 0xc1", version)
	}
}

func TestClientTLSModeRejectsPlainDialer(t *testing.T) {
	peer, conn := net.Pipe()
	defer peer.Close()
	defer conn.Close()
	client := NewClient(WithTLSConfig(nil), WithDialer(&pipeDialer{conn: conn}))
	defer client.Close()
	if err := client.Connect(context.Background()); err == nil {
		t.Error("TLS-configured client accepted a plaintext connection")
	}
	if client.IsConnected() {
		t.Error("plaintext connection retained")
	}
}

func TestClientCancelWithoutDeadline(t *testing.T) {
	operations := map[string]func(*Client, context.Context) error{
		"PAP": func(c *Client, ctx context.Context) error {
			_, err := c.Authenticate(ctx, "user", "pass")
			return err
		},
		"ASCII": func(c *Client, ctx context.Context) error {
			_, err := c.AuthenticateASCII(ctx, "user", func(string, bool) (string, error) { return "pass", nil })
			return err
		},
		"authorization": func(c *Client, ctx context.Context) error {
			_, err := c.Authorize(ctx, "user", nil)
			return err
		},
		"accounting": func(c *Client, ctx context.Context) error {
			_, err := c.Accounting(ctx, AcctFlagStart, "user", nil)
			return err
		},
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			peer, conn := net.Pipe()
			defer peer.Close()
			defer conn.Close()
			client := NewClient(WithDialer(&pipeDialer{conn: conn}), WithTimeout(0))
			defer client.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- operation(client, ctx) }()
			// Cancel only after the request has been sent and the client is
			// waiting for a reply on an already established connection.
			if _, _, err := ReadRawPacket(peer, DefaultMaxBodyLength); err != nil {
				t.Fatal(err)
			}
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Error("cancelled operation succeeded")
				}
			case <-time.After(100 * time.Millisecond):
				t.Error("cancellation did not interrupt the read")
				peer.Close()
				<-done
			}
			if client.IsConnected() {
				t.Error("cancelled connection retained for reuse")
			}
		})
	}
}

func TestClientASCIIInputFailures(t *testing.T) {
	for _, oversized := range []bool{false, true} {
		t.Run(fmt.Sprint("oversized=", oversized), func(t *testing.T) {
			server := NewServer(WithAuthenticationHandler(AuthenHandlerFunc(func(context.Context, *AuthenRequest) *AuthenReply {
				return &AuthenReply{Status: AuthenStatusGetPass}
			})))
			client, cleanup := newServeConnPair(t, server, "")
			defer cleanup()
			var prompt func(string, bool) (string, error)
			if oversized {
				prompt = func(string, bool) (string, error) { return strings.Repeat("x", 65536), nil }
			}
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Errorf("prompt caused panic: %v", recovered)
				}
			}()
			if _, err := client.AuthenticateASCII(context.Background(), "user", prompt); err == nil {
				t.Error("invalid prompt input succeeded")
			}
			if client.IsConnected() {
				t.Error("unfinished authentication retained for reuse")
			}
		})
	}
}

func TestClientASCIIPromptBoundary(t *testing.T) {
	// Disable the server-side retry cap so this test can exercise the client's
	// own 20-prompt boundary (the server cap is covered by
	// TestServerLimitsGetUserRetries).
	server := NewServer(WithServerAllowInsecure(true), WithServerMaxAuthenRetries(0), WithAuthenticationHandler(&multiStepHandler{
		onStart: func(context.Context, *AuthenRequest) *AuthenReply {
			return &AuthenReply{Status: AuthenStatusGetPass}
		},
		onContinue: func(_ context.Context, req *AuthenContinueRequest) *AuthenReply {
			if req.Header.SeqNo == 2*maxASCIIPrompts+1 {
				return &AuthenReply{Status: AuthenStatusPass}
			}
			return &AuthenReply{Status: AuthenStatusGetPass}
		},
	}))
	client, cleanup := newServeConnPair(t, server, "")
	defer cleanup()
	prompts := 0
	reply, err := client.AuthenticateASCII(context.Background(), "user", func(string, bool) (string, error) {
		prompts++
		return "pass", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reply.IsPass() || prompts != maxASCIIPrompts {
		t.Errorf("reply = %v, prompts = %d", reply, prompts)
	}
}

func TestClientASCIISingleConnectNegotiation(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		t.Run(fmt.Sprint("accepted=", accepted), func(t *testing.T) {
			peer, conn := net.Pipe()
			client := NewClient(WithDialer(&pipeDialer{conn: conn}), WithSingleConnect(true))
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer peer.Close()
				server := NewServer()
				for i := range 2 {
					header, _, err := server.readPacket(peer, nil, false)
					if err != nil {
						t.Error(err)
						return
					}
					header.SeqNo++
					header.SetSingleConnect(accepted != (i == 1))
					status := AuthenStatusGetPass
					if i == 1 {
						status = AuthenStatusPass
					}
					body, _ := (&AuthenReply{Status: status}).MarshalBinary()
					header.Length = uint32(len(body))
					if err := server.writePacket(peer, header, body, nil, false); err != nil {
						t.Error(err)
						return
					}
				}
			}()
			defer func() {
				client.Close()
				peer.Close()
				<-done
			}()
			if _, err := client.AuthenticateASCII(context.Background(), "user", func(string, bool) (string, error) { return "pass", nil }); err != nil {
				t.Fatal(err)
			}
			if client.IsConnected() != accepted {
				t.Errorf("connection retention must follow the first reply: accepted=%v", accepted)
			}
		})
	}
}

func TestClientClearsExpiredDeadlines(t *testing.T) {
	for _, reading := range []bool{false, true} {
		t.Run(fmt.Sprint("reading=", reading), func(t *testing.T) {
			peer, conn := net.Pipe()
			client := NewClient(WithTimeout(0))
			client.conn = conn
			done := make(chan struct{})
			header := NewHeader(PacketTypeAuthen, 42)
			if reading {
				conn.SetReadDeadline(time.Now().Add(-time.Second))
			} else {
				conn.SetWriteDeadline(time.Now().Add(-time.Second))
			}
			go func() {
				defer close(done)
				if reading {
					_ = NewServer().writePacket(peer, header, nil, nil, false)
				} else {
					_, _, _ = ReadRawPacket(peer, DefaultMaxBodyLength)
				}
			}()
			defer func() {
				client.Close()
				peer.Close()
				<-done
			}()
			if reading {
				if _, _, err := client.recvPacket(context.Background()); err != nil {
					t.Error(err)
				}
			} else if err := client.sendPacket(context.Background(), header, nil); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestClientSentinelErrors(t *testing.T) {
	secret := []byte("testsecret")

	t.Run("authentication fail returns ErrAuthenticationFailed with reply", func(t *testing.T) {
		reply := &AuthenReply{Status: AuthenStatusFail, ServerMsg: []byte("denied")}
		replyBody, _ := reply.MarshalBinary()
		server := newMockServer(t, createMockHandler(secret, mockResponseConfig{
			packetType: PacketTypeAuthen,
			seqNo:      2,
			body:       replyBody,
		}))
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		got, err := client.Authenticate(context.Background(), "user", "badpass")
		if !errors.Is(err, ErrAuthenticationFailed) {
			t.Errorf("got %v, want ErrAuthenticationFailed", err)
		}
		if got == nil || !got.IsFail() {
			t.Error("expected the FAIL reply alongside the error")
		}
	})

	t.Run("ascii authentication fail returns ErrAuthenticationFailed with reply", func(t *testing.T) {
		reply := &AuthenReply{Status: AuthenStatusFail}
		replyBody, _ := reply.MarshalBinary()
		server := newMockServer(t, createMockHandler(secret, mockResponseConfig{
			packetType: PacketTypeAuthen,
			seqNo:      2,
			body:       replyBody,
		}))
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		got, err := client.AuthenticateASCII(context.Background(), "user", nil)
		if !errors.Is(err, ErrAuthenticationFailed) {
			t.Errorf("got %v, want ErrAuthenticationFailed", err)
		}
		if got == nil || !got.IsFail() {
			t.Error("expected the FAIL reply alongside the error")
		}
	})

	t.Run("authorization fail returns ErrAuthorizationDenied with response", func(t *testing.T) {
		resp := &AuthorResponse{Status: AuthorStatusFail, ServerMsg: []byte("no shell")}
		respBody, _ := resp.MarshalBinary()
		server := newMockServer(t, createMockHandler(secret, mockResponseConfig{
			packetType: PacketTypeAuthor,
			seqNo:      2,
			body:       respBody,
		}))
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		got, err := client.Authorize(context.Background(), "user", []string{"service=shell"})
		if !errors.Is(err, ErrAuthorizationDenied) {
			t.Errorf("got %v, want ErrAuthorizationDenied", err)
		}
		if got == nil || got.Status != AuthorStatusFail {
			t.Error("expected the FAIL response alongside the error")
		}
	})

	t.Run("accounting error returns ErrAccountingFailed with reply", func(t *testing.T) {
		reply := &AcctReply{Status: AcctStatusError}
		replyBody, _ := reply.MarshalBinary()
		server := newMockServer(t, createMockHandler(secret, mockResponseConfig{
			packetType: PacketTypeAcct,
			seqNo:      2,
			body:       replyBody,
		}))
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		got, err := client.Accounting(context.Background(), AcctFlagStart, "user", []string{"task_id=1"})
		if !errors.Is(err, ErrAccountingFailed) {
			t.Errorf("got %v, want ErrAccountingFailed", err)
		}
		if got == nil || !got.IsError() {
			t.Error("expected the ERROR reply alongside the error")
		}
	})

	t.Run("read timeout returns ErrTimeout", func(t *testing.T) {
		server := newMockServer(t, func(conn net.Conn) {
			// Consume the request and never reply; the client read deadline fires.
			defer conn.Close()
			_, _ = io.Copy(io.Discard, conn)
		})
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"), WithTimeout(100*time.Millisecond))
		_, err := client.Authenticate(context.Background(), "user", "pass")
		if !errors.Is(err, ErrTimeout) {
			t.Errorf("got %v, want ErrTimeout", err)
		}
	})
}

func TestClientAuthenticateCHAP(t *testing.T) {
	secret := []byte("chap-secret")
	runServer := func(t *testing.T, accept bool) *mockServer {
		return newMockServer(t, func(conn net.Conn) {
			defer conn.Close()
			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)
			header := &Header{}
			header.UnmarshalBinary(headerBuf)
			body := make([]byte, header.Length)
			io.ReadFull(conn, body)
			deob := Obfuscate(header, secret, body)

			start := &AuthenStart{}
			if err := start.UnmarshalBinary(deob); err != nil {
				t.Errorf("server could not decode CHAP START: %v", err)
				return
			}
			status := AuthenStatusFail
			if start.AuthenType == AuthenTypeCHAP {
				ok, err := VerifyCHAP(secret, start.Data)
				if err != nil {
					t.Errorf("VerifyCHAP: %v", err)
				}
				if ok && accept {
					status = AuthenStatusPass
				}
			}
			reply := &AuthenReply{Status: status}
			replyBody, _ := reply.MarshalBinary()
			respHeader := &Header{Version: 0xc1, Type: PacketTypeAuthen, SeqNo: 2, SessionID: header.SessionID, Length: uint32(len(replyBody))}
			respHeaderData, _ := respHeader.MarshalBinary()
			conn.Write(respHeaderData)
			conn.Write(Obfuscate(respHeader, secret, replyBody))
		})
	}

	t.Run("valid response passes", func(t *testing.T) {
		server := runServer(t, true)
		defer server.Close()
		client := NewClient(WithAddress(server.Addr()), WithSecret("chap-secret"))
		reply, err := client.AuthenticateCHAP(context.Background(), "alice", 0x01, secret, []byte("a-good-challenge"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reply.IsPass() {
			t.Error("expected PASS for a valid CHAP response")
		}
	})

	t.Run("wrong secret fails", func(t *testing.T) {
		server := runServer(t, true)
		defer server.Close()
		// Client computes the response with a different secret than the server.
		client := NewClient(WithAddress(server.Addr()), WithSecret("chap-secret"))
		reply, err := client.AuthenticateCHAP(context.Background(), "alice", 0x01, []byte("other"), []byte("a-good-challenge"))
		if !errors.Is(err, ErrAuthenticationFailed) {
			t.Fatalf("got %v, want ErrAuthenticationFailed", err)
		}
		if reply == nil || !reply.IsFail() {
			t.Error("expected the FAIL reply alongside the error")
		}
	})
}

func TestClientFlagMismatchIsAuthFailure(t *testing.T) {
	// RFC 8907 10.5.2: a client with a configured secret that receives a
	// response carrying TAC_PLUS_UNENCRYPTED_FLAG MUST close the session and
	// process it the same way as a STATUS_FAIL. The error must therefore be
	// ErrAuthenticationFailed, not a generic protocol error.
	secret := []byte("testsecret")
	server := newMockServer(t, func(conn net.Conn) {
		defer conn.Close()
		headerBuf := make([]byte, HeaderLength)
		io.ReadFull(conn, headerBuf)
		header := &Header{}
		header.UnmarshalBinary(headerBuf)
		body := make([]byte, header.Length)
		io.ReadFull(conn, body)

		// Reply with the unencrypted flag set and a cleartext body, which a
		// secret-configured client must treat as a FAIL.
		reply := &AuthenReply{Status: AuthenStatusPass}
		replyBody, _ := reply.MarshalBinary()
		respHeader := &Header{Version: 0xc1, Type: PacketTypeAuthen, SeqNo: 2, SessionID: header.SessionID, Length: uint32(len(replyBody))}
		respHeader.SetUnencrypted(true)
		respHeaderData, _ := respHeader.MarshalBinary()
		conn.Write(respHeaderData)
		conn.Write(replyBody) // cleartext, matching the flag
	})
	defer server.Close()

	client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
	_, err := client.Authenticate(context.Background(), "user", "pass")
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Errorf("got %v, want ErrAuthenticationFailed", err)
	}
	if client.IsConnected() {
		t.Error("client must close the session on a flag mismatch")
	}
	_ = secret
}

func TestAuthenticateWithContextChangePassword(t *testing.T) {
	// RFC 8907 Section 5.1: the CHPASS action must be reachable from the client.
	secret := []byte("testsecret")
	seenAction := make(chan AuthenAction, 1)
	server := newMockServer(t, func(conn net.Conn) {
		defer conn.Close()
		headerBuf := make([]byte, HeaderLength)
		io.ReadFull(conn, headerBuf)
		header := &Header{}
		header.UnmarshalBinary(headerBuf)
		body := make([]byte, header.Length)
		io.ReadFull(conn, body)
		deob := Obfuscate(header, secret, body)
		start := &AuthenStart{}
		if err := start.UnmarshalBinary(deob); err == nil {
			seenAction <- start.Action
		}

		reply := &AuthenReply{Status: AuthenStatusPass}
		replyBody, _ := reply.MarshalBinary()
		respHeader := &Header{Version: 0xc1, Type: PacketTypeAuthen, SeqNo: 2, SessionID: header.SessionID, Length: uint32(len(replyBody))}
		respHeaderData, _ := respHeader.MarshalBinary()
		conn.Write(respHeaderData)
		conn.Write(Obfuscate(respHeader, secret, replyBody))
	})
	defer server.Close()

	client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
	reply, err := client.AuthenticateWithContext(context.Background(), &AuthenticateContext{
		Action:   AuthenActionChPass,
		Username: "user",
		Password: "newpass",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reply.IsPass() {
		t.Error("expected pass")
	}
	if got := <-seenAction; got != AuthenActionChPass {
		t.Errorf("got action %#x on the wire, want CHPASS %#x", got, AuthenActionChPass)
	}
}

func TestAuthenticateWithContextSession(t *testing.T) {
	t.Run("caller-supplied session ID is used on the wire", func(t *testing.T) {
		secret := []byte("testsecret")
		seenSessionID := make(chan uint32, 1)
		server := newMockServer(t, func(conn net.Conn) {
			defer conn.Close()
			headerBuf := make([]byte, HeaderLength)
			io.ReadFull(conn, headerBuf)
			header := &Header{}
			header.UnmarshalBinary(headerBuf)
			body := make([]byte, header.Length)
			io.ReadFull(conn, body)
			seenSessionID <- header.SessionID

			reply := &AuthenReply{Status: AuthenStatusPass}
			replyBody, _ := reply.MarshalBinary()
			respHeader := &Header{
				Version:   0xc1,
				Type:      PacketTypeAuthen,
				SeqNo:     2,
				SessionID: header.SessionID,
				Length:    uint32(len(replyBody)),
			}
			respHeaderData, _ := respHeader.MarshalBinary()
			conn.Write(respHeaderData)
			conn.Write(Obfuscate(respHeader, secret, replyBody))
		})
		defer server.Close()

		client := NewClient(WithAddress(server.Addr()), WithSecret("testsecret"))
		reply, err := client.AuthenticateWithContext(context.Background(), &AuthenticateContext{
			Session:  NewSessionWithID(0x1234abcd, true),
			Username: "user",
			Password: "pass",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reply.IsPass() {
			t.Error("expected pass")
		}
		if got := <-seenSessionID; got != 0x1234abcd {
			t.Errorf("got session ID %#x, want 0x1234abcd", got)
		}
	})
}
