package gotacacs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTCPDialer(t *testing.T) {
	t.Run("dial successful connection", func(t *testing.T) {
		// Start a test server
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer ln.Close()

		go func() {
			conn, _ := ln.Accept()
			if conn != nil {
				conn.Close()
			}
		}()

		dialer := &TCPDialer{Timeout: 5 * time.Second}
		conn, err := dialer.Dial(context.Background(), "tcp", ln.Addr().String())
		require.NoError(t, err)
		require.NotNil(t, conn)
		conn.Close()
	})

	t.Run("dial with timeout", func(t *testing.T) {
		dialer := &TCPDialer{Timeout: 10 * time.Millisecond}

		// Try to connect to a non-routable address
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		_, err := dialer.Dial(ctx, "tcp", "10.255.255.1:49")
		assert.Error(t, err)
	})

	t.Run("dial connection refused", func(t *testing.T) {
		dialer := &TCPDialer{Timeout: 1 * time.Second}
		_, err := dialer.Dial(context.Background(), "tcp", "127.0.0.1:1")
		assert.Error(t, err)
	})
}

func TestTLSDialer(t *testing.T) {
	t.Run("dial with TLS", func(t *testing.T) {
		// Generate test certificate
		cert, err := generateTestCertificate()
		require.NoError(t, err)

		serverConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		// Start TLS server
		ln, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
		require.NoError(t, err)
		defer ln.Close()

		serverDone := make(chan struct{})
		go func() {
			defer close(serverDone)
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Perform handshake by reading/writing
			buf := make([]byte, 1)
			conn.Read(buf)
			conn.Close()
		}()

		clientConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		dialer := &TLSDialer{
			Timeout: 5 * time.Second,
			Config:  clientConfig,
		}

		conn, err := dialer.Dial(context.Background(), "tcp", ln.Addr().String())
		require.NoError(t, err)
		require.NotNil(t, conn)
		conn.Write([]byte{0x00}) // Trigger server read
		conn.Close()
		<-serverDone
	})

	t.Run("dial TLS connection refused", func(t *testing.T) {
		dialer := &TLSDialer{
			Timeout: 1 * time.Second,
			Config:  &tls.Config{InsecureSkipVerify: true},
		}
		_, err := dialer.Dial(context.Background(), "tcp", "127.0.0.1:1")
		assert.Error(t, err)
	})
}

func TestListenTCP(t *testing.T) {
	t.Run("listen and accept", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)
		require.NotNil(t, ln)
		defer ln.Close()

		// Check address
		addr := ln.Addr()
		assert.NotNil(t, addr)
		assert.Contains(t, addr.String(), "127.0.0.1")

		// Accept in goroutine
		acceptDone := make(chan struct{})
		go func() {
			conn, err := ln.Accept()
			if err == nil {
				conn.Close()
			}
			close(acceptDone)
		}()

		// Connect
		dialer := &TCPDialer{Timeout: 30 * time.Second}
		conn, err := dialer.Dial(context.Background(), "tcp", ln.Addr().String())
		require.NoError(t, err)
		conn.Close()

		<-acceptDone
	})

	t.Run("listen on invalid address", func(t *testing.T) {
		_, err := ListenTCP("invalid:address:format")
		assert.Error(t, err)
	})
}

func TestListenTLS(t *testing.T) {
	t.Run("listen with TLS", func(t *testing.T) {
		cert, err := generateTestCertificate()
		require.NoError(t, err)

		config := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		ln, err := ListenTLS("127.0.0.1:0", config)
		require.NoError(t, err)
		require.NotNil(t, ln)
		defer ln.Close()

		addr := ln.Addr()
		assert.NotNil(t, addr)
	})

	t.Run("listen TLS without config", func(t *testing.T) {
		_, err := ListenTLS("127.0.0.1:0", nil)
		assert.Error(t, err)
	})

	t.Run("listen TLS on invalid address", func(t *testing.T) {
		config := &tls.Config{}
		_, err := ListenTLS("invalid:address:format", config)
		assert.Error(t, err)
	})
}

func TestTCPListenerAcceptClose(t *testing.T) {
	t.Run("accept after close returns error", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)

		ln.Close()

		_, err = ln.Accept()
		assert.Error(t, err)
	})
}

func TestConnInterface(t *testing.T) {
	t.Run("tcpConn implements Conn", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer ln.Close()

		go func() {
			conn, _ := ln.Accept()
			if conn != nil {
				conn.Write([]byte("test"))
				conn.Close()
			}
		}()

		netConn, err := net.Dial("tcp", ln.Addr().String())
		require.NoError(t, err)

		conn := &tcpConn{Conn: netConn}

		// Test all net.Conn methods through our wrapper
		assert.NotNil(t, conn.LocalAddr())
		assert.NotNil(t, conn.RemoteAddr())

		err = conn.SetDeadline(time.Now().Add(time.Second))
		assert.NoError(t, err)

		err = conn.SetReadDeadline(time.Now().Add(time.Second))
		assert.NoError(t, err)

		err = conn.SetWriteDeadline(time.Now().Add(time.Second))
		assert.NoError(t, err)

		buf := make([]byte, 4)
		n, err := conn.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 4, n)
		assert.Equal(t, []byte("test"), buf)

		conn.Close()
	})
}

func TestDialerInterface(t *testing.T) {
	t.Run("TCPDialer implements Dialer", func(_ *testing.T) {
		var _ Dialer = (*TCPDialer)(nil)
	})

	t.Run("TLSDialer implements Dialer", func(_ *testing.T) {
		var _ Dialer = (*TLSDialer)(nil)
	})
}

func TestListenerInterface(t *testing.T) {
	t.Run("tcpListener implements Listener", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)
		defer ln.Close()

		// Verify it implements Listener by calling interface methods
		assert.NotNil(t, ln.Addr())
	})
}

func TestWriteAll(t *testing.T) {
	t.Run("write all bytes successfully", func(t *testing.T) {
		// Create a pipe for testing
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		data := []byte("hello world test data")
		done := make(chan error)

		go func() {
			done <- writeAll(client, data)
		}()

		// Read all data on server side
		buf := make([]byte, len(data))
		_, err := server.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, data, buf)

		err = <-done
		assert.NoError(t, err)
	})

	t.Run("write empty data", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		err := writeAll(client, []byte{})
		assert.NoError(t, err)
	})

	t.Run("write to closed connection", func(t *testing.T) {
		server, client := net.Pipe()
		server.Close()

		err := writeAll(client, []byte("test"))
		assert.Error(t, err)
		client.Close()
	})

	t.Run("zero-progress write returns error", func(t *testing.T) {
		// Create a mock connection that returns 0 bytes written with no error
		mockConn := &zeroWriteConn{}

		err := writeAll(mockConn, []byte("test"))
		assert.ErrorIs(t, err, io.ErrShortWrite)
	})
}

// zeroWriteConn is a mock connection that returns 0 bytes written with no error.
type zeroWriteConn struct {
	net.Conn
}

func (c *zeroWriteConn) Write([]byte) (int, error) {
	return 0, nil
}

func TestIsTLSConn(t *testing.T) {
	t.Run("TLS connection returns true", func(t *testing.T) {
		cert, err := generateTestCertificate()
		require.NoError(t, err)

		serverConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		ln, err := ListenTLS("127.0.0.1:0", serverConfig)
		require.NoError(t, err)
		defer ln.Close()

		serverDone := make(chan Conn)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				serverDone <- nil
				return
			}
			// Perform handshake by reading/writing
			buf := make([]byte, 1)
			conn.Read(buf)
			serverDone <- conn
		}()

		clientConfig := &tls.Config{InsecureSkipVerify: true}
		dialer := &TLSDialer{Timeout: 5 * time.Second, Config: clientConfig}

		conn, err := dialer.Dial(context.Background(), "tcp", ln.Addr().String())
		require.NoError(t, err)
		defer conn.Close()

		// Trigger handshake completion
		conn.Write([]byte{0x00})

		assert.True(t, IsTLSConn(conn), "TLS dialer connection should be TLS")

		serverConn := <-serverDone
		if serverConn != nil {
			defer serverConn.Close()
			assert.True(t, IsTLSConn(serverConn), "TLS listener connection should be TLS")
		}
	})

	t.Run("TCP connection returns false", func(t *testing.T) {
		ln, err := ListenTCP("127.0.0.1:0")
		require.NoError(t, err)
		defer ln.Close()

		go func() {
			conn, _ := ln.Accept()
			if conn != nil {
				conn.Close()
			}
		}()

		dialer := &TCPDialer{Timeout: 5 * time.Second}
		conn, err := dialer.Dial(context.Background(), "tcp", ln.Addr().String())
		require.NoError(t, err)
		defer conn.Close()

		assert.False(t, IsTLSConn(conn), "TCP connection should not be TLS")
	})
}

func TestTLSConnInterface(t *testing.T) {
	t.Run("tlsConn implements TLSConn interface", func(t *testing.T) {
		cert, err := generateTestCertificate()
		require.NoError(t, err)

		serverConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
		ln, err := ListenTLS("127.0.0.1:0", serverConfig)
		require.NoError(t, err)
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err == nil {
				buf := make([]byte, 1)
				conn.Read(buf)
				conn.Close()
			}
		}()

		clientConfig := &tls.Config{InsecureSkipVerify: true}
		dialer := &TLSDialer{Timeout: 5 * time.Second, Config: clientConfig}

		conn, err := dialer.Dial(context.Background(), "tcp", ln.Addr().String())
		require.NoError(t, err)
		defer conn.Close()

		// Verify it implements TLSConn
		tlsConn, ok := conn.(TLSConn)
		require.True(t, ok, "should implement TLSConn interface")

		// Verify ConnectionState works
		state := tlsConn.ConnectionState()
		assert.True(t, state.HandshakeComplete, "handshake should be complete")

		conn.Write([]byte{0x00})
	})
}

// generateTestCertificate generates a self-signed certificate for testing.
func generateTestCertificate() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}, nil
}
