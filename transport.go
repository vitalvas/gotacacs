package gotacacs

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"
)

// TLSConn represents a TLS-secured connection.
// Use IsTLSConn to check if a connection is TLS-secured.
type TLSConn interface {
	net.Conn
	// ConnectionState returns the TLS connection state.
	ConnectionState() tls.ConnectionState
}

// Listener represents a network listener for accepting TACACS+ connections.
type Listener interface {
	// Accept waits for and returns the next connection to the listener.
	Accept() (net.Conn, error)

	// Close closes the listener.
	Close() error

	// Addr returns the listener's network address.
	Addr() net.Addr
}

// Dialer represents a dialer for establishing TACACS+ connections.
type Dialer interface {
	// Dial connects to the address on the named network.
	Dial(ctx context.Context, network, address string) (net.Conn, error)
}

// IsTLSConn returns true if the connection is TLS-secured.
func IsTLSConn(conn net.Conn) bool {
	_, ok := conn.(TLSConn)
	return ok
}

// tlsListener wraps a net.Listener for TLS connections.
type tlsListener struct {
	net.Listener
}

// Accept accepts a TLS connection from the listener.
func (l *tlsListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tc, ok := conn.(*tls.Conn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("expected TLS connection")
	}
	return tc, nil
}

// TCPDialer implements Dialer for TCP connections.
type TCPDialer struct {
	// Timeout is the maximum duration for the dial to complete.
	// If zero, no timeout is applied.
	Timeout time.Duration

	// LocalAddr is the local address to use when dialing.
	// If nil, a local address is automatically chosen.
	LocalAddr *net.TCPAddr
}

// Dial connects to the address using TCP.
func (d *TCPDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   d.Timeout,
		LocalAddr: d.LocalAddr,
	}

	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// TLSDialer implements Dialer for TLS connections.
type TLSDialer struct {
	// Timeout is the maximum duration for the dial to complete.
	Timeout time.Duration

	// Config is the TLS configuration to use.
	// If nil, a default configuration is used.
	Config *tls.Config
}

// Dial connects to the address using TLS.
func (d *TLSDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{
			Timeout: d.Timeout,
		},
		Config: d.Config,
	}

	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	tc, ok := conn.(*tls.Conn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("expected TLS connection")
	}
	return tc, nil
}

// ListenTCP creates a TCP listener on the specified address.
func ListenTCP(address string) (Listener, error) {
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", address, err)
	}
	return ln, nil
}

// ListenTLS creates a TLS listener on the specified address.
func ListenTLS(address string, config *tls.Config) (Listener, error) {
	if config == nil {
		return nil, fmt.Errorf("TLS config is required")
	}
	cfg := config.Clone()
	// RFC 9887: enforce TLS 1.3 for TACACS+ over TLS listeners.
	cfg.MinVersion = tls.VersionTLS13
	cfg.MaxVersion = tls.VersionTLS13

	ln, err := tls.Listen("tcp", address, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", address, err)
	}
	return &tlsListener{Listener: ln}, nil
}

// writeAll writes all bytes to the connection, handling partial writes.
// It loops until all bytes are written or an error occurs.
// Returns io.ErrShortWrite if Write returns 0 with no error.
func writeAll(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
