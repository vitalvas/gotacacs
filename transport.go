package gotacacs

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// Conn represents a network connection for TACACS+ communication.
// It extends net.Conn with additional context awareness.
type Conn interface {
	net.Conn
}

// Listener represents a network listener for accepting TACACS+ connections.
type Listener interface {
	// Accept waits for and returns the next connection to the listener.
	Accept() (Conn, error)

	// Close closes the listener.
	Close() error

	// Addr returns the listener's network address.
	Addr() net.Addr
}

// Dialer represents a dialer for establishing TACACS+ connections.
type Dialer interface {
	// Dial connects to the address on the named network.
	Dial(ctx context.Context, network, address string) (Conn, error)
}

// tcpConn wraps a net.Conn to implement Conn interface.
type tcpConn struct {
	net.Conn
}

// tcpListener wraps a net.Listener to implement Listener interface.
type tcpListener struct {
	net.Listener
}

// Accept accepts a connection from the listener.
func (l *tcpListener) Accept() (Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &tcpConn{Conn: conn}, nil
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
func (d *TCPDialer) Dial(ctx context.Context, network, address string) (Conn, error) {
	dialer := &net.Dialer{
		Timeout:   d.Timeout,
		LocalAddr: d.LocalAddr,
	}

	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &tcpConn{Conn: conn}, nil
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
func (d *TLSDialer) Dial(ctx context.Context, network, address string) (Conn, error) {
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
	return &tcpConn{Conn: conn}, nil
}

// ListenTCP creates a TCP listener on the specified address.
func ListenTCP(address string) (Listener, error) {
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", address, err)
	}
	return &tcpListener{Listener: ln}, nil
}

// ListenTLS creates a TLS listener on the specified address.
func ListenTLS(address string, config *tls.Config) (Listener, error) {
	if config == nil {
		return nil, fmt.Errorf("TLS config is required")
	}
	ln, err := tls.Listen("tcp", address, config)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", address, err)
	}
	return &tcpListener{Listener: ln}, nil
}

// DefaultTCPDialer returns a TCP dialer with default settings.
func DefaultTCPDialer() *TCPDialer {
	return &TCPDialer{
		Timeout: 30 * time.Second,
	}
}

// DefaultTLSDialer returns a TLS dialer with default settings.
func DefaultTLSDialer(config *tls.Config) *TLSDialer {
	return &TLSDialer{
		Timeout: 30 * time.Second,
		Config:  config,
	}
}

// NewTLSConfig creates a TLS config for TACACS+ connections.
// This is a helper function to create a basic TLS configuration.
func NewTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// NewTLSClientConfig creates a TLS config for TACACS+ client connections.
func NewTLSClientConfig(serverName string, insecureSkipVerify bool) *tls.Config {
	return &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: insecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}
}
