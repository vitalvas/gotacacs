package gotacacs

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Client represents a TACACS+ client for communicating with a TACACS+ server.
type Client struct {
	mu      sync.Mutex
	address string
	secret  []byte
	dialer  Dialer
	conn    Conn
	session *Session

	timeout       time.Duration
	singleConnect bool
	maxBodyLength uint32
}

// ClientOption is a function that configures a Client.
type ClientOption func(*Client)

// WithTimeout sets the connection and operation timeout.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.timeout = timeout
	}
}

// WithSecret sets the shared secret for packet obfuscation.
func WithSecret(secret string) ClientOption {
	return func(c *Client) {
		c.secret = []byte(secret)
	}
}

// WithSecretBytes sets the shared secret as bytes for packet obfuscation.
func WithSecretBytes(secret []byte) ClientOption {
	return func(c *Client) {
		c.secret = secret
	}
}

// WithTLSConfig sets the TLS configuration for secure connections.
func WithTLSConfig(config *tls.Config) ClientOption {
	return func(c *Client) {
		c.dialer = &TLSDialer{
			Timeout: c.timeout,
			Config:  config,
		}
	}
}

// WithDialer sets a custom dialer for connections.
// If dialer is nil, the default TCP dialer is retained.
func WithDialer(dialer Dialer) ClientOption {
	return func(c *Client) {
		if dialer != nil {
			c.dialer = dialer
		}
	}
}

// WithSingleConnect enables single-connect mode.
// In this mode, the connection is reused across multiple sessions.
func WithSingleConnect(enabled bool) ClientOption {
	return func(c *Client) {
		c.singleConnect = enabled
	}
}

// WithMaxBodyLength sets the maximum allowed body length for incoming packets.
// This prevents memory exhaustion attacks from malicious servers.
func WithMaxBodyLength(maxLength uint32) ClientOption {
	return func(c *Client) {
		c.maxBodyLength = maxLength
	}
}

// NewClient creates a new TACACS+ client.
func NewClient(address string, opts ...ClientOption) *Client {
	c := &Client{
		address:       address,
		timeout:       30 * time.Second,
		dialer:        DefaultTCPDialer(),
		maxBodyLength: DefaultMaxBodyLength,
	}

	for _, opt := range opts {
		opt(c)
	}

	// Update dialer timeout after all options are applied
	switch d := c.dialer.(type) {
	case *TCPDialer:
		d.Timeout = c.timeout
	case *TLSDialer:
		d.Timeout = c.timeout
	}

	return c
}

// Connect establishes a connection to the TACACS+ server.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connectLocked(ctx)
}

// connectLocked establishes a connection without acquiring the lock.
// The caller must hold c.mu.
func (c *Client) connectLocked(ctx context.Context) error {
	if c.conn != nil {
		return nil // Already connected
	}

	conn, err := c.dialer.Dial(ctx, "tcp", c.address)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", c.address, err)
	}

	c.conn = conn
	return nil
}

// Close closes the connection to the server.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil
	}

	err := c.conn.Close()
	c.conn = nil
	c.session = nil
	return err
}

// IsConnected returns true if the client has an active connection.
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}

// sendPacket sends a packet to the server with proper framing and obfuscation.
func (c *Client) sendPacket(header *Header, body []byte) error {
	// Set body length in header
	header.Length = uint32(len(body))

	// Set single-connect flag if enabled
	if c.singleConnect {
		header.SetSingleConnect(true)
	}

	// Obfuscate body
	obfuscatedBody := Obfuscate(header, c.secret, body)

	// Marshal header
	headerData, err := header.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal header: %w", err)
	}

	// Set deadline for write
	if c.timeout > 0 {
		if err := c.conn.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
			return fmt.Errorf("failed to set write deadline: %w", err)
		}
	}

	// Write header and body using writeAll to handle partial writes
	if err := writeAll(c.conn, headerData); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	if len(obfuscatedBody) > 0 {
		if err := writeAll(c.conn, obfuscatedBody); err != nil {
			return fmt.Errorf("failed to write body: %w", err)
		}
	}

	return nil
}

// recvPacket receives a packet from the server with deobfuscation.
func (c *Client) recvPacket() (*Header, []byte, error) {
	// Set deadline for read
	if c.timeout > 0 {
		if err := c.conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
			return nil, nil, fmt.Errorf("failed to set read deadline: %w", err)
		}
	}

	// Read header
	headerBuf := make([]byte, HeaderLength)
	if _, err := io.ReadFull(c.conn, headerBuf); err != nil {
		if err == io.EOF {
			return nil, nil, ErrConnectionClosed
		}
		return nil, nil, fmt.Errorf("failed to read header: %w", err)
	}

	header := &Header{}
	if err := header.UnmarshalBinary(headerBuf); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal header: %w", err)
	}

	// Validate header version and type
	if err := header.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid header: %w", err)
	}

	// Validate body length to prevent memory exhaustion
	if header.Length > c.maxBodyLength {
		return nil, nil, fmt.Errorf("%w: body length %d exceeds maximum %d", ErrBodyTooLarge, header.Length, c.maxBodyLength)
	}

	// Read body
	var body []byte
	if header.Length > 0 {
		body = make([]byte, header.Length)
		if _, err := io.ReadFull(c.conn, body); err != nil {
			return nil, nil, fmt.Errorf("failed to read body: %w", err)
		}

		// Obfuscate body
		body = Obfuscate(header, c.secret, body)
	}

	return header, body, nil
}

// newSession creates a new client session.
func (c *Client) newSession() (*Session, error) {
	session, err := NewSession(true)
	if err != nil {
		return nil, err
	}
	c.session = session
	return session, nil
}

// AuthenticateContext holds the context for multi-step authentication.
type AuthenticateContext struct {
	Session    *Session
	Username   string
	Password   string
	Port       string
	RemoteAddr string
}

// Authenticate performs authentication with the TACACS+ server.
// It handles the complete authentication flow including multi-step interactions.
func (c *Client) Authenticate(ctx context.Context, username, password string) (*AuthenReply, error) {
	return c.AuthenticateWithContext(ctx, &AuthenticateContext{
		Username: username,
		Password: password,
	})
}

// AuthenticateWithContext performs authentication with additional context.
func (c *Client) AuthenticateWithContext(ctx context.Context, authCtx *AuthenticateContext) (*AuthenReply, error) {
	if authCtx == nil {
		return nil, fmt.Errorf("%w: authCtx cannot be nil", ErrInvalidPacket)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Ensure we're connected
	if err := c.connectLocked(ctx); err != nil {
		return nil, err
	}

	// Create new session
	session, err := c.newSession()
	if err != nil {
		return nil, err
	}

	// Create START packet
	start := &AuthenStart{
		Action:     AuthenActionLogin,
		PrivLevel:  1,
		AuthenType: AuthenTypePAP, // Use PAP for simple password auth
		Service:    AuthenServiceLogin,
		User:       []byte(authCtx.Username),
		Port:       []byte(authCtx.Port),
		RemoteAddr: []byte(authCtx.RemoteAddr),
		Data:       []byte(authCtx.Password), // PAP sends password in START
	}

	startBody, err := start.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal START packet: %w", err)
	}

	// Create header
	header := NewHeader(PacketTypeAuthen, session.ID())
	seqNo, err := session.NextSeqNo()
	if err != nil {
		return nil, err
	}
	header.SeqNo = seqNo

	// Send START packet
	if err := c.sendPacket(header, startBody); err != nil {
		c.closeConnection()
		return nil, err
	}

	// Receive reply
	respHeader, respBody, err := c.recvPacket()
	if err != nil {
		c.closeConnection()
		return nil, err
	}

	// Validate response
	if respHeader.Type != PacketTypeAuthen {
		c.closeConnection()
		return nil, fmt.Errorf("%w: expected AUTHEN, got %d", ErrInvalidType, respHeader.Type)
	}
	if respHeader.SessionID != session.ID() {
		c.closeConnection()
		return nil, fmt.Errorf("%w: session ID mismatch", ErrSessionNotFound)
	}
	if !session.ValidateSeqNo(respHeader.SeqNo) {
		c.closeConnection()
		return nil, fmt.Errorf("%w: expected %d, got %d", ErrInvalidSequence, session.SeqNo()+1, respHeader.SeqNo)
	}
	session.UpdateSeqNo(respHeader.SeqNo)

	// Parse reply
	reply := &AuthenReply{}
	if err := reply.UnmarshalBinary(respBody); err != nil {
		c.closeConnection()
		return nil, fmt.Errorf("failed to unmarshal REPLY: %w", err)
	}

	// Update session state based on reply
	switch reply.Status {
	case AuthenStatusPass:
		session.SetState(SessionStateComplete)
	case AuthenStatusFail, AuthenStatusError:
		session.SetState(SessionStateError)
	case AuthenStatusFollow:
		session.SetState(SessionStateComplete)
		if !c.singleConnect {
			c.closeConnection()
		}
		return reply, fmt.Errorf("%w: %s", ErrAuthenFollow, string(reply.ServerMsg))
	case AuthenStatusRestart:
		session.SetState(SessionStateComplete)
		if !c.singleConnect {
			c.closeConnection()
		}
		return reply, ErrAuthenRestart
	}

	// Close connection if not using single-connect
	if !c.singleConnect {
		c.closeConnection()
	}

	return reply, nil
}

// AuthenticateASCII performs ASCII authentication with interactive prompts.
// The promptHandler is called for each GETDATA/GETUSER/GETPASS request.
func (c *Client) AuthenticateASCII(ctx context.Context, username string, promptHandler func(prompt string, noEcho bool) (string, error)) (*AuthenReply, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Ensure we're connected
	if err := c.connectLocked(ctx); err != nil {
		return nil, err
	}

	// Create new session
	session, err := c.newSession()
	if err != nil {
		return nil, err
	}

	// Create START packet for ASCII auth
	start := &AuthenStart{
		Action:     AuthenActionLogin,
		PrivLevel:  1,
		AuthenType: AuthenTypeASCII,
		Service:    AuthenServiceLogin,
		User:       []byte(username),
	}

	startBody, err := start.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal START packet: %w", err)
	}

	// Create header
	header := NewHeader(PacketTypeAuthen, session.ID())
	seqNo, err := session.NextSeqNo()
	if err != nil {
		return nil, err
	}
	header.SeqNo = seqNo

	// Send START packet
	if err := c.sendPacket(header, startBody); err != nil {
		c.closeConnection()
		return nil, err
	}

	// Authentication loop
	for {
		// Receive reply
		respHeader, respBody, err := c.recvPacket()
		if err != nil {
			c.closeConnection()
			return nil, err
		}

		// Validate response
		if respHeader.Type != PacketTypeAuthen {
			c.closeConnection()
			return nil, fmt.Errorf("%w: expected AUTHEN, got %d", ErrInvalidType, respHeader.Type)
		}
		if respHeader.SessionID != session.ID() {
			c.closeConnection()
			return nil, fmt.Errorf("%w: session ID mismatch", ErrSessionNotFound)
		}
		if !session.ValidateSeqNo(respHeader.SeqNo) {
			c.closeConnection()
			return nil, fmt.Errorf("%w: expected %d, got %d", ErrInvalidSequence, session.SeqNo()+1, respHeader.SeqNo)
		}

		// Parse reply
		reply := &AuthenReply{}
		if err := reply.UnmarshalBinary(respBody); err != nil {
			c.closeConnection()
			return nil, fmt.Errorf("failed to unmarshal REPLY: %w", err)
		}

		session.UpdateSeqNo(respHeader.SeqNo)

		// Check if authentication is complete
		if reply.IsPass() {
			session.SetState(SessionStateComplete)
			if !c.singleConnect {
				c.closeConnection()
			}
			return reply, nil
		}

		if reply.IsFail() || reply.IsError() {
			session.SetState(SessionStateError)
			if !c.singleConnect {
				c.closeConnection()
			}
			return reply, nil
		}

		// Handle FOLLOW/RESTART statuses
		if reply.Status == AuthenStatusFollow {
			session.SetState(SessionStateComplete)
			if !c.singleConnect {
				c.closeConnection()
			}
			return reply, fmt.Errorf("%w: %s", ErrAuthenFollow, string(reply.ServerMsg))
		}

		if reply.Status == AuthenStatusRestart {
			session.SetState(SessionStateComplete)
			if !c.singleConnect {
				c.closeConnection()
			}
			return reply, ErrAuthenRestart
		}

		// Handle prompts
		if reply.NeedsInput() {
			prompt := string(reply.ServerMsg)
			response, err := promptHandler(prompt, reply.NoEcho())
			if err != nil {
				// Send abort
				cont := &AuthenContinue{Flags: AuthenContinueFlagAbort}
				contBody, _ := cont.MarshalBinary()
				abortSeqNo, seqErr := session.NextSeqNo()
				if seqErr == nil {
					header.SeqNo = abortSeqNo
					c.sendPacket(header, contBody)
				}
				c.closeConnection()
				return nil, err
			}

			// Send CONTINUE with response
			cont := &AuthenContinue{UserMsg: []byte(response)}
			contBody, err := cont.MarshalBinary()
			if err != nil {
				return nil, fmt.Errorf("failed to marshal CONTINUE: %w", err)
			}

			contSeqNo, err := session.NextSeqNo()
			if err != nil {
				c.closeConnection()
				return nil, err
			}
			header.SeqNo = contSeqNo
			if err := c.sendPacket(header, contBody); err != nil {
				c.closeConnection()
				return nil, err
			}
		} else {
			// Unexpected status
			return nil, fmt.Errorf("unexpected authentication status: %d", reply.Status)
		}
	}
}

// Authorize performs authorization with the TACACS+ server.
func (c *Client) Authorize(ctx context.Context, username string, args []string) (*AuthorResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Ensure we're connected
	if err := c.connectLocked(ctx); err != nil {
		return nil, err
	}

	// Create new session
	session, err := c.newSession()
	if err != nil {
		return nil, err
	}

	// Create REQUEST packet
	req := &AuthorRequest{
		AuthenMethod: AuthenTypePAP,
		PrivLevel:    1,
		AuthenType:   AuthenTypePAP,
		Service:      AuthenServiceLogin,
		User:         []byte(username),
	}

	for _, arg := range args {
		req.AddArg(arg)
	}

	reqBody, err := req.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal REQUEST: %w", err)
	}

	// Create header
	header := NewHeader(PacketTypeAuthor, session.ID())
	seqNo, err := session.NextSeqNo()
	if err != nil {
		return nil, err
	}
	header.SeqNo = seqNo

	// Send REQUEST
	if err := c.sendPacket(header, reqBody); err != nil {
		c.closeConnection()
		return nil, err
	}

	// Receive response
	respHeader, respBody, err := c.recvPacket()
	if err != nil {
		c.closeConnection()
		return nil, err
	}

	// Validate response
	if respHeader.Type != PacketTypeAuthor {
		c.closeConnection()
		return nil, fmt.Errorf("%w: expected AUTHOR, got %d", ErrInvalidType, respHeader.Type)
	}
	if respHeader.SessionID != session.ID() {
		c.closeConnection()
		return nil, fmt.Errorf("%w: session ID mismatch", ErrSessionNotFound)
	}
	if !session.ValidateSeqNo(respHeader.SeqNo) {
		c.closeConnection()
		return nil, fmt.Errorf("%w: expected %d, got %d", ErrInvalidSequence, session.SeqNo()+1, respHeader.SeqNo)
	}
	session.UpdateSeqNo(respHeader.SeqNo)

	// Parse response
	resp := &AuthorResponse{}
	if err := resp.UnmarshalBinary(respBody); err != nil {
		c.closeConnection()
		return nil, fmt.Errorf("failed to unmarshal RESPONSE: %w", err)
	}

	// Update session state
	if resp.IsPass() {
		session.SetState(SessionStateComplete)
	} else {
		session.SetState(SessionStateError)
	}

	// Close connection if not using single-connect
	if !c.singleConnect {
		c.closeConnection()
	}

	return resp, nil
}

// Accounting sends an accounting record to the TACACS+ server.
func (c *Client) Accounting(ctx context.Context, flags uint8, username string, args []string) (*AcctReply, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Ensure we're connected
	if err := c.connectLocked(ctx); err != nil {
		return nil, err
	}

	// Create new session
	session, err := c.newSession()
	if err != nil {
		return nil, err
	}

	// Create REQUEST packet
	req := &AcctRequest{
		Flags:        flags,
		AuthenMethod: AuthenTypePAP,
		PrivLevel:    1,
		AuthenType:   AuthenTypePAP,
		Service:      AuthenServiceLogin,
		User:         []byte(username),
	}

	for _, arg := range args {
		req.AddArg(arg)
	}

	reqBody, err := req.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal REQUEST: %w", err)
	}

	// Create header
	header := NewHeader(PacketTypeAcct, session.ID())
	seqNo, err := session.NextSeqNo()
	if err != nil {
		return nil, err
	}
	header.SeqNo = seqNo

	// Send REQUEST
	if err := c.sendPacket(header, reqBody); err != nil {
		c.closeConnection()
		return nil, err
	}

	// Receive reply
	respHeader, respBody, err := c.recvPacket()
	if err != nil {
		c.closeConnection()
		return nil, err
	}

	// Validate response
	if respHeader.Type != PacketTypeAcct {
		c.closeConnection()
		return nil, fmt.Errorf("%w: expected ACCT, got %d", ErrInvalidType, respHeader.Type)
	}
	if respHeader.SessionID != session.ID() {
		c.closeConnection()
		return nil, fmt.Errorf("%w: session ID mismatch", ErrSessionNotFound)
	}
	if !session.ValidateSeqNo(respHeader.SeqNo) {
		c.closeConnection()
		return nil, fmt.Errorf("%w: expected %d, got %d", ErrInvalidSequence, session.SeqNo()+1, respHeader.SeqNo)
	}
	session.UpdateSeqNo(respHeader.SeqNo)

	// Parse reply
	reply := &AcctReply{}
	if err := reply.UnmarshalBinary(respBody); err != nil {
		c.closeConnection()
		return nil, fmt.Errorf("failed to unmarshal REPLY: %w", err)
	}

	// Update session state
	if reply.IsSuccess() {
		session.SetState(SessionStateComplete)
	} else {
		session.SetState(SessionStateError)
	}

	// Close connection if not using single-connect
	if !c.singleConnect {
		c.closeConnection()
	}

	return reply, nil
}

// closeConnection closes the connection without locking.
func (c *Client) closeConnection() {
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.session = nil
}

// Address returns the server address.
func (c *Client) Address() string {
	return c.address
}

// LocalAddr returns the local address of the connection.
func (c *Client) LocalAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote address of the connection.
func (c *Client) RemoteAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	return c.conn.RemoteAddr()
}
