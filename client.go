package gotacacs

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// maxASCIIPrompts limits the number of interactive prompt round-trips in ASCII
// authentication to prevent a malicious server from keeping the client in an
// infinite loop. The TACACS+ protocol limits sessions to 255 sequence numbers,
// but a practical authentication exchange should never exceed this many prompts.
const maxASCIIPrompts = 20

// errUnencryptedFlagMismatch marks a response that arrived with
// TAC_PLUS_UNENCRYPTED_FLAG set while the client has a shared secret. RFC 8907
// Section 10.5.2 requires closing the session and processing it as a FAIL; the
// AAA methods translate this into the matching FAIL sentinel for the caller.
var errUnencryptedFlagMismatch = errors.New("response carried the unencrypted flag with a secret configured")

// mapRecvError translates a recvPacket error. A flag mismatch (RFC 8907
// Section 10.5.2) is reported as the given FAIL sentinel so the caller treats
// it exactly like a server FAIL status; any other error passes through.
func mapRecvError(err, failErr error) error {
	if errors.Is(err, errUnencryptedFlagMismatch) {
		return failErr
	}
	return err
}

// Client represents a TACACS+ client for communicating with a TACACS+ server.
type Client struct {
	mu      sync.Mutex
	address string
	secret  []byte
	dialer  Dialer
	conn    net.Conn
	session *Session

	timeout                 time.Duration
	singleConnect           bool
	singleConnectNegotiated bool
	singleConnectAccepted   bool
	maxBodyLength           uint32
	tlsMode                 bool // RFC 9887: when true, use unencrypted flag and skip obfuscation
}

// ClientOption is a function that configures a Client.
type ClientOption func(*Client)

// WithAddress sets the server address to connect to.
func WithAddress(address string) ClientOption {
	return func(c *Client) {
		c.address = address
	}
}

// WithTimeout sets the built-in dialer timeout and timeout for each network
// read/write. Zero disables this timeout; context deadlines still apply.
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
// The input slice is copied to prevent mutations from affecting the client.
func WithSecretBytes(secret []byte) ClientOption {
	cp := make([]byte, len(secret))
	copy(cp, secret)
	return func(c *Client) {
		c.secret = cp
	}
}

// WithTLSConfig sets the TLS configuration for TACACS+ over TLS.
// When using TLS mode, the unencrypted flag is automatically set and
// packet obfuscation is disabled since TLS provides encryption.
// This function enforces a minimum of TLS 1.3 as required by RFC 9887.
// If config is nil, a default TLS 1.3 configuration is used.
// Built-in dialer timeouts are applied after all options, regardless of order.
// A custom dialer supplied after this option must return a TLS connection.
func WithTLSConfig(config *tls.Config) ClientOption {
	return func(c *Client) {
		var cfg *tls.Config
		if config == nil {
			cfg = &tls.Config{}
		} else {
			// Clone config to avoid modifying the original
			cfg = config.Clone()
		}

		// RFC 9887 requires TLS 1.3
		cfg.MinVersion = tls.VersionTLS13
		// Ensure MaxVersion is not below MinVersion
		if cfg.MaxVersion != 0 && cfg.MaxVersion < tls.VersionTLS13 {
			cfg.MaxVersion = tls.VersionTLS13
		}

		c.dialer = &TLSDialer{
			Timeout: c.timeout,
			Config:  cfg,
		}
		c.tlsMode = true
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
func NewClient(opts ...ClientOption) *Client {
	c := &Client{
		timeout:       30 * time.Second,
		dialer:        &TCPDialer{Timeout: 30 * time.Second},
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
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.conn != nil {
		return nil // Already connected
	}

	conn, err := c.dialer.Dial(ctx, "tcp", c.address)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", c.address, wrapTimeout(err))
	}
	if c.tlsMode && !IsTLSConn(conn) {
		_ = conn.Close()
		return fmt.Errorf("%w: TLS mode requires a TLS connection", ErrInvalidPacket)
	}

	c.conn = conn
	c.singleConnectNegotiated = false
	c.singleConnectAccepted = false
	return nil
}

// watchContext interrupts in-flight I/O when a context without a deadline is
// cancelled. The caller holds c.mu until the returned cleanup has finished.
func (c *Client) watchContext(ctx context.Context) func() {
	conn := c.conn
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
		close(done)
	})
	return func() {
		if !stop() {
			<-done
			c.closeConnection()
		}
	}
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

// wrapTimeout tags network timeout errors with ErrTimeout so callers can
// branch with errors.Is; the underlying error stays in the chain.
func wrapTimeout(err error) error {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fmt.Errorf("%w: %w", ErrTimeout, err)
	}
	return err
}

// effectiveDeadline returns the earliest deadline from the context and timeout.
func (c *Client) effectiveDeadline(ctx context.Context) time.Time {
	timeoutDeadline := time.Time{}
	if c.timeout > 0 {
		timeoutDeadline = time.Now().Add(c.timeout)
	}

	if ctxDeadline, ok := ctx.Deadline(); ok {
		if timeoutDeadline.IsZero() || ctxDeadline.Before(timeoutDeadline) {
			return ctxDeadline
		}
	}

	return timeoutDeadline
}

// sendPacket sends a packet to the server with proper framing and obfuscation.
func (c *Client) sendPacket(ctx context.Context, header *Header, body []byte) error {
	// Set body length in header
	header.Length = uint32(len(body))

	// Reset flags to avoid stale state from previous iterations
	header.Flags = 0

	// Set single-connect flag if enabled
	if c.singleConnect {
		header.SetSingleConnect(true)
	}

	// Check if connection is actually TLS-secured
	// Security: Only use TLS mode if the connection is actually TLS,
	// not just based on tlsMode flag (prevents sending unencrypted data
	// if tlsMode was set but a non-TLS dialer was used)
	isTLS := IsTLSConn(c.conn)

	// RFC 9887: Set unencrypted flag when using TLS
	// TLS provides encryption, so packet obfuscation is not needed
	if isTLS {
		header.SetUnencrypted(true)
	}

	// Obfuscate body (skipped if unencrypted flag is set or using TLS)
	obfuscatedBody := body
	if !isTLS {
		obfuscatedBody = Obfuscate(header, c.secret, body)
	}

	// Marshal header
	headerData, err := header.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal header: %w", err)
	}

	// Set deadline for write (respects both timeout and context deadline)
	if err := c.conn.SetWriteDeadline(c.effectiveDeadline(ctx)); err != nil {
		return fmt.Errorf("failed to set write deadline: %w", err)
	}

	// Write header and body using writeAll to handle partial writes
	if err := writeAll(c.conn, headerData); err != nil {
		return fmt.Errorf("failed to write header: %w", wrapTimeout(err))
	}

	if len(obfuscatedBody) > 0 {
		if err := writeAll(c.conn, obfuscatedBody); err != nil {
			return fmt.Errorf("failed to write body: %w", wrapTimeout(err))
		}
	}

	return nil
}

// recvPacket receives a packet from the server with deobfuscation.
func (c *Client) recvPacket(ctx context.Context) (*Header, []byte, error) {
	// Set deadline for read (respects both timeout and context deadline)
	if err := c.conn.SetReadDeadline(c.effectiveDeadline(ctx)); err != nil {
		return nil, nil, fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Read header
	headerBuf := make([]byte, HeaderLength)
	if _, err := io.ReadFull(c.conn, headerBuf); err != nil {
		if err == io.EOF {
			return nil, nil, ErrConnectionClosed
		}
		return nil, nil, fmt.Errorf("failed to read header: %w", wrapTimeout(err))
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

	// Check if connection is actually TLS-secured
	// Security: Only use TLS mode if the connection is actually TLS
	isTLS := IsTLSConn(c.conn)

	// RFC 9887: On TLS connections, the unencrypted flag MUST be set.
	// Reject packets without the flag when using TLS.
	if isTLS && !header.IsUnencrypted() {
		return nil, nil, fmt.Errorf("%w: RFC 9887 requires unencrypted flag on TLS connections", ErrInvalidPacket)
	}

	// RFC 8907 Section 10.5.2: a client configured with a shared key that
	// receives a response with TAC_PLUS_UNENCRYPTED_FLAG set MUST close the
	// session and process it as a FAIL. Signal that distinctly so callers map
	// it to an authentication/authorization failure rather than a generic
	// protocol error. When no secret is configured obfuscation is a no-op, so
	// the flag is only a mismatch when a secret is present.
	if !isTLS && header.IsUnencrypted() && len(c.secret) > 0 {
		return nil, nil, errUnencryptedFlagMismatch
	}

	// Read body
	var body []byte
	if header.Length > 0 {
		body = make([]byte, header.Length)
		if _, err := io.ReadFull(c.conn, body); err != nil {
			return nil, nil, fmt.Errorf("failed to read body: %w", wrapTimeout(err))
		}

		// Deobfuscate body (skipped if using TLS per RFC 9887)
		if !isTLS {
			body = Obfuscate(header, c.secret, body)
		}
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
	// Session is used for the exchange when non-nil; a fresh random
	// session is created otherwise.
	Session *Session
	// Action is the authentication action. The zero value selects
	// AuthenActionLogin; set AuthenActionChPass to change a password.
	Action     AuthenAction
	Username   string
	Password   string
	Port       string
	RemoteAddr string
}

// Authenticate performs authentication with the TACACS+ server.
// It handles the complete authentication flow including multi-step interactions.
// A FAIL status returns the reply together with ErrAuthenticationFailed;
// FOLLOW and RESTART return the reply with ErrAuthenFollow and
// ErrAuthenRestart. Network timeouts wrap ErrTimeout.
func (c *Client) Authenticate(ctx context.Context, username, password string) (*AuthenReply, error) {
	return c.AuthenticateWithContext(ctx, &AuthenticateContext{
		Username: username,
		Password: password,
	})
}

// AuthenticateWithContext performs authentication with additional context.
// It returns the same errors as Authenticate.
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
	defer c.watchContext(ctx)()

	// Use the caller-supplied session when provided
	session := authCtx.Session
	if session == nil {
		var err error
		session, err = c.newSession()
		if err != nil {
			return nil, err
		}
	} else {
		c.session = session
	}

	// Create START packet
	action := authCtx.Action
	if action == 0 {
		action = AuthenActionLogin
	}
	start := &AuthenStart{
		Action:     action,
		PrivLevel:  1,
		AuthenType: AuthenTypePAP, // Use PAP for simple password auth
		Service:    AuthenServiceLogin,
		User:       []byte(authCtx.Username),
		Port:       []byte(authCtx.Port),
		RemoteAddr: []byte(authCtx.RemoteAddr),
		Data:       []byte(authCtx.Password), // PAP sends password in START
	}

	return c.runSingleExchange(ctx, session, start)
}

// runSingleExchange sends a single authentication START and processes the
// single REPLY, the exchange shape shared by PAP (Section 5.4.2.2) and CHAP
// (Section 5.4.2.3). The caller holds c.mu and has established the connection
// and session. A FAIL status returns the reply with ErrAuthenticationFailed;
// FOLLOW and RESTART return the reply with ErrAuthenFollow / ErrAuthenRestart;
// an interactive GET* status is a protocol error for a single-exchange method.
func (c *Client) runSingleExchange(ctx context.Context, session *Session, start *AuthenStart) (*AuthenReply, error) {
	startBody, err := start.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal START packet: %w", err)
	}

	// Create header. PAP and CHAP both use minor version 1 (Section 5.4.1).
	header := NewHeader(PacketTypeAuthen, session.ID())
	header.Version = MajorVersion<<4 | MinorVersionOne
	seqNo, err := session.NextSeqNo()
	if err != nil {
		return nil, err
	}
	header.SeqNo = seqNo

	// Send START packet
	if err := c.sendPacket(ctx, header, startBody); err != nil {
		c.closeConnection()
		return nil, err
	}

	// Receive reply
	respHeader, respBody, err := c.recvPacket(ctx)
	if err != nil {
		c.closeConnection()
		return nil, mapRecvError(err, ErrAuthenticationFailed)
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

	// RFC 8907: Check if server agreed to single-connect mode
	singleConnectOK := c.acceptSingleConnect(respHeader)

	// Update session state based on reply
	switch reply.Status {
	case AuthenStatusPass:
		session.SetState(SessionStateComplete)
	case AuthenStatusFail:
		session.SetState(SessionStateError)
		if !singleConnectOK {
			c.closeConnection()
		}
		return reply, ErrAuthenticationFailed
	case AuthenStatusError:
		session.SetState(SessionStateError)
	case AuthenStatusFollow:
		session.SetState(SessionStateComplete)
		if !singleConnectOK {
			c.closeConnection()
		}
		return reply, fmt.Errorf("%w: %s", ErrAuthenFollow, string(reply.ServerMsg))
	case AuthenStatusRestart:
		session.SetState(SessionStateComplete)
		if !singleConnectOK {
			c.closeConnection()
		}
		return reply, ErrAuthenRestart
	case AuthenStatusGetData, AuthenStatusGetUser, AuthenStatusGetPass:
		session.SetState(SessionStateError)
		c.closeConnection()
		return reply, fmt.Errorf("%w: interactive authentication status %d returned to non-interactive authentication", ErrInvalidPacket, reply.Status)
	default:
		session.SetState(SessionStateError)
		c.closeConnection()
		return reply, fmt.Errorf("%w: unexpected authentication status %d", ErrInvalidPacket, reply.Status)
	}

	// Close connection if not using single-connect or server rejected it
	if !singleConnectOK {
		c.closeConnection()
	}

	return reply, nil
}

// AuthenticateCHAP performs a CHAP login (RFC 8907 Section 5.4.2.3): a single
// START carrying the username and the id/challenge/MD5-response data field,
// and a single REPLY. The caller supplies the PPP id and challenge; the
// response is computed from the shared secret with CHAPResponse. The challenge
// SHOULD be at least 8 octets and unpredictable. A FAIL status returns the
// reply with ErrAuthenticationFailed.
func (c *Client) AuthenticateCHAP(ctx context.Context, username string, id byte, secret, challenge []byte) (*AuthenReply, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.connectLocked(ctx); err != nil {
		return nil, err
	}
	defer c.watchContext(ctx)()

	session, err := c.newSession()
	if err != nil {
		return nil, err
	}

	start := NewCHAPStart(username, id, secret, challenge)
	start.Port = nil
	start.RemoteAddr = nil
	return c.runSingleExchange(ctx, session, start)
}

// AuthenticateASCII performs ASCII authentication with interactive prompts.
// The promptHandler is called for each GETDATA/GETUSER/GETPASS request.
// A missing callback when input is requested returns ErrInvalidPacket.
// At most 20 prompt responses are allowed; a further prompt returns ErrMaxPrompts.
// A FAIL status returns the reply together with ErrAuthenticationFailed.
func (c *Client) AuthenticateASCII(ctx context.Context, username string, promptHandler func(prompt string, noEcho bool) (string, error)) (*AuthenReply, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Ensure we're connected
	if err := c.connectLocked(ctx); err != nil {
		return nil, err
	}
	defer c.watchContext(ctx)()

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
	if err := c.sendPacket(ctx, header, startBody); err != nil {
		c.closeConnection()
		return nil, err
	}

	// Authentication loop with iteration limit to prevent malicious servers
	// from keeping the client in an infinite prompt loop.
	for iteration := 0; ; iteration++ {
		// Receive reply
		respHeader, respBody, err := c.recvPacket(ctx)
		if err != nil {
			c.closeConnection()
			return nil, mapRecvError(err, ErrAuthenticationFailed)
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

		// RFC 8907: Check if server agreed to single-connect mode
		singleConnectOK := c.acceptSingleConnect(respHeader)

		// Check if authentication is complete
		if reply.IsPass() {
			session.SetState(SessionStateComplete)
			if !singleConnectOK {
				c.closeConnection()
			}
			return reply, nil
		}

		if reply.IsFail() {
			session.SetState(SessionStateError)
			if !singleConnectOK {
				c.closeConnection()
			}
			return reply, ErrAuthenticationFailed
		}

		if reply.IsError() {
			session.SetState(SessionStateError)
			if !singleConnectOK {
				c.closeConnection()
			}
			return reply, nil
		}

		// Handle FOLLOW/RESTART statuses
		if reply.Status == AuthenStatusFollow {
			session.SetState(SessionStateComplete)
			if !singleConnectOK {
				c.closeConnection()
			}
			return reply, fmt.Errorf("%w: %s", ErrAuthenFollow, string(reply.ServerMsg))
		}

		if reply.Status == AuthenStatusRestart {
			session.SetState(SessionStateComplete)
			if !singleConnectOK {
				c.closeConnection()
			}
			return reply, ErrAuthenRestart
		}

		// Handle prompts
		if reply.NeedsInput() {
			if iteration >= maxASCIIPrompts {
				c.closeConnection()
				return nil, fmt.Errorf("%w: %d", ErrMaxPrompts, maxASCIIPrompts)
			}
			if promptHandler == nil {
				c.closeConnection()
				return nil, fmt.Errorf("%w: prompt handler is nil", ErrInvalidPacket)
			}
			prompt := string(reply.ServerMsg)
			response, err := promptHandler(prompt, reply.NoEcho())
			if err != nil {
				// Send abort
				cont := &AuthenContinue{Flags: AuthenContinueFlagAbort}
				contBody, _ := cont.MarshalBinary()
				abortSeqNo, seqErr := session.NextSeqNo()
				if seqErr == nil {
					header.SeqNo = abortSeqNo
					c.sendPacket(ctx, header, contBody)
				}
				c.closeConnection()
				return nil, err
			}

			// Send CONTINUE with response
			cont := &AuthenContinue{UserMsg: []byte(response)}
			contBody, err := cont.MarshalBinary()
			if err != nil {
				c.closeConnection()
				return nil, fmt.Errorf("failed to marshal CONTINUE: %w", err)
			}

			contSeqNo, err := session.NextSeqNo()
			if err != nil {
				c.closeConnection()
				return nil, err
			}
			header.SeqNo = contSeqNo
			if err := c.sendPacket(ctx, header, contBody); err != nil {
				c.closeConnection()
				return nil, err
			}
		} else {
			// Unexpected status
			c.closeConnection()
			return nil, fmt.Errorf("unexpected authentication status: %d", reply.Status)
		}
	}
}

// Authorize performs authorization with the TACACS+ server.
// A FAIL status returns the response together with ErrAuthorizationDenied.
// Network timeouts wrap ErrTimeout.
func (c *Client) Authorize(ctx context.Context, username string, args []string) (*AuthorResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Ensure we're connected
	if err := c.connectLocked(ctx); err != nil {
		return nil, err
	}
	defer c.watchContext(ctx)()

	// Create new session
	session, err := c.newSession()
	if err != nil {
		return nil, err
	}

	// Create REQUEST packet
	req := &AuthorRequest{
		AuthenMethod: AuthenMethodTACACSPlus,
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
	if err := c.sendPacket(ctx, header, reqBody); err != nil {
		c.closeConnection()
		return nil, err
	}

	// Receive response
	respHeader, respBody, err := c.recvPacket(ctx)
	if err != nil {
		c.closeConnection()
		return nil, mapRecvError(err, ErrAuthorizationDenied)
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

	// RFC 8907: Check if server agreed to single-connect mode
	singleConnectOK := c.acceptSingleConnect(respHeader)

	// Update session state
	switch resp.Status {
	case AuthorStatusPassAdd, AuthorStatusPassRepl:
		session.SetState(SessionStateComplete)
	case AuthorStatusFail:
		session.SetState(SessionStateError)
		if !singleConnectOK {
			c.closeConnection()
		}
		return resp, ErrAuthorizationDenied
	case AuthorStatusError, AuthorStatusFollow:
		session.SetState(SessionStateError)
	default:
		session.SetState(SessionStateError)
		c.closeConnection()
		return resp, fmt.Errorf("%w: unexpected authorization status %d", ErrInvalidPacket, resp.Status)
	}

	// RFC 8907: Close connection if server didn't agree to single-connect
	if !singleConnectOK {
		c.closeConnection()
	}

	return resp, nil
}

// Accounting sends an accounting record to the TACACS+ server.
// An ERROR status returns the reply together with ErrAccountingFailed.
// Network timeouts wrap ErrTimeout.
func (c *Client) Accounting(ctx context.Context, flags AcctFlag, username string, args []string) (*AcctReply, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Ensure we're connected
	if err := c.connectLocked(ctx); err != nil {
		return nil, err
	}
	defer c.watchContext(ctx)()

	// Create new session
	session, err := c.newSession()
	if err != nil {
		return nil, err
	}

	// Create REQUEST packet
	req := &AcctRequest{
		Flags:        flags,
		AuthenMethod: AuthenMethodTACACSPlus,
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
	if err := c.sendPacket(ctx, header, reqBody); err != nil {
		c.closeConnection()
		return nil, err
	}

	// Receive reply
	respHeader, respBody, err := c.recvPacket(ctx)
	if err != nil {
		c.closeConnection()
		return nil, mapRecvError(err, ErrAccountingFailed)
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

	// RFC 8907: Check if server agreed to single-connect mode
	singleConnectOK := c.acceptSingleConnect(respHeader)

	// Update session state
	switch reply.Status {
	case AcctStatusSuccess:
		session.SetState(SessionStateComplete)
	case AcctStatusError:
		session.SetState(SessionStateError)
		if !singleConnectOK {
			c.closeConnection()
		}
		return reply, ErrAccountingFailed
	case AcctStatusFollow:
		session.SetState(SessionStateError)
	default:
		session.SetState(SessionStateError)
		c.closeConnection()
		return reply, fmt.Errorf("%w: unexpected accounting status %d", ErrInvalidPacket, reply.Status)
	}

	// RFC 8907: Close connection if server didn't agree to single-connect
	if !singleConnectOK {
		c.closeConnection()
	}

	return reply, nil
}

// serverAcceptedSingleConnect checks if the server echoed the single-connect flag.
// Per RFC 8907 Section 4.3, both sides must agree on single-connect mode.
func serverAcceptedSingleConnect(respHeader *Header) bool {
	return respHeader.Flags&FlagSingleConnect != 0
}

// acceptSingleConnect remembers the negotiation from the first reply on this
// connection. RFC 8907 Section 4.3 requires ignoring subsequent flag changes.
func (c *Client) acceptSingleConnect(header *Header) bool {
	if !c.singleConnectNegotiated {
		c.singleConnectAccepted = c.singleConnect && serverAcceptedSingleConnect(header)
		c.singleConnectNegotiated = true
	}
	return c.singleConnectAccepted
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

// IsTLSMode returns true if the client is using RFC 9887 TLS mode.
func (c *Client) IsTLSMode() bool {
	return c.tlsMode
}

// IsTLSConnection returns true if the current connection is TLS-secured.
func (c *Client) IsTLSConnection() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return false
	}
	return IsTLSConn(c.conn)
}
