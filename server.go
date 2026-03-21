package gotacacs

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// SecretRequest contains information about the client connection for secret lookup.
type SecretRequest struct {
	// RemoteAddr is the remote address of the client.
	RemoteAddr net.Addr
	// LocalAddr is the local address of the server connection.
	LocalAddr net.Addr
	// TLSState is the TLS connection state when the connection is TLS-secured.
	// Nil for non-TLS connections. Provides access to client certificates
	// via PeerCertificates for mutual TLS authentication.
	TLSState *tls.ConnectionState
	// Attempt is the 0-based secret attempt index for secret rotation.
	// The server calls GetSecret multiple times with increasing Attempt values
	// when the first secret fails to deobfuscate the packet.
	Attempt int
}

// SecretResponse contains the secret and optional user data for a client.
type SecretResponse struct {
	// Secret is the shared secret for packet obfuscation.
	// If nil, packets will not be obfuscated.
	Secret []byte
	// UserData is optional metadata passed to handlers.
	UserData map[string]string
	// Attempts is the total number of secrets available for rotation.
	// A value of 0 or 1 means no rotation (single secret).
	// When greater than 1, the server will try each secret in order
	// on the first packet of a connection until one succeeds.
	Attempts int
}

// SecretProvider provides per-client shared secrets and optional user data.
type SecretProvider interface {
	// GetSecret returns the shared secret and optional user data for the given request.
	GetSecret(ctx context.Context, req SecretRequest) SecretResponse
}

// SecretProviderFunc is an adapter to allow ordinary functions to be used as SecretProvider.
type SecretProviderFunc func(ctx context.Context, req SecretRequest) SecretResponse

// GetSecret implements SecretProvider.
func (f SecretProviderFunc) GetSecret(ctx context.Context, req SecretRequest) SecretResponse {
	return f(ctx, req)
}

// AuthenRequest represents an authentication request context.
type AuthenRequest struct {
	SessionID  uint32
	RemoteAddr net.Addr
	LocalAddr  net.Addr
	Header     *Header
	Start      *AuthenStart
	UserData   map[string]string
}

// AuthenContinueRequest represents an authentication continue request context.
type AuthenContinueRequest struct {
	SessionID  uint32
	RemoteAddr net.Addr
	LocalAddr  net.Addr
	Header     *Header
	Continue   *AuthenContinue
	UserData   map[string]string
}

// AuthorRequestContext represents an authorization request context.
type AuthorRequestContext struct {
	SessionID  uint32
	RemoteAddr net.Addr
	LocalAddr  net.Addr
	Header     *Header
	Request    *AuthorRequest
	UserData   map[string]string
}

// AcctRequestContext represents an accounting request context.
type AcctRequestContext struct {
	SessionID  uint32
	RemoteAddr net.Addr
	LocalAddr  net.Addr
	Header     *Header
	Request    *AcctRequest
	UserData   map[string]string
}

// AuthenticationHandler handles authentication requests.
type AuthenticationHandler interface {
	// HandleAuthenStart handles an authentication START packet.
	HandleAuthenStart(ctx context.Context, req *AuthenRequest) *AuthenReply

	// HandleAuthenContinue handles an authentication CONTINUE packet.
	HandleAuthenContinue(ctx context.Context, req *AuthenContinueRequest) *AuthenReply
}

// AuthorizationHandler handles authorization requests.
type AuthorizationHandler interface {
	// HandleAuthorRequest handles an authorization REQUEST packet.
	HandleAuthorRequest(ctx context.Context, req *AuthorRequestContext) *AuthorResponse
}

// AccountingHandler handles accounting requests.
type AccountingHandler interface {
	// HandleAcctRequest handles an accounting REQUEST packet.
	HandleAcctRequest(ctx context.Context, req *AcctRequestContext) *AcctReply
}

// Handler combines all handler interfaces.
type Handler interface {
	AuthenticationHandler
	AuthorizationHandler
	AccountingHandler
}

// AuthenHandlerFunc is an adapter for simple authentication handlers.
type AuthenHandlerFunc func(ctx context.Context, req *AuthenRequest) *AuthenReply

// HandleAuthenStart implements AuthenticationHandler.
func (f AuthenHandlerFunc) HandleAuthenStart(ctx context.Context, req *AuthenRequest) *AuthenReply {
	return f(ctx, req)
}

// HandleAuthenContinue implements AuthenticationHandler (returns ERROR by default).
func (f AuthenHandlerFunc) HandleAuthenContinue(_ context.Context, _ *AuthenContinueRequest) *AuthenReply {
	return &AuthenReply{Status: AuthenStatusError, ServerMsg: []byte("CONTINUE not supported")}
}

// AuthorHandlerFunc is an adapter for simple authorization handlers.
type AuthorHandlerFunc func(ctx context.Context, req *AuthorRequestContext) *AuthorResponse

// HandleAuthorRequest implements AuthorizationHandler.
func (f AuthorHandlerFunc) HandleAuthorRequest(ctx context.Context, req *AuthorRequestContext) *AuthorResponse {
	return f(ctx, req)
}

// AcctHandlerFunc is an adapter for simple accounting handlers.
type AcctHandlerFunc func(ctx context.Context, req *AcctRequestContext) *AcctReply

// HandleAcctRequest implements AccountingHandler.
func (f AcctHandlerFunc) HandleAcctRequest(ctx context.Context, req *AcctRequestContext) *AcctReply {
	return f(ctx, req)
}

// ServerOption configures a Server.
type ServerOption func(*Server)

// WithServerListener sets the listener for the server.
func WithServerListener(ln Listener) ServerOption {
	return func(s *Server) {
		s.listener = ln
	}
}

// WithSecretProvider sets the secret provider for the server.
func WithSecretProvider(provider SecretProvider) ServerOption {
	return func(s *Server) {
		s.secretProvider = provider
	}
}

// WithServerSecret sets a static secret for all clients.
func WithServerSecret(secret string) ServerOption {
	secretBytes := []byte(secret)
	return func(s *Server) {
		s.secretProvider = SecretProviderFunc(func(_ context.Context, _ SecretRequest) SecretResponse {
			return SecretResponse{Secret: secretBytes}
		})
	}
}

// WithServerSecretBytes sets a static secret for all clients.
func WithServerSecretBytes(secret []byte) ServerOption {
	return func(s *Server) {
		s.secretProvider = SecretProviderFunc(func(_ context.Context, _ SecretRequest) SecretResponse {
			return SecretResponse{Secret: secret}
		})
	}
}

// WithServerReadTimeout sets the read timeout for client connections.
func WithServerReadTimeout(timeout time.Duration) ServerOption {
	return func(s *Server) {
		s.readTimeout = timeout
	}
}

// WithServerWriteTimeout sets the write timeout for client connections.
func WithServerWriteTimeout(timeout time.Duration) ServerOption {
	return func(s *Server) {
		s.writeTimeout = timeout
	}
}

// WithAuthenticationHandler sets the authentication handler.
func WithAuthenticationHandler(handler AuthenticationHandler) ServerOption {
	return func(s *Server) {
		s.authenHandler = handler
	}
}

// WithAuthorizationHandler sets the authorization handler.
func WithAuthorizationHandler(handler AuthorizationHandler) ServerOption {
	return func(s *Server) {
		s.authorHandler = handler
	}
}

// WithAccountingHandler sets the accounting handler.
func WithAccountingHandler(handler AccountingHandler) ServerOption {
	return func(s *Server) {
		s.acctHandler = handler
	}
}

// WithHandler sets a combined handler for all request types.
func WithHandler(handler Handler) ServerOption {
	return func(s *Server) {
		s.authenHandler = handler
		s.authorHandler = handler
		s.acctHandler = handler
	}
}

// Server is a TACACS+ server.
type Server struct {
	mu             sync.Mutex
	listener       Listener
	secretProvider SecretProvider
	readTimeout    time.Duration
	writeTimeout   time.Duration
	maxBodyLength  uint32
	authenHandler  AuthenticationHandler
	authorHandler  AuthorizationHandler
	acctHandler    AccountingHandler

	running        bool
	shutdownCh     chan struct{}
	wg             sync.WaitGroup
	activeSessions sync.Map
	nextTrackingID atomic.Uint64
}

// NewServer creates a new TACACS+ server with the given options.
func NewServer(opts ...ServerOption) *Server {
	s := &Server{
		readTimeout:   30 * time.Second,
		writeTimeout:  30 * time.Second,
		maxBodyLength: DefaultMaxBodyLength,
		shutdownCh:    make(chan struct{}),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// WithServerMaxBodyLength sets the maximum allowed body length for incoming packets.
func WithServerMaxBodyLength(maxLength uint32) ServerOption {
	return func(s *Server) {
		s.maxBodyLength = maxLength
	}
}

// Serve starts accepting connections on the configured listener.
// This method blocks until the server is shut down.
func (s *Server) Serve() error {
	if s.listener == nil {
		return errors.New("no listener configured")
	}

	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("server already running")
	}
	s.running = true
	s.mu.Unlock()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.shutdownCh:
				return nil
			default:
				return fmt.Errorf("accept error: %w", err)
			}
		}

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	s.mu.Unlock()

	close(s.shutdownCh)

	if s.listener != nil {
		s.listener.Close()
	}

	// Wait for connections to finish or context to expire
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// IsRunning returns true if the server is currently running.
func (s *Server) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// Addr returns the server's listener address.
func (s *Server) Addr() net.Addr {
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Sessions returns a snapshot of all active sessions.
// The returned SessionInfo values are deep copies safe for concurrent use.
func (s *Server) Sessions() []SessionInfo {
	var sessions []SessionInfo
	s.activeSessions.Range(func(_, value any) bool {
		ts := value.(*trackedSession)
		info := ts.info
		info.State = SessionState(ts.state.Load())
		if info.UserData != nil {
			ud := make(map[string]string, len(info.UserData))
			maps.Copy(ud, info.UserData)
			info.UserData = ud
		}
		sessions = append(sessions, info)
		return true
	})
	return sessions
}

// KickSession marks a session for termination by its tracking ID.
// Returns true if the session was found and marked.
// The session will receive an error response on its next packet.
func (s *Server) KickSession(trackingID uint64) bool {
	value, ok := s.activeSessions.Load(trackingID)
	if !ok {
		return false
	}
	value.(*trackedSession).kicked.Store(true)
	return true
}

// completeTLSHandshake completes the TLS handshake and returns the connection state.
func (s *Server) completeTLSHandshake(ctx context.Context, conn Conn) (*tls.ConnectionState, error) {
	if hs, ok := conn.(interface{ HandshakeContext(context.Context) error }); ok {
		if err := hs.HandshakeContext(ctx); err != nil {
			return nil, err
		}
	}
	if tc, ok := conn.(TLSConn); ok {
		state := tc.ConnectionState()
		return &state, nil
	}
	return nil, nil
}

// registerSession registers a new session in the active sessions tracker.
func (s *Server) registerSession(header *Header, remoteAddr, localAddr net.Addr, userData map[string]string, tlsState *tls.ConnectionState, trackingIDs map[uint32]uint64) {
	trackingID := s.nextTrackingID.Add(1)
	trackingIDs[header.SessionID] = trackingID
	s.activeSessions.Store(trackingID, &trackedSession{
		info: SessionInfo{
			TrackingID: trackingID,
			SessionID:  header.SessionID,
			RemoteAddr: remoteAddr,
			LocalAddr:  localAddr,
			UserData:   userData,
			TLSState:   tlsState,
			PacketType: header.Type,
			StartedAt:  time.Now(),
		},
	})
}

// isSessionKicked returns true if the session with the given tracking ID has been kicked.
func (s *Server) isSessionKicked(trackingID uint64) bool {
	if trackingID == 0 {
		return false
	}
	ts, ok := s.activeSessions.Load(trackingID)
	if !ok {
		return false
	}
	return ts.(*trackedSession).kicked.Load()
}

// cleanupSession removes a session from local and active session maps.
func (s *Server) cleanupSession(sessionID uint32, localSessions map[uint32]*Session, trackingIDs map[uint32]uint64) {
	delete(localSessions, sessionID)
	if trackingID, ok := trackingIDs[sessionID]; ok {
		s.activeSessions.Delete(trackingID)
		delete(trackingIDs, sessionID)
	}
}

// sendKickedResponse sends an error response for a kicked session.
func (s *Server) sendKickedResponse(conn Conn, header *Header, secret []byte, isTLS bool) {
	var respBody []byte
	var respType uint8

	switch header.Type {
	case PacketTypeAuthen:
		respBody, respType = s.authenErrorResponse("session terminated")
	case PacketTypeAuthor:
		respBody, respType = s.authorErrorResponse("session terminated")
	case PacketTypeAcct:
		respBody, respType = s.acctErrorResponse("session terminated")
	default:
		return
	}

	respHeader := &Header{
		Version:   header.Version,
		Type:      respType,
		SeqNo:     header.SeqNo + 1,
		Flags:     header.Flags & FlagSingleConnect,
		SessionID: header.SessionID,
		Length:    uint32(len(respBody)),
	}

	if s.writeTimeout > 0 {
		conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
	}

	s.writePacket(conn, respHeader, respBody, secret, isTLS)
}

func (s *Server) handleConnection(conn Conn) {
	defer s.wg.Done()
	defer conn.Close()

	ctx := context.Background()
	secretReq := SecretRequest{
		RemoteAddr: conn.RemoteAddr(),
		LocalAddr:  conn.LocalAddr(),
	}

	// RFC 9887: Detect if connection is TLS-secured
	isTLS := IsTLSConn(conn)
	if isTLS {
		tlsState, err := s.completeTLSHandshake(ctx, conn)
		if err != nil {
			return
		}
		secretReq.TLSState = tlsState
	}

	secretResp := s.getSecret(ctx, secretReq)
	secret := secretResp.Secret
	userData := secretResp.UserData
	totalAttempts := max(secretResp.Attempts, 0)
	remoteAddr := secretReq.RemoteAddr
	localAddr := secretReq.LocalAddr

	// Secret rotation: resolved after first packet when multiple secrets are available
	secretResolved := false

	// Use connection-local session map to prevent cross-client session hijacking
	localSessions := make(map[uint32]*Session)
	trackingIDs := make(map[uint32]uint64)
	defer func() {
		// Clean up all tracked sessions on connection close
		for _, trackingID := range trackingIDs {
			s.activeSessions.Delete(trackingID)
		}
	}()

	for {
		select {
		case <-s.shutdownCh:
			return
		default:
		}

		// Set read deadline
		if s.readTimeout > 0 {
			conn.SetReadDeadline(time.Now().Add(s.readTimeout))
		}

		var header *Header
		var body []byte

		if secretResolved || totalAttempts <= 1 {
			var err error
			header, body, err = s.readPacket(conn, secret, isTLS)
			if err != nil {
				return
			}
		} else {
			var err error
			header, body, err = s.readRawPacket(conn, len(secret) > 0, isTLS)
			if err != nil {
				return
			}
			body, secret, userData = s.resolveSecret(ctx, secretReq, header, body, secret, userData, totalAttempts, isTLS)
			secretResolved = true
		}

		// Get or create session (scoped to this connection for security)
		session, exists := localSessions[header.SessionID]
		if !exists {
			session = NewSessionWithID(header.SessionID, false)
			localSessions[header.SessionID] = session
			s.registerSession(header, remoteAddr, localAddr, userData, secretReq.TLSState, trackingIDs)
		}

		// Check if session was kicked
		if s.isSessionKicked(trackingIDs[header.SessionID]) {
			s.sendKickedResponse(conn, header, secret, isTLS)
			s.cleanupSession(header.SessionID, localSessions, trackingIDs)
			if header.Flags&FlagSingleConnect == 0 {
				return
			}
			continue
		}

		// Validate and update sequence number
		if !session.ValidateSeqNo(header.SeqNo) {
			return
		}
		session.UpdateSeqNo(header.SeqNo)

		// Mark tracked session as active once the first packet is accepted
		if trackingID, ok := trackingIDs[header.SessionID]; ok {
			if ts, loaded := s.activeSessions.Load(trackingID); loaded {
				ts.(*trackedSession).state.CompareAndSwap(uint32(SessionStateNew), uint32(SessionStateActive))
			}
		}

		// Process packet based on type
		ctx := context.Background()
		var respBody []byte
		var respType uint8
		var sessionState SessionState

		switch header.Type {
		case PacketTypeAuthen:
			respBody, respType, sessionState = s.handleAuthenPacketWithState(ctx, header, body, remoteAddr, localAddr, userData)
		case PacketTypeAuthor:
			respBody, respType, sessionState = s.handleAuthorPacket(ctx, header, body, remoteAddr, localAddr, userData)
		case PacketTypeAcct:
			respBody, respType, sessionState = s.handleAcctPacket(ctx, header, body, remoteAddr, localAddr, userData)
		default:
			return
		}

		if respBody == nil {
			return
		}

		// Set session state based on response (Complete for success, Error for failures)
		if sessionState != SessionStateActive {
			session.SetState(sessionState)
		}

		// Update tracked session state atomically
		if trackingID, ok := trackingIDs[header.SessionID]; ok {
			if ts, loaded := s.activeSessions.Load(trackingID); loaded {
				ts.(*trackedSession).state.Store(uint32(sessionState))
			}
		}

		// Get next sequence number
		seqNo, err := session.NextSeqNo()
		if err != nil {
			// Sequence number overflow, terminate session
			return
		}

		// Build response header.
		// Only copy FlagSingleConnect from the client request.
		// FlagUnencrypted is set by writePacket based on actual TLS state,
		// preventing clients from bypassing obfuscation on non-TLS connections.
		respHeader := &Header{
			Version:   header.Version,
			Type:      respType,
			SeqNo:     seqNo,
			Flags:     header.Flags & FlagSingleConnect,
			SessionID: header.SessionID,
			Length:    uint32(len(respBody)),
		}

		// Set write deadline
		if s.writeTimeout > 0 {
			conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
		}

		if err := s.writePacket(conn, respHeader, respBody, secret, isTLS); err != nil {
			return
		}

		// Clean up completed sessions to prevent unbounded growth in single-connect mode
		if session.State() == SessionStateComplete || session.State() == SessionStateError {
			s.cleanupSession(header.SessionID, localSessions, trackingIDs)

			// Close connection if not single-connect mode
			if header.Flags&FlagSingleConnect == 0 {
				return
			}
		}
	}
}

func (s *Server) getSecret(ctx context.Context, req SecretRequest) SecretResponse {
	if s.secretProvider == nil {
		return SecretResponse{}
	}
	return s.secretProvider.GetSecret(ctx, req)
}

// resolveSecret tries each secret in order until one successfully deobfuscates and validates
// the packet. Returns the deobfuscated body and the resolved secret/userData.
// If all secrets fail, returns the body deobfuscated with the first secret
// so the handler produces a standard "bad secret" response.
func (s *Server) resolveSecret(ctx context.Context, baseReq SecretRequest, header *Header, rawBody, firstSecret []byte, firstUserData map[string]string, totalAttempts int, isTLS bool) (body, secret []byte, userData map[string]string) {
	for i := range totalAttempts {
		var attemptSecret []byte
		var attemptUserData map[string]string
		if i == 0 {
			attemptSecret = firstSecret
			attemptUserData = firstUserData
		} else {
			req := baseReq
			req.Attempt = i
			resp := s.getSecret(ctx, req)
			attemptSecret = resp.Secret
			attemptUserData = resp.UserData
		}

		deobBody, validateErr := s.deobfuscateAndValidate(header, rawBody, attemptSecret, isTLS)
		if validateErr == nil || !errors.Is(validateErr, ErrBadSecret) {
			return deobBody, attemptSecret, attemptUserData
		}
	}

	// All secrets failed: deobfuscate with the first secret
	body = rawBody
	if !isTLS && header.Flags&FlagUnencrypted == 0 && len(firstSecret) > 0 {
		body = Obfuscate(header, firstSecret, rawBody)
	}
	return body, firstSecret, firstUserData
}

func (s *Server) readRawPacket(conn Conn, hasSecret, isTLS bool) (*Header, []byte, error) {
	// Read header
	headerBuf := make([]byte, HeaderLength)
	if _, err := io.ReadFull(conn, headerBuf); err != nil {
		return nil, nil, err
	}

	header := &Header{}
	if err := header.UnmarshalBinary(headerBuf); err != nil {
		return nil, nil, err
	}

	// Validate header version and type
	if err := header.Validate(); err != nil {
		return nil, nil, err
	}

	// RFC 9887: On TLS connections, the unencrypted flag MUST be set.
	// Reject packets without the flag when using TLS.
	if isTLS && !header.IsUnencrypted() {
		return nil, nil, fmt.Errorf("%w: RFC 9887 requires unencrypted flag on TLS connections", ErrInvalidPacket)
	}

	// Reject unencrypted flag on non-TLS connections when a secret is configured.
	// This prevents clients from bypassing obfuscation by setting the flag.
	if !isTLS && header.IsUnencrypted() && hasSecret {
		return nil, nil, fmt.Errorf("%w: unencrypted flag not allowed on non-TLS connections with shared secret", ErrInvalidPacket)
	}

	// Validate body length to prevent memory exhaustion
	if header.Length > s.maxBodyLength {
		return nil, nil, fmt.Errorf("%w: body length %d exceeds maximum %d", ErrBodyTooLarge, header.Length, s.maxBodyLength)
	}

	// Read body
	var body []byte
	if header.Length > 0 {
		body = make([]byte, header.Length)
		if _, err := io.ReadFull(conn, body); err != nil {
			return nil, nil, err
		}
	}

	return header, body, nil
}

func (s *Server) readPacket(conn Conn, secret []byte, isTLS bool) (*Header, []byte, error) {
	header, body, err := s.readRawPacket(conn, len(secret) > 0, isTLS)
	if err != nil {
		return nil, nil, err
	}

	// Deobfuscate if needed (Obfuscate is symmetric)
	// RFC 9887: Skip deobfuscation on TLS connections (TLS provides encryption)
	if !isTLS && header.Flags&FlagUnencrypted == 0 && len(secret) > 0 {
		body = Obfuscate(header, secret, body)
	}

	return header, body, nil
}

// deobfuscateAndValidate deobfuscates the raw body with the given secret and validates
// the result by parsing the packet. Returns the deobfuscated body or an error.
// Obfuscate() creates a new slice, so rawBody is preserved for retries.
func (s *Server) deobfuscateAndValidate(header *Header, rawBody, secret []byte, isTLS bool) ([]byte, error) {
	var body []byte
	if !isTLS && header.Flags&FlagUnencrypted == 0 && len(secret) > 0 {
		body = Obfuscate(header, secret, rawBody)
	} else {
		body = rawBody
	}

	_, err := ParsePacket(header, body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

func (s *Server) writePacket(conn Conn, header *Header, body []byte, secret []byte, isTLS bool) error {
	// RFC 9887: Set unencrypted flag on TLS connections
	if isTLS {
		header.SetUnencrypted(true)
	}

	// Obfuscate if needed
	// RFC 9887: Skip obfuscation on TLS connections (TLS provides encryption)
	if !isTLS && header.Flags&FlagUnencrypted == 0 && len(secret) > 0 {
		body = Obfuscate(header, secret, body)
	}

	headerBuf, err := header.MarshalBinary()
	if err != nil {
		return err
	}

	// Use writeAll to handle partial writes
	if err := writeAll(conn, headerBuf); err != nil {
		return err
	}

	if len(body) > 0 {
		if err := writeAll(conn, body); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) handleAuthenPacket(ctx context.Context, header *Header, body []byte, remoteAddr, localAddr net.Addr, userData map[string]string) ([]byte, uint8) {
	if header.SeqNo == 1 {
		return s.handleAuthenStart(ctx, header, body, remoteAddr, localAddr, userData)
	}
	return s.handleAuthenContinue(ctx, header, body, remoteAddr, localAddr, userData)
}

// handleAuthenPacketWithState processes authentication packets and returns session state.
// Returns (response body, packet type, session state).
// Session state is determined by the reply status:
// - PASS: SessionStateComplete
// - FAIL, ERROR: SessionStateError
// - GETDATA, GETUSER, GETPASS: SessionStateActive (session continues)
// - Other terminal statuses (FOLLOW, RESTART): SessionStateComplete
func (s *Server) handleAuthenPacketWithState(ctx context.Context, header *Header, body []byte, remoteAddr, localAddr net.Addr, userData map[string]string) ([]byte, uint8, SessionState) {
	respBody, respType := s.handleAuthenPacket(ctx, header, body, remoteAddr, localAddr, userData)

	// Parse reply to determine session state
	if len(respBody) > 0 {
		status := respBody[0] // First byte is always the status
		switch status {
		case AuthenStatusGetData, AuthenStatusGetUser, AuthenStatusGetPass:
			return respBody, respType, SessionStateActive
		case AuthenStatusFail, AuthenStatusError:
			return respBody, respType, SessionStateError
		default:
			// PASS, FOLLOW, RESTART are terminal but successful completions
			return respBody, respType, SessionStateComplete
		}
	}

	// If no response body, treat as error
	return respBody, respType, SessionStateError
}

func (s *Server) authenErrorResponse(msg string) ([]byte, uint8) {
	reply := &AuthenReply{Status: AuthenStatusError, ServerMsg: []byte(msg)}
	respBody, _ := reply.MarshalBinary()
	return respBody, PacketTypeAuthen
}

func (s *Server) handleAuthenStart(ctx context.Context, header *Header, body []byte, remoteAddr, localAddr net.Addr, userData map[string]string) ([]byte, uint8) {
	start := &AuthenStart{}
	if err := start.UnmarshalBinary(body); err != nil {
		if errors.Is(err, ErrBadSecret) {
			return s.authenErrorResponse("bad secret")
		}
		return s.authenErrorResponse("invalid START packet")
	}
	if s.authenHandler == nil {
		return s.authenErrorResponse("no authentication handler configured")
	}

	req := &AuthenRequest{
		SessionID: header.SessionID, RemoteAddr: remoteAddr, LocalAddr: localAddr,
		Header: header, Start: start, UserData: userData,
	}
	reply := s.authenHandler.HandleAuthenStart(ctx, req)
	if reply == nil {
		return s.authenErrorResponse("handler returned nil response")
	}
	respBody, _ := reply.MarshalBinary()
	return respBody, PacketTypeAuthen
}

func (s *Server) handleAuthenContinue(ctx context.Context, header *Header, body []byte, remoteAddr, localAddr net.Addr, userData map[string]string) ([]byte, uint8) {
	cont := &AuthenContinue{}
	if err := cont.UnmarshalBinary(body); err != nil {
		if errors.Is(err, ErrBadSecret) {
			return s.authenErrorResponse("bad secret")
		}
		return s.authenErrorResponse("invalid CONTINUE packet")
	}
	if s.authenHandler == nil {
		return s.authenErrorResponse("no authentication handler configured")
	}

	req := &AuthenContinueRequest{
		SessionID: header.SessionID, RemoteAddr: remoteAddr, LocalAddr: localAddr,
		Header: header, Continue: cont, UserData: userData,
	}
	reply := s.authenHandler.HandleAuthenContinue(ctx, req)
	if reply == nil {
		return s.authenErrorResponse("handler returned nil response")
	}
	respBody, _ := reply.MarshalBinary()
	return respBody, PacketTypeAuthen
}

func (s *Server) authorErrorResponse(msg string) ([]byte, uint8) {
	resp := &AuthorResponse{Status: AuthorStatusError, ServerMsg: []byte(msg)}
	respBody, _ := resp.MarshalBinary()
	return respBody, PacketTypeAuthor
}

func (s *Server) handleAuthorPacket(ctx context.Context, header *Header, body []byte, remoteAddr, localAddr net.Addr, userData map[string]string) ([]byte, uint8, SessionState) {
	request := &AuthorRequest{}
	if err := request.UnmarshalBinary(body); err != nil {
		msg := "invalid authorization request"
		if errors.Is(err, ErrBadSecret) {
			msg = "bad secret"
		}
		respBody, respType := s.authorErrorResponse(msg)
		return respBody, respType, SessionStateError
	}
	if s.authorHandler == nil {
		respBody, respType := s.authorErrorResponse("no authorization handler configured")
		return respBody, respType, SessionStateError
	}

	req := &AuthorRequestContext{
		SessionID: header.SessionID, RemoteAddr: remoteAddr, LocalAddr: localAddr,
		Header: header, Request: request, UserData: userData,
	}
	resp := s.authorHandler.HandleAuthorRequest(ctx, req)
	if resp == nil {
		respBody, respType := s.authorErrorResponse("handler returned nil response")
		return respBody, respType, SessionStateError
	}
	respBody, _ := resp.MarshalBinary()

	// Determine session state based on response status
	state := SessionStateComplete
	if resp.Status == AuthorStatusFail || resp.Status == AuthorStatusError {
		state = SessionStateError
	}
	return respBody, PacketTypeAuthor, state
}

func (s *Server) acctErrorResponse(msg string) ([]byte, uint8) {
	resp := &AcctReply{Status: AcctStatusError, ServerMsg: []byte(msg)}
	respBody, _ := resp.MarshalBinary()
	return respBody, PacketTypeAcct
}

func (s *Server) handleAcctPacket(ctx context.Context, header *Header, body []byte, remoteAddr, localAddr net.Addr, userData map[string]string) ([]byte, uint8, SessionState) {
	request := &AcctRequest{}
	if err := request.UnmarshalBinary(body); err != nil {
		msg := "invalid accounting request"
		if errors.Is(err, ErrBadSecret) {
			msg = "bad secret"
		}
		respBody, respType := s.acctErrorResponse(msg)
		return respBody, respType, SessionStateError
	}
	if s.acctHandler == nil {
		respBody, respType := s.acctErrorResponse("no accounting handler configured")
		return respBody, respType, SessionStateError
	}

	req := &AcctRequestContext{
		SessionID: header.SessionID, RemoteAddr: remoteAddr, LocalAddr: localAddr,
		Header: header, Request: request, UserData: userData,
	}
	resp := s.acctHandler.HandleAcctRequest(ctx, req)
	if resp == nil {
		respBody, respType := s.acctErrorResponse("handler returned nil response")
		return respBody, respType, SessionStateError
	}
	respBody, _ := resp.MarshalBinary()

	// Determine session state based on response status
	state := SessionStateComplete
	if resp.Status == AcctStatusError {
		state = SessionStateError
	}
	return respBody, PacketTypeAcct, state
}

// isNetClosedError checks if the error is a closed network connection error.
func isNetClosedError(err error) bool {
	if err == nil {
		return false
	}
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		return netErr.Err.Error() == "use of closed network connection"
	}
	return false
}
