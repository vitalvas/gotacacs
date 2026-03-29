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
	// The provider's GetSecret will be called with Attempt values from
	// 0 to Attempts-1; the provider must handle all values in this range.
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

// ConnectEvent is fired when a new client connection is accepted.
type ConnectEvent struct {
	RemoteAddr net.Addr
	LocalAddr  net.Addr
	TLSState   *tls.ConnectionState
}

// DisconnectEvent is fired when a client connection is closed.
type DisconnectEvent struct {
	RemoteAddr net.Addr
	LocalAddr  net.Addr
}

// SessionEvent is fired on session start and end.
type SessionEvent struct {
	SessionInfo
}

// BadSecretEvent is fired when secret validation fails.
type BadSecretEvent struct {
	RemoteAddr net.Addr
	LocalAddr  net.Addr
}

// PacketErrorEvent is fired when a packet parsing error occurs.
type PacketErrorEvent struct {
	RemoteAddr net.Addr
	LocalAddr  net.Addr
	Err        error
}

// ServerHooks contains optional callbacks for server lifecycle events.
// All callbacks must be non-blocking. Nil callbacks are skipped.
type ServerHooks struct {
	OnConnect      func(event ConnectEvent)
	OnDisconnect   func(event DisconnectEvent)
	OnSessionStart func(event SessionEvent)
	OnSessionEnd   func(event SessionEvent)
	OnBadSecret    func(event BadSecretEvent)
	OnPacketError  func(event PacketErrorEvent)
}

// composedHandler combines separate handler interfaces into a single Handler.
// Methods return error responses when the corresponding handler is nil.
type composedHandler struct {
	authen AuthenticationHandler
	author AuthorizationHandler
	acct   AccountingHandler
}

func (h *composedHandler) HandleAuthenStart(ctx context.Context, req *AuthenRequest) *AuthenReply {
	if h.authen == nil {
		return &AuthenReply{Status: AuthenStatusError, ServerMsg: []byte("no authentication handler configured")}
	}
	return h.authen.HandleAuthenStart(ctx, req)
}

func (h *composedHandler) HandleAuthenContinue(ctx context.Context, req *AuthenContinueRequest) *AuthenReply {
	if h.authen == nil {
		return &AuthenReply{Status: AuthenStatusError, ServerMsg: []byte("no authentication handler configured")}
	}
	return h.authen.HandleAuthenContinue(ctx, req)
}

func (h *composedHandler) HandleAuthorRequest(ctx context.Context, req *AuthorRequestContext) *AuthorResponse {
	if h.author == nil {
		return &AuthorResponse{Status: AuthorStatusError, ServerMsg: []byte("no authorization handler configured")}
	}
	return h.author.HandleAuthorRequest(ctx, req)
}

func (h *composedHandler) HandleAcctRequest(ctx context.Context, req *AcctRequestContext) *AcctReply {
	if h.acct == nil {
		return &AcctReply{Status: AcctStatusError, ServerMsg: []byte("no accounting handler configured")}
	}
	return h.acct.HandleAcctRequest(ctx, req)
}

// Middleware wraps a Handler to intercept any of the four request methods.
// The middleware receives the next handler in the chain and returns a new handler.
type Middleware func(next Handler) Handler

// MiddlewareHandler delegates all Handler methods to the next handler.
// Embed this in middleware implementations to only override the methods you need.
type MiddlewareHandler struct {
	Next Handler
}

// HandleAuthenStart delegates to the next handler.
func (m *MiddlewareHandler) HandleAuthenStart(ctx context.Context, req *AuthenRequest) *AuthenReply {
	return m.Next.HandleAuthenStart(ctx, req)
}

// HandleAuthenContinue delegates to the next handler.
func (m *MiddlewareHandler) HandleAuthenContinue(ctx context.Context, req *AuthenContinueRequest) *AuthenReply {
	return m.Next.HandleAuthenContinue(ctx, req)
}

// HandleAuthorRequest delegates to the next handler.
func (m *MiddlewareHandler) HandleAuthorRequest(ctx context.Context, req *AuthorRequestContext) *AuthorResponse {
	return m.Next.HandleAuthorRequest(ctx, req)
}

// HandleAcctRequest delegates to the next handler.
func (m *MiddlewareHandler) HandleAcctRequest(ctx context.Context, req *AcctRequestContext) *AcctReply {
	return m.Next.HandleAcctRequest(ctx, req)
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
// The input slice is copied to prevent mutations from affecting the server.
func WithServerSecretBytes(secret []byte) ServerOption {
	cp := make([]byte, len(secret))
	copy(cp, secret)
	return func(s *Server) {
		s.secretProvider = SecretProviderFunc(func(_ context.Context, _ SecretRequest) SecretResponse {
			return SecretResponse{Secret: cp}
		})
	}
}

// WithServerHooks sets lifecycle hooks for the server.
func WithServerHooks(hooks ServerHooks) ServerOption {
	return func(s *Server) {
		s.hooks = hooks
	}
}

// WithMiddleware appends middleware to the server's middleware chain.
// Middlewares are applied in order: first added = outermost (runs first).
func WithMiddleware(middlewares ...Middleware) ServerOption {
	return func(s *Server) {
		s.middlewares = append(s.middlewares, middlewares...)
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
	hooks          ServerHooks
	middlewares    []Middleware
	readTimeout    time.Duration
	writeTimeout   time.Duration
	maxBodyLength  uint32
	authenHandler  AuthenticationHandler
	authorHandler  AuthorizationHandler
	acctHandler    AccountingHandler
	handler        Handler

	running        bool
	shutdownCh     chan struct{}
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc
	wg             sync.WaitGroup
	activeConns    sync.Map // map of net.Conn for forcible close on shutdown
	activeSessions sync.Map
	nextTrackingID atomic.Uint64
	nextConnID     atomic.Uint64
}

// NewServer creates a new TACACS+ server with the given options.
func NewServer(opts ...ServerOption) *Server {
	s := &Server{
		readTimeout:   30 * time.Second,
		writeTimeout:  30 * time.Second,
		maxBodyLength: DefaultMaxBodyLength,
	}

	for _, opt := range opts {
		opt(s)
	}

	// Build combined handler from individual handlers
	s.handler = &composedHandler{
		authen: s.authenHandler,
		author: s.authorHandler,
		acct:   s.acctHandler,
	}

	// Apply middleware chain (first added = outermost)
	for i := len(s.middlewares) - 1; i >= 0; i-- {
		s.handler = s.middlewares[i](s.handler)
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
// A server can be restarted by calling Serve again after Shutdown completes.
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
	s.shutdownCh = make(chan struct{})
	s.shutdownCtx, s.shutdownCancel = context.WithCancel(context.Background())
	s.mu.Unlock()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.shutdownCh:
				return nil
			default:
				s.mu.Lock()
				s.running = false
				s.mu.Unlock()
				return fmt.Errorf("accept error: %w", err)
			}
		}

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// Shutdown gracefully shuts down the server.
// It stops accepting new connections, signals active handlers via context,
// and waits for connections to finish. If the provided context expires,
// active connections are forcibly closed.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	shutdownCancel := s.shutdownCancel
	s.mu.Unlock()

	close(s.shutdownCh)
	shutdownCancel()

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
		// Forcibly close all active connections to unblock pending I/O
		s.activeConns.Range(func(_, value any) bool {
			value.(net.Conn).Close()
			return true
		})
		// Wait for handler goroutines to finish after force close
		<-done
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

// copyUserData returns a shallow copy of the map, safe for handler mutation.
func copyUserData(ud map[string]string) map[string]string {
	if ud == nil {
		return nil
	}
	cp := make(map[string]string, len(ud))
	maps.Copy(cp, ud)
	return cp
}

// connState holds per-connection state passed to internal handler methods.
type connState struct {
	remoteAddr    net.Addr
	localAddr     net.Addr
	userData      map[string]string
	tlsState      *tls.ConnectionState
	secret        []byte
	isTLS         bool
	totalAttempts int
	secretReq     SecretRequest
}

// completeTLSHandshake completes the TLS handshake and returns the connection state.
func (s *Server) completeTLSHandshake(ctx context.Context, conn net.Conn) (*tls.ConnectionState, error) {
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
func (s *Server) registerSession(header *Header, cs *connState, trackingIDs map[uint32]uint64) {
	trackingID := s.nextTrackingID.Add(1)
	trackingIDs[header.SessionID] = trackingID
	info := SessionInfo{
		TrackingID: trackingID,
		SessionID:  header.SessionID,
		RemoteAddr: cs.remoteAddr,
		LocalAddr:  cs.localAddr,
		UserData:   copyUserData(cs.userData),
		TLSState:   cs.tlsState,
		PacketType: header.Type,
		StartedAt:  time.Now(),
	}
	s.activeSessions.Store(trackingID, &trackedSession{info: info})
	if s.hooks.OnSessionStart != nil {
		s.hooks.OnSessionStart(SessionEvent{SessionInfo: info})
	}
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
		if s.hooks.OnSessionEnd != nil {
			if ts, loaded := s.activeSessions.Load(trackingID); loaded {
				info := ts.(*trackedSession).info
				info.State = SessionState(ts.(*trackedSession).state.Load())
				s.hooks.OnSessionEnd(SessionEvent{SessionInfo: info})
			}
		}
		s.activeSessions.Delete(trackingID)
		delete(trackingIDs, sessionID)
	}
}

// updateTrackedState updates the tracked session state atomically.
func (s *Server) updateTrackedState(trackingIDs map[uint32]uint64, sessionID uint32, state SessionState) {
	if trackingID, ok := trackingIDs[sessionID]; ok {
		if ts, loaded := s.activeSessions.Load(trackingID); loaded {
			ts.(*trackedSession).state.Store(uint32(state))
		}
	}
}

// cleanupConnection marks remaining active sessions as errored and cleans them up.
func (s *Server) cleanupConnection(localSessions map[uint32]*Session, trackingIDs map[uint32]uint64, cs *connState) {
	for _, trackingID := range trackingIDs {
		if ts, loaded := s.activeSessions.Load(trackingID); loaded {
			ts.(*trackedSession).state.CompareAndSwap(
				uint32(SessionStateActive), uint32(SessionStateError),
			)
			ts.(*trackedSession).state.CompareAndSwap(
				uint32(SessionStateNew), uint32(SessionStateError),
			)
		}
	}
	for sessionID := range localSessions {
		s.cleanupSession(sessionID, localSessions, trackingIDs)
	}
	s.fireDisconnect(cs.remoteAddr, cs.localAddr)
}

// sendKickedResponse sends an error response for a kicked session.
func (s *Server) sendKickedResponse(conn net.Conn, header *Header, secret []byte, isTLS bool) {
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

func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	connID := s.nextConnID.Add(1)
	s.activeConns.Store(connID, conn)
	defer s.activeConns.Delete(connID)

	ctx := s.shutdownCtx
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
	cs := &connState{
		remoteAddr:    secretReq.RemoteAddr,
		localAddr:     secretReq.LocalAddr,
		userData:      secretResp.UserData,
		tlsState:      secretReq.TLSState,
		secret:        secretResp.Secret,
		isTLS:         isTLS,
		totalAttempts: max(secretResp.Attempts, 0),
		secretReq:     secretReq,
	}

	// Secret rotation: resolved after first packet when multiple secrets are available
	secretResolved := false

	s.fireConnect(cs.remoteAddr, cs.localAddr, cs.tlsState)

	// Use connection-local session map to prevent cross-client session hijacking
	localSessions := make(map[uint32]*Session)
	trackingIDs := make(map[uint32]uint64)
	defer func() {
		s.cleanupConnection(localSessions, trackingIDs, cs)
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

		if secretResolved || cs.totalAttempts <= 1 {
			var err error
			header, body, err = s.readPacket(conn, cs.secret, cs.isTLS)
			if err != nil {
				s.fireReadError(err, cs.remoteAddr, cs.localAddr)
				return
			}
		} else {
			var err error
			header, body, err = s.readRawPacket(conn, len(cs.secret) > 0, cs.isTLS)
			if err != nil {
				s.fireReadError(err, cs.remoteAddr, cs.localAddr)
				return
			}
			body = s.resolveSecret(ctx, header, body, cs)
			secretResolved = true
		}

		// Get or create session (scoped to this connection for security)
		session, exists := localSessions[header.SessionID]
		if !exists {
			session = NewSessionWithID(header.SessionID, false)
			localSessions[header.SessionID] = session
			s.registerSession(header, cs, trackingIDs)
		}

		// Check if session was kicked
		if s.isSessionKicked(trackingIDs[header.SessionID]) {
			s.sendKickedResponse(conn, header, cs.secret, cs.isTLS)
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
		var respBody []byte
		var respType uint8
		var sessionState SessionState

		switch header.Type {
		case PacketTypeAuthen:
			respBody, respType, sessionState = s.handleAuthenPacketWithState(ctx, header, body, cs)
		case PacketTypeAuthor:
			respBody, respType, sessionState = s.handleAuthorPacket(ctx, header, body, cs)
		case PacketTypeAcct:
			respBody, respType, sessionState = s.handleAcctPacket(ctx, header, body, cs)
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
		s.updateTrackedState(trackingIDs, header.SessionID, sessionState)

		// Get next sequence number
		seqNo, err := session.NextSeqNo()
		if err != nil {
			session.SetState(SessionStateError)
			s.updateTrackedState(trackingIDs, header.SessionID, SessionStateError)
			s.cleanupSession(header.SessionID, localSessions, trackingIDs)
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

		if err := s.writePacket(conn, respHeader, respBody, cs.secret, cs.isTLS); err != nil {
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
// the packet. Returns the deobfuscated body. On success, updates cs.secret and cs.userData.
// If all secrets fail, returns the body deobfuscated with the first secret
// so the handler produces a standard "bad secret" response.
func (s *Server) resolveSecret(ctx context.Context, header *Header, rawBody []byte, cs *connState) []byte {
	for i := range cs.totalAttempts {
		var attemptSecret []byte
		var attemptUserData map[string]string
		if i == 0 {
			attemptSecret = cs.secret
			attemptUserData = cs.userData
		} else {
			req := cs.secretReq
			req.Attempt = i
			resp := s.getSecret(ctx, req)
			attemptSecret = resp.Secret
			attemptUserData = resp.UserData
		}

		deobBody, validateErr := s.deobfuscateAndValidate(header, rawBody, attemptSecret, cs.isTLS)
		if validateErr == nil || !errors.Is(validateErr, ErrBadSecret) {
			cs.secret = attemptSecret
			cs.userData = attemptUserData
			return deobBody
		}
	}

	// All secrets failed: deobfuscate with the first secret
	s.fireBadSecret(cs.remoteAddr, cs.localAddr)
	if !cs.isTLS && header.Flags&FlagUnencrypted == 0 && len(cs.secret) > 0 {
		return Obfuscate(header, cs.secret, rawBody)
	}
	return rawBody
}

func (s *Server) readRawPacket(conn net.Conn, hasSecret, isTLS bool) (*Header, []byte, error) {
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

func (s *Server) readPacket(conn net.Conn, secret []byte, isTLS bool) (*Header, []byte, error) {
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

func (s *Server) writePacket(conn net.Conn, header *Header, body []byte, secret []byte, isTLS bool) error {
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

func (s *Server) handleAuthenPacket(ctx context.Context, header *Header, body []byte, cs *connState) ([]byte, uint8) {
	if header.SeqNo == 1 {
		return s.handleAuthenStart(ctx, header, body, cs)
	}
	return s.handleAuthenContinue(ctx, header, body, cs)
}

// handleAuthenPacketWithState processes authentication packets and returns session state.
func (s *Server) handleAuthenPacketWithState(ctx context.Context, header *Header, body []byte, cs *connState) ([]byte, uint8, SessionState) {
	respBody, respType := s.handleAuthenPacket(ctx, header, body, cs)

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

func (s *Server) fireConnect(remoteAddr, localAddr net.Addr, tlsState *tls.ConnectionState) {
	if s.hooks.OnConnect != nil {
		s.hooks.OnConnect(ConnectEvent{RemoteAddr: remoteAddr, LocalAddr: localAddr, TLSState: tlsState})
	}
}

func (s *Server) fireDisconnect(remoteAddr, localAddr net.Addr) {
	if s.hooks.OnDisconnect != nil {
		s.hooks.OnDisconnect(DisconnectEvent{RemoteAddr: remoteAddr, LocalAddr: localAddr})
	}
}

func (s *Server) fireReadError(err error, remoteAddr, localAddr net.Addr) {
	if isProtocolError(err) {
		s.firePacketError(remoteAddr, localAddr, err)
	}
}

// isProtocolError returns true if the error is a TACACS+ protocol-level error
// (invalid header, invalid packet, body too large) rather than a transport-level
// error (timeout, connection reset, EOF).
func isProtocolError(err error) bool {
	return errors.Is(err, ErrInvalidHeader) ||
		errors.Is(err, ErrInvalidPacket) ||
		errors.Is(err, ErrInvalidVersion) ||
		errors.Is(err, ErrInvalidType) ||
		errors.Is(err, ErrBodyTooLarge)
}

func (s *Server) fireBadSecret(remoteAddr, localAddr net.Addr) {
	if s.hooks.OnBadSecret != nil {
		s.hooks.OnBadSecret(BadSecretEvent{RemoteAddr: remoteAddr, LocalAddr: localAddr})
	}
}

func (s *Server) firePacketError(remoteAddr, localAddr net.Addr, err error) {
	if s.hooks.OnPacketError != nil {
		s.hooks.OnPacketError(PacketErrorEvent{RemoteAddr: remoteAddr, LocalAddr: localAddr, Err: err})
	}
}

func (s *Server) authenErrorResponse(msg string) ([]byte, uint8) {
	reply := &AuthenReply{Status: AuthenStatusError, ServerMsg: []byte(msg)}
	respBody, _ := reply.MarshalBinary()
	return respBody, PacketTypeAuthen
}

// handleUnmarshalError fires the appropriate hook and returns an error response for
// authen packet unmarshal failures. Returns nil if there was no error.
func (s *Server) handleUnmarshalError(err error, cs *connState, errMsg string) ([]byte, uint8, bool) {
	if err == nil {
		return nil, 0, false
	}
	if errors.Is(err, ErrBadSecret) {
		s.fireBadSecret(cs.remoteAddr, cs.localAddr)
		resp, ptype := s.authenErrorResponse("bad secret")
		return resp, ptype, true
	}
	s.firePacketError(cs.remoteAddr, cs.localAddr, err)
	resp, ptype := s.authenErrorResponse(errMsg)
	return resp, ptype, true
}

func (s *Server) handleAuthenStart(ctx context.Context, header *Header, body []byte, cs *connState) ([]byte, uint8) {
	start := &AuthenStart{}
	if resp, ptype, handled := s.handleUnmarshalError(start.UnmarshalBinary(body), cs, "invalid START packet"); handled {
		return resp, ptype
	}

	req := &AuthenRequest{
		SessionID: header.SessionID, RemoteAddr: cs.remoteAddr, LocalAddr: cs.localAddr,
		Header: header, Start: start, UserData: copyUserData(cs.userData),
	}
	reply := s.handler.HandleAuthenStart(ctx, req)
	if reply == nil {
		return s.authenErrorResponse("handler returned nil response")
	}
	respBody, _ := reply.MarshalBinary()
	return respBody, PacketTypeAuthen
}

func (s *Server) handleAuthenContinue(ctx context.Context, header *Header, body []byte, cs *connState) ([]byte, uint8) {
	cont := &AuthenContinue{}
	if resp, ptype, handled := s.handleUnmarshalError(cont.UnmarshalBinary(body), cs, "invalid CONTINUE packet"); handled {
		return resp, ptype
	}

	req := &AuthenContinueRequest{
		SessionID: header.SessionID, RemoteAddr: cs.remoteAddr, LocalAddr: cs.localAddr,
		Header: header, Continue: cont, UserData: copyUserData(cs.userData),
	}
	reply := s.handler.HandleAuthenContinue(ctx, req)
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

func (s *Server) handleAuthorPacket(ctx context.Context, header *Header, body []byte, cs *connState) ([]byte, uint8, SessionState) {
	request := &AuthorRequest{}
	if err := request.UnmarshalBinary(body); err != nil {
		msg := "invalid authorization request"
		if errors.Is(err, ErrBadSecret) {
			s.fireBadSecret(cs.remoteAddr, cs.localAddr)
			msg = "bad secret"
		} else {
			s.firePacketError(cs.remoteAddr, cs.localAddr, err)
		}
		respBody, respType := s.authorErrorResponse(msg)
		return respBody, respType, SessionStateError
	}

	req := &AuthorRequestContext{
		SessionID: header.SessionID, RemoteAddr: cs.remoteAddr, LocalAddr: cs.localAddr,
		Header: header, Request: request, UserData: copyUserData(cs.userData),
	}
	resp := s.handler.HandleAuthorRequest(ctx, req)
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

func (s *Server) handleAcctPacket(ctx context.Context, header *Header, body []byte, cs *connState) ([]byte, uint8, SessionState) {
	request := &AcctRequest{}
	if err := request.UnmarshalBinary(body); err != nil {
		msg := "invalid accounting request"
		if errors.Is(err, ErrBadSecret) {
			s.fireBadSecret(cs.remoteAddr, cs.localAddr)
			msg = "bad secret"
		} else {
			s.firePacketError(cs.remoteAddr, cs.localAddr, err)
		}
		respBody, respType := s.acctErrorResponse(msg)
		return respBody, respType, SessionStateError
	}

	req := &AcctRequestContext{
		SessionID: header.SessionID, RemoteAddr: cs.remoteAddr, LocalAddr: cs.localAddr,
		Header: header, Request: request, UserData: copyUserData(cs.userData),
	}
	resp := s.handler.HandleAcctRequest(ctx, req)
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
