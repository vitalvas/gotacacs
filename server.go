package gotacacs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// SecretProvider provides per-client shared secrets.
type SecretProvider interface {
	// GetSecret returns the shared secret for the given remote address.
	// If no secret is found, it should return nil.
	GetSecret(remoteAddr net.Addr) []byte
}

// SecretProviderFunc is an adapter to allow ordinary functions to be used as SecretProvider.
type SecretProviderFunc func(remoteAddr net.Addr) []byte

// GetSecret implements SecretProvider.
func (f SecretProviderFunc) GetSecret(remoteAddr net.Addr) []byte {
	return f(remoteAddr)
}

// StaticSecretProvider returns a SecretProvider that always returns the same secret.
func StaticSecretProvider(secret []byte) SecretProvider {
	return SecretProviderFunc(func(_ net.Addr) []byte {
		return secret
	})
}

// AuthenRequest represents an authentication request context.
type AuthenRequest struct {
	SessionID  uint32
	RemoteAddr net.Addr
	Header     *Header
	Start      *AuthenStart
}

// AuthenContinueRequest represents an authentication continue request context.
type AuthenContinueRequest struct {
	SessionID  uint32
	RemoteAddr net.Addr
	Header     *Header
	Continue   *AuthenContinue
}

// AuthorRequestContext represents an authorization request context.
type AuthorRequestContext struct {
	SessionID  uint32
	RemoteAddr net.Addr
	Header     *Header
	Request    *AuthorRequest
}

// AcctRequestContext represents an accounting request context.
type AcctRequestContext struct {
	SessionID  uint32
	RemoteAddr net.Addr
	Header     *Header
	Request    *AcctRequest
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
	return func(s *Server) {
		s.secretProvider = StaticSecretProvider([]byte(secret))
	}
}

// WithServerSecretBytes sets a static secret for all clients.
func WithServerSecretBytes(secret []byte) ServerOption {
	return func(s *Server) {
		s.secretProvider = StaticSecretProvider(secret)
	}
}

// WithServerSessionStore sets the session store.
func WithServerSessionStore(store SessionStore) ServerOption {
	return func(s *Server) {
		s.sessionStore = store
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
	sessionStore   SessionStore
	readTimeout    time.Duration
	writeTimeout   time.Duration
	authenHandler  AuthenticationHandler
	authorHandler  AuthorizationHandler
	acctHandler    AccountingHandler

	running    bool
	shutdownCh chan struct{}
	wg         sync.WaitGroup
}

// NewServer creates a new TACACS+ server with the given options.
func NewServer(opts ...ServerOption) *Server {
	s := &Server{
		sessionStore: NewMemorySessionStore(),
		readTimeout:  30 * time.Second,
		writeTimeout: 30 * time.Second,
		shutdownCh:   make(chan struct{}),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
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

func (s *Server) handleConnection(conn Conn) {
	defer s.wg.Done()
	defer conn.Close()

	remoteAddr := conn.RemoteAddr()
	secret := s.getSecret(remoteAddr)

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

		header, body, err := s.readPacket(conn, secret)
		if err != nil {
			if errors.Is(err, io.EOF) || isNetClosedError(err) {
				return
			}
			return
		}

		// Get or create session
		session, _ := s.sessionStore.Get(header.SessionID)
		if session == nil {
			session = NewSessionWithID(header.SessionID, false)
			s.sessionStore.Put(session)
		}

		// Validate and update sequence number
		if !session.ValidateSeqNo(header.SeqNo) {
			return
		}
		session.UpdateSeqNo(header.SeqNo)

		// Process packet based on type
		ctx := context.Background()
		var respBody []byte
		var respType uint8

		switch header.Type {
		case PacketTypeAuthen:
			respBody, respType = s.handleAuthenPacket(ctx, header, body, remoteAddr)
		case PacketTypeAuthor:
			respBody, respType = s.handleAuthorPacket(ctx, header, body, remoteAddr)
		case PacketTypeAcct:
			respBody, respType = s.handleAcctPacket(ctx, header, body, remoteAddr)
		default:
			return
		}

		if respBody == nil {
			return
		}

		// Build response header
		respHeader := &Header{
			Version:   header.Version,
			Type:      respType,
			SeqNo:     session.NextSeqNo(),
			Flags:     header.Flags,
			SessionID: header.SessionID,
			Length:    uint32(len(respBody)),
		}

		// Set write deadline
		if s.writeTimeout > 0 {
			conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
		}

		if err := s.writePacket(conn, respHeader, respBody, secret); err != nil {
			return
		}

		// Check if single-connect mode
		if header.Flags&FlagSingleConnect == 0 {
			return
		}
	}
}

func (s *Server) getSecret(remoteAddr net.Addr) []byte {
	if s.secretProvider == nil {
		return nil
	}
	return s.secretProvider.GetSecret(remoteAddr)
}

func (s *Server) readPacket(conn Conn, secret []byte) (*Header, []byte, error) {
	// Read header
	headerBuf := make([]byte, HeaderLength)
	if _, err := io.ReadFull(conn, headerBuf); err != nil {
		return nil, nil, err
	}

	header := &Header{}
	if err := header.UnmarshalBinary(headerBuf); err != nil {
		return nil, nil, err
	}

	// Read body
	body := make([]byte, header.Length)
	if header.Length > 0 {
		if _, err := io.ReadFull(conn, body); err != nil {
			return nil, nil, err
		}
	}

	// Deobfuscate if needed
	if header.Flags&FlagUnencrypted == 0 && len(secret) > 0 {
		body = Deobfuscate(header, secret, body)
	}

	return header, body, nil
}

func (s *Server) writePacket(conn Conn, header *Header, body []byte, secret []byte) error {
	// Obfuscate if needed
	if header.Flags&FlagUnencrypted == 0 && len(secret) > 0 {
		body = Obfuscate(header, secret, body)
	}

	headerBuf, err := header.MarshalBinary()
	if err != nil {
		return err
	}

	if _, err := conn.Write(headerBuf); err != nil {
		return err
	}

	if len(body) > 0 {
		if _, err := conn.Write(body); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) handleAuthenPacket(ctx context.Context, header *Header, body []byte, remoteAddr net.Addr) ([]byte, uint8) {
	if header.SeqNo == 1 {
		return s.handleAuthenStart(ctx, header, body, remoteAddr)
	}
	return s.handleAuthenContinue(ctx, header, body, remoteAddr)
}

func (s *Server) authenErrorResponse(msg string) ([]byte, uint8) {
	reply := &AuthenReply{Status: AuthenStatusError, ServerMsg: []byte(msg)}
	respBody, _ := reply.MarshalBinary()
	return respBody, PacketTypeAuthen
}

func (s *Server) handleAuthenStart(ctx context.Context, header *Header, body []byte, remoteAddr net.Addr) ([]byte, uint8) {
	start := &AuthenStart{}
	if err := start.UnmarshalBinary(body); err != nil {
		return s.authenErrorResponse("invalid START packet")
	}
	if s.authenHandler == nil {
		return s.authenErrorResponse("no authentication handler configured")
	}

	req := &AuthenRequest{
		SessionID: header.SessionID, RemoteAddr: remoteAddr,
		Header: header, Start: start,
	}
	reply := s.authenHandler.HandleAuthenStart(ctx, req)
	if reply == nil {
		return s.authenErrorResponse("handler returned nil response")
	}
	respBody, _ := reply.MarshalBinary()
	return respBody, PacketTypeAuthen
}

func (s *Server) handleAuthenContinue(ctx context.Context, header *Header, body []byte, remoteAddr net.Addr) ([]byte, uint8) {
	cont := &AuthenContinue{}
	if err := cont.UnmarshalBinary(body); err != nil {
		return s.authenErrorResponse("invalid CONTINUE packet")
	}
	if s.authenHandler == nil {
		return s.authenErrorResponse("no authentication handler configured")
	}

	req := &AuthenContinueRequest{
		SessionID: header.SessionID, RemoteAddr: remoteAddr,
		Header: header, Continue: cont,
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

func (s *Server) handleAuthorPacket(ctx context.Context, header *Header, body []byte, remoteAddr net.Addr) ([]byte, uint8) {
	request := &AuthorRequest{}
	if err := request.UnmarshalBinary(body); err != nil {
		return s.authorErrorResponse("invalid authorization request")
	}
	if s.authorHandler == nil {
		return s.authorErrorResponse("no authorization handler configured")
	}

	req := &AuthorRequestContext{
		SessionID: header.SessionID, RemoteAddr: remoteAddr,
		Header: header, Request: request,
	}
	resp := s.authorHandler.HandleAuthorRequest(ctx, req)
	if resp == nil {
		return s.authorErrorResponse("handler returned nil response")
	}
	respBody, _ := resp.MarshalBinary()
	return respBody, PacketTypeAuthor
}

func (s *Server) acctErrorResponse(msg string) ([]byte, uint8) {
	resp := &AcctReply{Status: AcctStatusError, ServerMsg: []byte(msg)}
	respBody, _ := resp.MarshalBinary()
	return respBody, PacketTypeAcct
}

func (s *Server) handleAcctPacket(ctx context.Context, header *Header, body []byte, remoteAddr net.Addr) ([]byte, uint8) {
	request := &AcctRequest{}
	if err := request.UnmarshalBinary(body); err != nil {
		return s.acctErrorResponse("invalid accounting request")
	}
	if s.acctHandler == nil {
		return s.acctErrorResponse("no accounting handler configured")
	}

	req := &AcctRequestContext{
		SessionID: header.SessionID, RemoteAddr: remoteAddr,
		Header: header, Request: request,
	}
	resp := s.acctHandler.HandleAcctRequest(ctx, req)
	if resp == nil {
		return s.acctErrorResponse("handler returned nil response")
	}
	respBody, _ := resp.MarshalBinary()
	return respBody, PacketTypeAcct
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
