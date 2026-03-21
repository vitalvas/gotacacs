# TACACS+ Server

The gotacacs server provides a framework for implementing TACACS+ AAA services with pluggable handlers for Authentication, Authorization, and Accounting.

## Creating a Server

Create a server using `NewServer` with functional options:

```go
import (
    "log"
    "github.com/vitalvas/gotacacs"
)

ln, err := gotacacs.ListenTCP(":49")
if err != nil {
    log.Fatal(err)
}

server := gotacacs.NewServer(
    gotacacs.WithServerListener(ln),
    gotacacs.WithServerSecret("sharedsecret"),
    gotacacs.WithHandler(&myHandler{}),
)

if err := server.Serve(); err != nil {
    log.Fatal(err)
}
```

## Server Options

| Option | Description | Default |
|--------|-------------|---------|
| `WithServerListener(listener)` | Network listener | Required |
| `WithServerSecret(secret string)` | Static shared secret | None |
| `WithServerSecretBytes(secret []byte)` | Static shared secret as bytes | None |
| `WithSecretProvider(provider)` | Per-client secret provider | None |
| `WithHandler(handler)` | Combined AAA handler | None |
| `WithAuthenticationHandler(handler)` | Authentication-only handler | None |
| `WithAuthorizationHandler(handler)` | Authorization-only handler | None |
| `WithAccountingHandler(handler)` | Accounting-only handler | None |
| `WithServerReadTimeout(duration)` | Read timeout | 30 seconds |
| `WithServerWriteTimeout(duration)` | Write timeout | 30 seconds |
| `WithServerHooks(hooks)` | Lifecycle event hooks | None |
| `WithMiddleware(middlewares...)` | Handler middleware chain | None |

## Handler Interface

Implement the `Handler` interface to process all AAA requests:

```go
type Handler interface {
    AuthenticationHandler
    AuthorizationHandler
    AccountingHandler
}

type AuthenticationHandler interface {
    HandleAuthenStart(ctx context.Context, req *AuthenRequest) *AuthenReply
    HandleAuthenContinue(ctx context.Context, req *AuthenContinueRequest) *AuthenReply
}

type AuthorizationHandler interface {
    HandleAuthorRequest(ctx context.Context, req *AuthorRequestContext) *AuthorResponse
}

type AccountingHandler interface {
    HandleAcctRequest(ctx context.Context, req *AcctRequestContext) *AcctReply
}
```

### Complete Handler Example

```go
type myHandler struct {
    users       map[string]string
    permissions map[string][]string
}

func (h *myHandler) HandleAuthenStart(_ context.Context, req *gotacacs.AuthenRequest) *gotacacs.AuthenReply {
    user := string(req.Start.User)
    password := string(req.Start.Data)

    log.Printf("Authentication: user=%s from=%s userData=%v",
        user, req.RemoteAddr, req.UserData)

    expectedPass, ok := h.users[user]
    if !ok || password != expectedPass {
        return &gotacacs.AuthenReply{
            Status:    gotacacs.AuthenStatusFail,
            ServerMsg: []byte("Invalid credentials"),
        }
    }

    return &gotacacs.AuthenReply{
        Status:    gotacacs.AuthenStatusPass,
        ServerMsg: []byte("Authentication successful"),
    }
}

func (h *myHandler) HandleAuthenContinue(_ context.Context, req *gotacacs.AuthenContinueRequest) *gotacacs.AuthenReply {
    // Handle multi-step authentication (ASCII mode)
    userInput := string(req.Continue.UserMsg)

    // Process input and return appropriate response
    return &gotacacs.AuthenReply{
        Status: gotacacs.AuthenStatusPass,
    }
}

func (h *myHandler) HandleAuthorRequest(_ context.Context, req *gotacacs.AuthorRequestContext) *gotacacs.AuthorResponse {
    user := string(req.Request.User)
    args := req.Request.GetArgs()

    log.Printf("Authorization: user=%s args=%v from=%s userData=%v",
        user, args, req.RemoteAddr, req.UserData)

    perms, ok := h.permissions[user]
    if !ok {
        return &gotacacs.AuthorResponse{
            Status:    gotacacs.AuthorStatusFail,
            ServerMsg: []byte("User not authorized"),
        }
    }

    // Return authorized attributes
    respArgs := make([][]byte, len(perms))
    for i, p := range perms {
        respArgs[i] = []byte(p)
    }

    return &gotacacs.AuthorResponse{
        Status: gotacacs.AuthorStatusPassAdd,
        Args:   respArgs,
    }
}

func (h *myHandler) HandleAcctRequest(_ context.Context, req *gotacacs.AcctRequestContext) *gotacacs.AcctReply {
    user := string(req.Request.User)
    args := req.Request.GetArgs()

    log.Printf("Accounting: user=%s flags=%d args=%v from=%s userData=%v",
        user, req.Request.Flags, args, req.RemoteAddr, req.UserData)

    // Log or store accounting data
    if req.Request.IsStart() {
        log.Printf("Session started for %s", user)
    } else if req.Request.IsStop() {
        log.Printf("Session stopped for %s", user)
    } else if req.Request.IsWatchdog() {
        log.Printf("Watchdog update for %s", user)
    }

    return &gotacacs.AcctReply{
        Status: gotacacs.AcctStatusSuccess,
    }
}
```

## Request Context

Each handler receives a request context containing connection information:

### AuthenRequest

```go
type AuthenRequest struct {
    Header     *Header          // Packet header
    Start      *AuthenStart     // Authentication start data
    SessionID  uint32           // Session identifier
    RemoteAddr net.Addr         // Client address
    LocalAddr  net.Addr         // Server address
    UserData   map[string]string // Custom data from SecretProvider
}
```

### AuthenContinueRequest

```go
type AuthenContinueRequest struct {
    Header     *Header          // Packet header
    Continue   *AuthenContinue  // Continue data with user input
    SessionID  uint32           // Session identifier
    RemoteAddr net.Addr         // Client address
    LocalAddr  net.Addr         // Server address
    UserData   map[string]string // Custom data from SecretProvider
}
```

### AuthorRequestContext

```go
type AuthorRequestContext struct {
    Header     *Header          // Packet header
    Request    *AuthorRequest   // Authorization request data
    SessionID  uint32           // Session identifier
    RemoteAddr net.Addr         // Client address
    LocalAddr  net.Addr         // Server address
    UserData   map[string]string // Custom data from SecretProvider
}
```

### AcctRequestContext

```go
type AcctRequestContext struct {
    Header     *Header          // Packet header
    Request    *AcctRequest     // Accounting request data
    SessionID  uint32           // Session identifier
    RemoteAddr net.Addr         // Client address
    LocalAddr  net.Addr         // Server address
    UserData   map[string]string // Custom data from SecretProvider
}
```

## Authentication Status Codes

| Status | Constant | Description |
|--------|----------|-------------|
| PASS | `AuthenStatusPass` | Authentication successful |
| FAIL | `AuthenStatusFail` | Authentication failed |
| GETDATA | `AuthenStatusGetData` | Request additional data |
| GETUSER | `AuthenStatusGetUser` | Request username |
| GETPASS | `AuthenStatusGetPass` | Request password |
| RESTART | `AuthenStatusRestart` | Restart authentication |
| ERROR | `AuthenStatusError` | Server error |
| FOLLOW | `AuthenStatusFollow` | Follow to another server |

### Multi-Step Authentication

For interactive (ASCII) authentication, use GETDATA/GETUSER/GETPASS:

```go
func (h *myHandler) HandleAuthenStart(_ context.Context, req *gotacacs.AuthenRequest) *gotacacs.AuthenReply {
    if len(req.Start.User) == 0 {
        return &gotacacs.AuthenReply{
            Status:    gotacacs.AuthenStatusGetUser,
            ServerMsg: []byte("Username: "),
        }
    }

    return &gotacacs.AuthenReply{
        Status:    gotacacs.AuthenStatusGetPass,
        ServerMsg: []byte("Password: "),
        Flags:     gotacacs.AuthenReplyFlagNoEcho, // Don't echo password
    }
}

func (h *myHandler) HandleAuthenContinue(_ context.Context, req *gotacacs.AuthenContinueRequest) *gotacacs.AuthenReply {
    // Get session state to determine what we're waiting for
    input := string(req.Continue.UserMsg)

    // Validate and return result
    if h.validateCredentials(input) {
        return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusPass}
    }
    return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusFail}
}
```

## Authorization Status Codes

| Status | Constant | Description |
|--------|----------|-------------|
| PASS_ADD | `AuthorStatusPassAdd` | Authorized, add returned args |
| PASS_REPL | `AuthorStatusPassRepl` | Authorized, replace with returned args |
| FAIL | `AuthorStatusFail` | Authorization denied |
| ERROR | `AuthorStatusError` | Server error |
| FOLLOW | `AuthorStatusFollow` | Follow to another server |

### Authorization Arguments

Parse and process authorization arguments:

```go
func (h *myHandler) HandleAuthorRequest(_ context.Context, req *gotacacs.AuthorRequestContext) *gotacacs.AuthorResponse {
    args := req.Request.GetArgs()

    var service, cmd string
    for _, arg := range args {
        parts := strings.SplitN(arg, "=", 2)
        if len(parts) == 2 {
            switch parts[0] {
            case "service":
                service = parts[1]
            case "cmd":
                cmd = parts[1]
            }
        }
    }

    // Check authorization
    if service == "shell" && h.isCommandAllowed(cmd) {
        return &gotacacs.AuthorResponse{
            Status: gotacacs.AuthorStatusPassAdd,
            Args:   [][]byte{[]byte("priv-lvl=15")},
        }
    }

    return &gotacacs.AuthorResponse{
        Status:    gotacacs.AuthorStatusFail,
        ServerMsg: []byte("Command not authorized"),
    }
}
```

## Accounting Status Codes

| Status | Constant | Description |
|--------|----------|-------------|
| SUCCESS | `AcctStatusSuccess` | Record accepted |
| ERROR | `AcctStatusError` | Server error |
| FOLLOW | `AcctStatusFollow` | Follow to another server |

### Accounting Flags

Check the type of accounting record:

```go
func (h *myHandler) HandleAcctRequest(_ context.Context, req *gotacacs.AcctRequestContext) *gotacacs.AcctReply {
    if req.Request.IsStart() {
        // Session starting
        h.recordSessionStart(req)
    } else if req.Request.IsStop() {
        // Session ending
        h.recordSessionStop(req)
    } else if req.Request.IsWatchdog() {
        // Periodic update
        h.recordWatchdog(req)
    }

    return &gotacacs.AcctReply{Status: gotacacs.AcctStatusSuccess}
}
```

## Per-Client Secret Provider

Use `SecretProviderFunc` for per-client secrets and custom user data:

```go
type SecretRequest struct {
    RemoteAddr net.Addr              // Client address
    LocalAddr  net.Addr              // Server address
    TLSState   *tls.ConnectionState  // TLS state (nil for non-TLS)
    Attempt    int                   // 0-based secret attempt index (for rotation)
}

type SecretResponse struct {
    Secret   []byte             // Shared secret for obfuscation
    UserData map[string]string  // Custom data passed to handlers
    Attempts int                // Total secrets available (0 or 1 = no rotation)
}

type SecretProvider interface {
    GetSecret(ctx context.Context, req SecretRequest) SecretResponse
}
```

### Implementation Example

```go
secretProvider := gotacacs.SecretProviderFunc(func(ctx context.Context, req gotacacs.SecretRequest) gotacacs.SecretResponse {
    host, _, _ := net.SplitHostPort(req.RemoteAddr.String())

    // Look up client configuration
    clientConfig := getClientConfig(host)

    return gotacacs.SecretResponse{
        Secret: []byte(clientConfig.Secret),
        UserData: map[string]string{
            "client_ip":   host,
            "client_name": clientConfig.Name,
            "client_type": clientConfig.Type,
            "site":        clientConfig.Site,
            "local_addr":  req.LocalAddr.String(),
        },
    }
})

server := gotacacs.NewServer(
    gotacacs.WithServerListener(ln),
    gotacacs.WithSecretProvider(secretProvider),
    gotacacs.WithHandler(handler),
)
```

### Accessing UserData in Handlers

```go
func (h *myHandler) HandleAuthenStart(_ context.Context, req *gotacacs.AuthenRequest) *gotacacs.AuthenReply {
    // Access custom data from SecretProvider
    clientName := req.UserData["client_name"]
    clientType := req.UserData["client_type"]
    site := req.UserData["site"]

    log.Printf("Auth from %s (%s) at %s", clientName, clientType, site)

    // Use this data for authorization decisions, logging, etc.
    // ...
}
```

### Secret Rotation

During secret rotation, the server needs to accept both old and new secrets simultaneously. Set `SecretResponse.Attempts` to the total number of available secrets. The server calls `GetSecret` with increasing `SecretRequest.Attempt` values (0, 1, 2, ...) until one succeeds or all fail.

The secret is resolved on the first packet of a connection and reused for the entire connection lifetime, including single-connect mode with multiple sessions.

```go
secrets := map[string][]string{
    "10.0.0.1": {"newsecret", "oldsecret"},
    "10.0.0.2": {"onlysecret"},
}

secretProvider := gotacacs.SecretProviderFunc(func(_ context.Context, req gotacacs.SecretRequest) gotacacs.SecretResponse {
    host, _, _ := net.SplitHostPort(req.RemoteAddr.String())
    clientSecrets := secrets[host]

    return gotacacs.SecretResponse{
        Secret:   []byte(clientSecrets[req.Attempt]),
        Attempts: len(clientSecrets),
    }
})
```

When `Attempts` is 0 or 1, the server uses the single-secret fast path with no behavioral change from previous versions.

### TLS Client Certificate Access

On TLS connections, `SecretRequest.TLSState` provides access to the client certificate. Use this to extract the CN or other certificate fields and pass them to handlers via `UserData`:

```go
secretProvider := gotacacs.SecretProviderFunc(func(_ context.Context, req gotacacs.SecretRequest) gotacacs.SecretResponse {
    userData := map[string]string{}

    if req.TLSState != nil && len(req.TLSState.PeerCertificates) > 0 {
        cert := req.TLSState.PeerCertificates[0]
        userData["cn"] = cert.Subject.CommonName
    }

    return gotacacs.SecretResponse{
        UserData: userData,
    }
})
```

`TLSState` is nil for non-TLS connections.

## TLS Configuration (RFC 9887)

When using TLS, the shared secret is not needed as TLS provides encryption.
The default TLS port for TACACS+ is 300 per RFC 9887. `ListenTLS` enforces TLS 1.3.

### Server with TLS

```go
cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
if err != nil {
    log.Fatal(err)
}

tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
}

ln, err := gotacacs.ListenTLS(":300", tlsConfig)
if err != nil {
    log.Fatal(err)
}

server := gotacacs.NewServer(
    gotacacs.WithServerListener(ln),
    gotacacs.WithHandler(handler),
)
```

### TLS with Client Certificate Verification

```go
caCert, err := os.ReadFile("ca.crt")
if err != nil {
    log.Fatal(err)
}

caCertPool := x509.NewCertPool()
caCertPool.AppendCertsFromPEM(caCert)

cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
if err != nil {
    log.Fatal(err)
}

tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    ClientCAs:    caCertPool,
    ClientAuth:   tls.RequireAndVerifyClientCert,
    MinVersion:   tls.VersionTLS13,
}

ln, err := gotacacs.ListenTLS(":300", tlsConfig)
```

## Server Lifecycle

### Starting the Server

```go
// Blocking call - runs until shutdown or error
if err := server.Serve(); err != nil {
    log.Printf("Server error: %v", err)
}
```

### Checking Server Status

```go
if server.IsRunning() {
    fmt.Println("Server is running")
}

addr := server.Addr()
if addr != nil {
    fmt.Printf("Listening on %s\n", addr.String())
}
```

### Graceful Shutdown

```go
// Handle shutdown signals
sigChan := make(chan os.Signal, 1)
signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

go func() {
    <-sigChan
    log.Println("Shutting down server...")

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    if err := server.Shutdown(ctx); err != nil {
        log.Printf("Shutdown error: %v", err)
    }
}()

if err := server.Serve(); err != nil {
    log.Printf("Server stopped: %v", err)
}
```

## Function-Based Handlers

Use handler functions instead of implementing interfaces:

```go
// Authentication handler function
authenHandler := gotacacs.AuthenHandlerFunc(func(_ context.Context, req *gotacacs.AuthenRequest) *gotacacs.AuthenReply {
    // Handle authentication
    return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusPass}
})

// Authorization handler function
authorHandler := gotacacs.AuthorHandlerFunc(func(_ context.Context, req *gotacacs.AuthorRequestContext) *gotacacs.AuthorResponse {
    // Handle authorization
    return &gotacacs.AuthorResponse{Status: gotacacs.AuthorStatusPassAdd}
})

// Accounting handler function
acctHandler := gotacacs.AcctHandlerFunc(func(_ context.Context, req *gotacacs.AcctRequestContext) *gotacacs.AcctReply {
    // Handle accounting
    return &gotacacs.AcctReply{Status: gotacacs.AcctStatusSuccess}
})

server := gotacacs.NewServer(
    gotacacs.WithServerListener(ln),
    gotacacs.WithServerSecret("sharedsecret"),
    gotacacs.WithAuthenticationHandler(authenHandler),
    gotacacs.WithAuthorizationHandler(authorHandler),
    gotacacs.WithAccountingHandler(acctHandler),
)
```

## Active Session Tracking

The server tracks all active sessions and provides methods to list and terminate them.

### SessionInfo

```go
type SessionInfo struct {
    TrackingID uint64            // Unique server-wide identifier
    SessionID  uint32            // TACACS+ session ID from the NAS (may collide across connections)
    RemoteAddr net.Addr          // Client address
    LocalAddr  net.Addr          // Server address
    UserData   map[string]string // Custom data from SecretProvider
    TLSState   *tls.ConnectionState // TLS state (nil for non-TLS)
    PacketType uint8             // Packet type (authen, author, acct)
    State      SessionState      // Current session state
    StartedAt  time.Time         // When the session was created
}
```

`TrackingID` is a monotonic counter unique across all connections. Use it for `KickSession()`. `SessionID` is the TACACS+ session ID chosen by the NAS — it is only unique per connection.

### Listing Active Sessions

```go
sessions := server.Sessions()
for _, s := range sessions {
    fmt.Printf("tracking=%d session=%d remote=%s type=%d state=%s\n",
        s.TrackingID, s.SessionID, s.RemoteAddr, s.PacketType, s.State)
}
```

### Kicking a Session

```go
if server.KickSession(trackingID) {
    fmt.Println("session marked for termination")
}
```

The kicked session receives an error response on its next packet. In single-connect mode, only the kicked session is terminated — the connection stays alive for other sessions. In non-single-connect mode, the connection closes after the error response.

For idle sessions (waiting for client input in multi-step auth), the error is sent when the client sends its next packet.

## Server Lifecycle Hooks

Use `WithServerHooks` to receive notifications about server lifecycle events. All callbacks must be non-blocking. Nil callbacks are skipped.

```go
type ServerHooks struct {
    OnConnect      func(event ConnectEvent)      // New connection accepted
    OnDisconnect   func(event DisconnectEvent)    // Connection closed
    OnSessionStart func(event SessionEvent)       // New session started
    OnSessionEnd   func(event SessionEvent)       // Session completed or terminated
    OnBadSecret    func(event BadSecretEvent)      // Secret validation failed
    OnPacketError  func(event PacketErrorEvent)    // Packet parsing error
}
```

### Event Types

| Event | Fields | When |
|-------|--------|------|
| `ConnectEvent` | `RemoteAddr`, `LocalAddr`, `TLSState` | After TLS handshake and initial secret lookup (before rotation is resolved) |
| `DisconnectEvent` | `RemoteAddr`, `LocalAddr` | Connection closing |
| `SessionEvent` | `SessionInfo` (embedded) | Session start and end |
| `BadSecretEvent` | `RemoteAddr`, `LocalAddr` | All rotation secrets fail, or single secret mismatch |
| `PacketErrorEvent` | `RemoteAddr`, `LocalAddr`, `Err` | Malformed packet (non-secret error) |

### Example

```go
server := gotacacs.NewServer(
    gotacacs.WithServerListener(ln),
    gotacacs.WithServerSecret("sharedsecret"),
    gotacacs.WithHandler(handler),
    gotacacs.WithServerHooks(gotacacs.ServerHooks{
        OnConnect: func(event gotacacs.ConnectEvent) {
            log.Printf("connect: %s", event.RemoteAddr)
        },
        OnDisconnect: func(event gotacacs.DisconnectEvent) {
            log.Printf("disconnect: %s", event.RemoteAddr)
        },
        OnBadSecret: func(event gotacacs.BadSecretEvent) {
            log.Printf("bad secret from %s", event.RemoteAddr)
        },
    }),
)
```

## Middleware

Middleware wraps the `Handler` interface to intercept any of the four request methods (HandleAuthenStart, HandleAuthenContinue, HandleAuthorRequest, HandleAcctRequest). Middlewares are applied in order: first added = outermost (runs first).

```go
type Middleware func(next Handler) Handler
```

### MiddlewareHandler

Embed `MiddlewareHandler` to delegate all methods to the next handler by default. Override only the methods you need:

```go
type rateLimitMiddleware struct {
    gotacacs.MiddlewareHandler
    limiter *rate.Limiter
}

func (m *rateLimitMiddleware) HandleAuthenStart(ctx context.Context, req *gotacacs.AuthenRequest) *gotacacs.AuthenReply {
    if !m.limiter.Allow() {
        return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusError, ServerMsg: []byte("rate limited")}
    }
    return m.Next.HandleAuthenStart(ctx, req)
}
```

### Usage

```go
server := gotacacs.NewServer(
    gotacacs.WithServerListener(ln),
    gotacacs.WithServerSecret("sharedsecret"),
    gotacacs.WithHandler(handler),
    gotacacs.WithMiddleware(
        func(next gotacacs.Handler) gotacacs.Handler {
            return &rateLimitMiddleware{
                MiddlewareHandler: gotacacs.MiddlewareHandler{Next: next},
                limiter:           rate.NewLimiter(100, 10),
            }
        },
    ),
)
```

Middleware that does not call `m.Next.*` short-circuits the chain and the handler is not called.

## Listeners

### TCP Listener

```go
ln, err := gotacacs.ListenTCP(":49")
if err != nil {
    log.Fatal(err)
}
defer ln.Close()
```

### TLS Listener

```go
cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
if err != nil {
    log.Fatal(err)
}

tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
}

ln, err := gotacacs.ListenTLS(":300", tlsConfig)
if err != nil {
    log.Fatal(err)
}
defer ln.Close()
```

### Custom Listener

Wrap any `net.Listener`:

```go
netLn, err := net.Listen("tcp", ":49")
if err != nil {
    log.Fatal(err)
}

// Apply custom configuration to netLn...

ln := &customListener{Listener: netLn}
```

## Error Handling

### Handler Errors

Return error status when processing fails:

```go
func (h *myHandler) HandleAuthenStart(_ context.Context, req *gotacacs.AuthenRequest) *gotacacs.AuthenReply {
    user, err := h.lookupUser(string(req.Start.User))
    if err != nil {
        log.Printf("Database error: %v", err)
        return &gotacacs.AuthenReply{
            Status:    gotacacs.AuthenStatusError,
            ServerMsg: []byte("Internal server error"),
        }
    }

    // Continue processing...
}
```

### Nil Handler Protection

The server handles nil handler returns gracefully:

```go
// If handler returns nil, server returns ERROR status
func (h *myHandler) HandleAuthenStart(_ context.Context, req *gotacacs.AuthenRequest) *gotacacs.AuthenReply {
    return nil  // Server will return AuthenStatusError
}
```

## Best Practices

1. **Use SecretProvider**: Implement per-client secrets for production deployments.

2. **Log with UserData**: Include UserData in logs for client identification.

3. **Handle All Cases**: Return appropriate status codes for all scenarios.

4. **Use TLS**: Always use TLS in production.

5. **Set Timeouts**: Configure read/write timeouts to prevent resource exhaustion.

6. **Graceful Shutdown**: Implement proper shutdown handling for clean termination.

7. **Validate Input**: Always validate user input from requests.

```go
ln, err := gotacacs.ListenTLS(":300", tlsConfig)
if err != nil {
    log.Fatal(err)
}

server := gotacacs.NewServer(
    gotacacs.WithServerListener(ln),
    gotacacs.WithHandler(handler),
    gotacacs.WithServerReadTimeout(30*time.Second),
    gotacacs.WithServerWriteTimeout(30*time.Second),
)

// Graceful shutdown
go handleShutdown(server)

if err := server.Serve(); err != nil {
    log.Printf("Server stopped: %v", err)
}
```
