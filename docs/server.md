# TACACS+ Server

The gotacacs server provides a framework for implementing TACACS+ AAA services with pluggable handlers for Authentication, Authorization, and Accounting.

## Creating a Server

Create a server using `NewServer` with functional options:

```go
import (
    "log"
    "go.vitalvas.com/gotacacs"
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
| `WithServerListener(listener)` | Network listener for `Serve`; optional for `ServeConn` | None |
| `WithServerSecret(secret string)` | Static shared secret | None |
| `WithServerSecretBytes(secret []byte)` | Static shared secret as bytes | None |
| `WithSecretProvider(provider)` | Per-client secret provider | None |
| `WithHandler(handler)` | Combined AAA handler | None |
| `WithAuthenticationHandler(handler)` | Authentication-only handler | None |
| `WithAuthorizationHandler(handler)` | Authorization-only handler | None |
| `WithAccountingHandler(handler)` | Accounting-only handler | None |
| `WithServerReadTimeout(duration)` | Packet read and TLS handshake timeout; zero disables this timeout | 30 seconds |
| `WithServerWriteTimeout(duration)` | Write timeout | 30 seconds |
| `WithServerMaxBodyLength(length uint32)` | Maximum allowed request body length | 256 KiB |
| `WithServerMaxSessionsPerConn(count int)` | Maximum concurrent sessions per connection; the connection is terminated with `ErrTooManySessions` when exceeded | 64 |
| `WithServerMaxAuthenRetries(count int)` | Maximum interactive re-prompts (GETUSER/GETPASS/GETDATA) per authentication session before the server sends FAIL (RFC 8907 Section 5.4.2.1). `0` disables the cap | 3 |
| `WithServerAllowInsecure(allow bool)` | Permit non-TLS connections with no shared secret (cleartext AAA). RFC 8907 forbids this, so it is rejected with `ErrNoSecret` by default | false |
| `WithServerSingleConnect(allow bool)` | Accept a client's single-connection request (RFC 8907 Section 4.3). When false the server refuses it and closes after each session | true |
| `WithServerAllowedAuthenTypes(types...)` | Restrict authentication START packets to the listed `authen_type` values (RFC 8907 Section 10.5.3). A disallowed type is refused with FAIL. Empty allows all | all |
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

### PAP Handler Example

```go
type myHandler struct {
    users       map[string]string
    permissions map[string][]string
}

func (h *myHandler) HandleAuthenStart(_ context.Context, req *gotacacs.AuthenRequest) *gotacacs.AuthenReply {
    if req.Start.Action != gotacacs.AuthenActionLogin ||
        req.Start.AuthenType != gotacacs.AuthenTypePAP ||
        req.Start.Service != gotacacs.AuthenServiceLogin {
        return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusFail}
    }
    user := string(req.Start.User)

    log.Printf("Authentication: user=%s from=%s userData=%v",
        user, req.RemoteAddr, req.UserData)

    // Demo only: real deployments store salted password hashes. Compare in
    // constant time so a reply cannot leak password-prefix timing.
    expectedPass, ok := h.users[user]
    if !ok || subtle.ConstantTimeCompare(req.Start.Data, []byte(expectedPass)) != 1 {
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

func (h *myHandler) HandleAuthenContinue(_ context.Context, _ *gotacacs.AuthenContinueRequest) *gotacacs.AuthenReply {
    return &gotacacs.AuthenReply{
        Status:    gotacacs.AuthenStatusError,
        ServerMsg: []byte("CONTINUE not supported"),
    }
}

func (h *myHandler) HandleAuthorRequest(_ context.Context, req *gotacacs.AuthorRequestContext) *gotacacs.AuthorResponse {
    user := string(req.Request.User)
    args := req.Request.Args()

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
        RawArgs: respArgs,
    }
}

func (h *myHandler) HandleAcctRequest(_ context.Context, req *gotacacs.AcctRequestContext) *gotacacs.AcctReply {
    user := string(req.Request.User)
    args := req.Request.Args()

    log.Printf("Accounting: user=%s flags=%d args=%v from=%s userData=%v",
        user, req.Request.Flags, args, req.RemoteAddr, req.UserData)

    // Log or store accounting data
    if req.Request.IsWatchdog() {
        log.Printf("Watchdog update for %s", user)
    } else if req.Request.IsStart() {
        log.Printf("Session started for %s", user)
    } else if req.Request.IsStop() {
        log.Printf("Session stopped for %s", user)
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
| FOLLOW | `AuthenStatusFollow` | Client returns the reply with `ErrAuthenFollow` |

### CHAP Authentication

A CHAP login ([RFC 8907 Section 5.4.2.3](https://datatracker.ietf.org/doc/html/rfc8907#section-5.4.2.3)) arrives as a single START whose data field holds the id, challenge, and MD5 response. Verify it with `VerifyCHAP`, which recomputes the response from the shared secret and compares in constant time:

```go
func (h *myHandler) HandleAuthenStart(_ context.Context, req *gotacacs.AuthenRequest) *gotacacs.AuthenReply {
    if req.Start.AuthenType == gotacacs.AuthenTypeCHAP {
        secret := h.secretFor(string(req.Start.User)) // the user's CHAP secret
        ok, err := gotacacs.VerifyCHAP(secret, req.Start.Data)
        if err != nil || !ok {
            return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusFail}
        }
        return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusPass}
    }
    // ... other authen types
}
```

`ParseCHAPData` and `CHAPResponse` are available for handlers that need the id, challenge, or response separately. MS-CHAP and MS-CHAPv2 are not implemented.

### Multi-Step Authentication

For ASCII authentication, handlers use GETUSER to collect a missing username, GETPASS to collect a password, and GETDATA for other input. Keep the requested input and credentials in application state scoped to the connection and `SessionID`; different connections can reuse a `SessionID`. Limit username retries; [RFC 8907 Section 5.4.2.1](https://datatracker.ietf.org/doc/html/rfc8907#section-5.4.2.1) recommends three attempts.

For example, return this reply when the handler is ready to request the password:

```go
reply := &gotacacs.AuthenReply{
    Status:    gotacacs.AuthenStatusGetPass,
    ServerMsg: []byte("Password: "),
    Flags:     gotacacs.AuthenReplyFlagNoEcho,
}
```

The next CONTINUE carries the answer in `req.Continue.UserMsg`. Validate it for the current authentication step before returning PASS. ASCII START and CONTINUE `Data` fields are unused and must be ignored.

An ABORT is still delivered to `HandleAuthenContinue` so the handler can release its application state:

```go
if req.Continue.IsAbort() {
    // Release authentication state for this connection and session.
    return nil
}
```

The server discards the handler's reply to ABORT, removes the tracked session, and sends no response. A connection negotiated for single-connect remains available for other sessions.

## Authorization Status Codes

| Status | Constant | Description |
|--------|----------|-------------|
| PASS_ADD | `AuthorStatusPassAdd` | Authorized, add returned args |
| PASS_REPL | `AuthorStatusPassRepl` | Authorized, replace with returned args |
| FAIL | `AuthorStatusFail` | Authorization denied |
| ERROR | `AuthorStatusError` | Server error |
| FOLLOW | `AuthorStatusFollow` | Client returns the response without automatic redirection |

### Authorization Arguments

Parse and process authorization arguments:

```go
func (h *myHandler) HandleAuthorRequest(_ context.Context, req *gotacacs.AuthorRequestContext) *gotacacs.AuthorResponse {
    values := req.Request.ArgValues()
    service := values.Get("service")
    cmd := values.Get("cmd")

    // Check authorization
    if service == "shell" && h.isCommandAllowed(cmd) {
        return &gotacacs.AuthorResponse{
            Status: gotacacs.AuthorStatusPassAdd,
            RawArgs: gotacacs.ArgsFromMap(map[string]string{"priv-lvl": "15"}),
        }
    }

    return &gotacacs.AuthorResponse{
        Status:    gotacacs.AuthorStatusFail,
        ServerMsg: []byte("Command not authorized"),
    }
}
```

Build response arguments with `ArgValues` when an attribute can have multiple
values:

```go
values := gotacacs.ArgValues{"priv-lvl": []string{"15"}}
values.Add("local-user-name", "remote-readonly")
values.Add("allow-commands1", "show.*")
values.Del("unused-attribute")

resp := &gotacacs.AuthorResponse{
    Status:  gotacacs.AuthorStatusPassAdd,
    RawArgs: values.Output(),
}
```

`ArgValues` parses both mandatory `key=value` and optional `key*value` attributes, splitting each on the first separator, but it is a lossy convenience view: it discards the mandatory/optional separator, wire order, and cross-key interleaving, and `Output` re-emits every pair with `=`. Use it only when those properties do not matter (for example reading a single `priv-lvl`).

For conformant authorization and accounting arguments, use the `Arg` pair type: `ParseArgs(RawArgs)` returns `[]Arg` carrying the `Optional` flag in wire order with duplicates preserved, and `MarshalArgs` renders `[]Arg` back to raw arguments with each separator, order, and duplicate intact. Reading or building `RawArgs` directly with `Args`/`AddArg` is equally lossless. A handler must reject authorization when it cannot process a mandatory (`=`) attribute, as described in [RFC 8907 Section 6.1](https://datatracker.ietf.org/doc/html/rfc8907#section-6.1).

## Accounting Status Codes

| Status | Constant | Description |
|--------|----------|-------------|
| SUCCESS | `AcctStatusSuccess` | Record accepted |
| ERROR | `AcctStatusError` | Server error |
| FOLLOW | `AcctStatusFollow` | Client returns the reply without automatic redirection |

### Accounting Flags

Check the type of accounting record:

```go
func (h *myHandler) HandleAcctRequest(_ context.Context, req *gotacacs.AcctRequestContext) *gotacacs.AcctReply {
    if req.Request.IsWatchdog() {
        // Periodic update; START is also set when arguments are updated.
        h.recordWatchdog(req)
    } else if req.Request.IsStart() {
        // Session starting
        h.recordSessionStart(req)
    } else if req.Request.IsStop() {
        // Session ending
        h.recordSessionStop(req)
    }

    return &gotacacs.AcctReply{Status: gotacacs.AcctStatusSuccess}
}
```

Check WATCHDOG before START because an update with arguments sets both flags. For WATCHDOG without START, ignore all arguments. The server rejects INVALID flag combinations (START with STOP, WATCHDOG with STOP, or no flag set) with `AcctStatusError` before the handler runs, per [RFC 8907 Section 7.2](https://datatracker.ietf.org/doc/html/rfc8907#section-7.2); `AcctRequest.HasValidFlags` exposes the same check.

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
secretProvider := gotacacs.SecretProviderFunc(func(_ context.Context, req gotacacs.SecretRequest) gotacacs.SecretResponse {
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

Each candidate is tried until the deobfuscated body passes packet parsing. All parse failures, including ordinary length mismatches, advance to the next candidate. This validates packet framing; obfuscation does not authenticate the peer cryptographically.

```go
secrets := map[string][]string{
    "10.0.0.1": {"newsecret", "oldsecret"},
    "10.0.0.2": {"onlysecret"},
}

secretProvider := gotacacs.SecretProviderFunc(func(_ context.Context, req gotacacs.SecretRequest) gotacacs.SecretResponse {
    host, _, _ := net.SplitHostPort(req.RemoteAddr.String())
    clientSecrets := secrets[host]
    if len(clientSecrets) == 0 {
        clientSecrets = []string{"defaultsecret"}
    }
    attempt := req.Attempt
    if attempt >= len(clientSecrets) {
        attempt = 0
    }

    return gotacacs.SecretResponse{
        Secret:   []byte(clientSecrets[attempt]),
        Attempts: len(clientSecrets),
    }
})
```

When `Attempts` is 0 or 1, the server uses the single-secret fast path with no behavioral change from previous versions.

When no candidate validates the packet (or, on the single-secret path, the deobfuscated body fails to parse), the server fires `OnBadSecret` and terminates the connection without replying. [RFC 8907 Section 10.5.2](https://www.rfc-editor.org/rfc/rfc8907.html#section-10.5.2) forbids accepting new sessions on a connection after an invalid shared secret is detected, and an error reply obfuscated with the real secret would hand the peer a known-plaintext keystream sample.

### TLS Client Certificate Access

On TLS connections, `SecretRequest.TLSState` provides access to the client certificate. This example passes the CN to handlers as logging metadata; identity verification belongs in the TLS configuration and uses the configured certificate identities, including SAN DNS names or IP addresses:

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

## Shared Secret Requirement

[RFC 8907 Section 10.5.2](https://www.rfc-editor.org/rfc/rfc8907.html#section-10.5.2) requires a shared secret on every non-TLS connection. A non-TLS connection whose resolved secret is empty is rejected with `ErrNoSecret` before any packet is processed. Configure a secret (`WithServerSecret`, `WithServerSecretBytes`, or `WithSecretProvider`), use TLS, or opt into cleartext with `WithServerAllowInsecure(true)` for testing or trusted transports.

On a TLS connection (RFC 9887), a packet received without the unencrypted flag is answered with a `STATUS_ERROR` reply carrying the flag set, and then the connection terminates.

A packet whose type is not authentication, authorization, or accounting cannot be dispatched. Per [RFC 8907 Section 3.6](https://www.rfc-editor.org/rfc/rfc8907.html#section-3.6), the server replies with the identical cleartext header, the sequence number incremented by one, and the length set to zero, then terminates the connection.

## Text and Username Validation

[RFC 8907 Section 3.7](https://www.rfc-editor.org/rfc/rfc8907.html#section-3.7) requires usernames to follow the RFC 8265 UsernameCasePreserved profile and all other text fields to be printable US-ASCII with no control characters. The server rejects a request whose username fails validation with an error response before invoking the handler. Two exported helpers expose the same checks for application use:

- `ValidateUsername([]byte) error` enforces the RFC 8265 profile for the ASCII range (printable, non-space, non-empty). Full PRECIS handling of non-ASCII code points requires Unicode tables this zero-dependency library does not carry, so a non-ASCII username is rejected rather than passed through unvalidated; an application that must accept non-ASCII usernames should apply a PRECIS implementation before calling the library.
- `ValidateText([]byte) error` enforces printable US-ASCII (space allowed, control characters and non-ASCII bytes rejected) for other text fields.

## Authentication Retry Limit

[RFC 8907 Section 5.4.2.1](https://www.rfc-editor.org/rfc/rfc8907.html#section-5.4.2.1) requires the server to limit interactive authentication retries. The server counts GETUSER/GETPASS/GETDATA re-prompts per session and, once a session exceeds `WithServerMaxAuthenRetries` (default 3), replaces the handler's prompt with a FAIL and ends the session, so a handler that loops on GET* cannot keep a session open to the sequence-number ceiling. Set the limit to `0` to disable the cap.

## TLS Configuration (RFC 9887)

When using TLS, the shared secret is not needed as TLS provides encryption.
The default TLS port is 300. `ListenTLS` clones the configuration and sets both `MinVersion` and `MaxVersion` to TLS 1.3. The configured server read timeout also bounds the TLS handshake.

### Mutual Certificate Authentication

[RFC 9887 Section 3](https://www.rfc-editor.org/rfc/rfc9887.html#section-3) requires mutual authentication. Require a client certificate and verify it against trusted client CAs:

```go
caCert, err := os.ReadFile("ca.crt")
if err != nil {
    log.Fatal(err)
}

caCertPool := x509.NewCertPool()
if !caCertPool.AppendCertsFromPEM(caCert) {
    log.Fatal("CA file contains no certificates")
}

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
if err != nil {
    log.Fatal(err)
}

server := gotacacs.NewServer(
    gotacacs.WithServerListener(ln),
    gotacacs.WithHandler(handler),
)
```

Configure `tls.Config.VerifyConnection` for the required certificate revocation checks and the deployment's permitted client identities. Go's [default certificate verifier](https://pkg.go.dev/crypto/x509#Certificate.Verify) does not check revocation. The callback also runs on resumed connections. Requiring a trusted certificate alone does not enforce which client SAN identities may access the service.

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

Wait for `Shutdown` to finish after `Serve` returns so active handlers have time to exit:

```go
// Handle shutdown signals
signalCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
defer stop()

shutdownDone := make(chan error, 1)
go func() {
    <-signalCtx.Done()
    log.Println("Shutting down server...")

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    shutdownDone <- server.Shutdown(ctx)
}()

if err := server.Serve(); err != nil {
    log.Printf("Server stopped: %v", err)
}
stop() // Also request shutdown if Serve exited before a signal arrived.
if err := <-shutdownDone; err != nil {
    log.Printf("Shutdown error: %v", err)
}
```

Handler contexts are canceled when shutdown begins. If the shutdown context expires, active connections are closed and `Shutdown` returns the context error. Handlers that ignore cancellation may still be running; another `Shutdown` call waits for the same shutdown to complete.

### Serving a Caller-Supplied Connection

`ServeConn` accepts an existing `net.Conn` and runs the same packet handling, timeouts, hooks, secret rotation, and session tracking as `Serve`. It needs no listener and blocks until the connection ends:

```go
server := gotacacs.NewServer(
    gotacacs.WithServerSecret("sharedsecret"),
    gotacacs.WithHandler(handler),
)

if err := server.ServeConn(conn); err != nil {
    log.Printf("Connection ended: %v", err)
}
```

Once accepted for serving, the connection is closed by the server on exit. A connection rejected during shutdown remains the caller's responsibility. `Shutdown` also applies to active `ServeConn` calls. Connection metadata comes from `conn.RemoteAddr()` and `conn.LocalAddr()`; adapters must report the actual device addresses when those are used for secret lookup.

For raw forwarding, `ReadRawPacket(r, maxBodyLength)` returns the original header and body bytes after header and size validation. `WriteRawPacket(w, header, body)` checks the declared body length and handles partial writes. These helpers operate on `io.Reader` and `io.Writer` and leave obfuscation and TLS flag policy to the endpoints.

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
    PacketType PacketType        // Packet type (authen, author, acct)
    State      SessionState      // Current session state
    StartedAt  time.Time         // When the session was created
}
```

`TrackingID` is a monotonic counter unique across all connections. Use it for `KickSession()`. `SessionID` is the TACACS+ session ID chosen by the NAS — it is only unique per connection.

### Listing Active Sessions

Each snapshot includes a separate `UserData` map. Treat shared `TLSState` and address metadata as read-only.

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

Embed `MiddlewareHandler` to delegate all methods to the next handler by default. This example logs authentication requests using the standard library:

```go
type loggingMiddleware struct {
    gotacacs.MiddlewareHandler
}

func (m *loggingMiddleware) HandleAuthenStart(ctx context.Context, req *gotacacs.AuthenRequest) *gotacacs.AuthenReply {
    log.Printf("Authentication request from %s for %q", req.RemoteAddr, req.Start.User)
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
            return &loggingMiddleware{
                MiddlewareHandler: gotacacs.MiddlewareHandler{Next: next},
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

Use the mutually authenticated `tlsConfig` from [TLS Configuration](#tls-configuration-rfc-9887):

```go
ln, err := gotacacs.ListenTLS(":300", tlsConfig)
if err != nil {
    log.Fatal(err)
}
defer ln.Close()
```

### Custom Listener

Any `net.Listener` satisfies the server `Listener` interface:

```go
netLn, err := net.Listen("tcp", ":49")
if err != nil {
    log.Fatal(err)
}

// Apply custom configuration to netLn...

server := gotacacs.NewServer(
    gotacacs.WithServerListener(netLn),
    gotacacs.WithHandler(handler),
)
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

If a handler reply cannot be marshaled (for example, a message exceeds its length field), the server sends the matching protocol ERROR response and ends the session. ABORT is the exception: the handler's response is ignored and no reply is sent.

## Best Practices

1. **Use SecretProvider for TCP**: Configure per-client shared secrets when using the non-TLS transport. TLS connections use certificate authentication instead of obfuscation secrets.

2. **Log with UserData**: Include UserData in logs for client identification.

3. **Handle All Cases**: Return appropriate status codes for all scenarios.

4. **Use TLS**: Always use TLS in production.

5. **Set Timeouts**: Configure read/write timeouts to prevent resource exhaustion.

6. **Limit Body Size**: Set `WithServerMaxBodyLength` to prevent memory exhaustion from malicious clients.

7. **Graceful Shutdown**: Implement proper shutdown handling for clean termination.

8. **Validate Input**: Always validate user input from requests.

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
    gotacacs.WithServerMaxBodyLength(gotacacs.DefaultMaxBodyLength),
)

// Graceful shutdown
go handleShutdown(server)

if err := server.Serve(); err != nil {
    log.Printf("Server stopped: %v", err)
}
```
