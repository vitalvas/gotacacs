# TACACS+ SDK Implementation Roadmap

Implementation roadmap for TACACS+ RFC8907 SDK providing client and server interfaces.

**Testing Requirements:**
- Each step must include unit tests with race detector
- Minimum test coverage: 80% per package
- All tests must pass via `yake tests` before proceeding to next step

## 1. Project Initialization

- [ ] Initialize Go module with `go mod init github.com/vitalvas/gotacacs`
- [ ] Create `.golangci.yml` configuration using `yake code defaults`
- [ ] Add test dependencies (`github.com/stretchr/testify`)
- [ ] Verify `yake tests` runs successfully (empty project baseline)

## 2. Core Protocol Types and Header

### 2.1 Constants and Enumerations

- [ ] Define TACACS+ major version (0x0c) and minor version (0x00, 0x01) constants
- [ ] Define packet type constants (AUTHEN=0x01, AUTHOR=0x02, ACCT=0x03)
- [ ] Define flag constants (UNENCRYPTED_FLAG=0x01, SINGLE_CONNECT_FLAG=0x04)
- [ ] Define authentication action types (LOGIN=0x01, CHPASS=0x02, SENDAUTH=0x04)
- [ ] Define authentication types (ASCII=0x01, PAP=0x02, CHAP=0x03, MSCHAP=0x05, MSCHAPV2=0x06)
- [ ] Define authentication services (NONE=0x00, LOGIN=0x01, ENABLE=0x02, PPP=0x03, PT=0x05, RCMD=0x06, X25=0x07, NASI=0x08)
- [ ] Define authentication status codes (PASS=0x01, FAIL=0x02, GETDATA=0x03, GETUSER=0x04, GETPASS=0x05, RESTART=0x06, ERROR=0x07, FOLLOW=0x21)
- [ ] Define authentication reply flags (NOECHO=0x01)
- [ ] Define authentication continue flags (ABORT=0x01)
- [ ] Define authorization status codes (PASS_ADD=0x01, PASS_REPL=0x02, FAIL=0x10, ERROR=0x11, FOLLOW=0x21)
- [ ] Define accounting flags (START=0x02, STOP=0x04, WATCHDOG=0x08)
- [ ] Define accounting status codes (SUCCESS=0x01, ERROR=0x02, FOLLOW=0x21)
- [ ] Write tests for constant values validation
- [ ] Run `yake tests` - verify pass

### 2.2 Error Definitions

- [ ] Define base error type with protocol context
- [ ] Define ErrInvalidHeader (malformed header)
- [ ] Define ErrInvalidPacket (malformed packet body)
- [ ] Define ErrInvalidVersion (unsupported version)
- [ ] Define ErrInvalidSequence (sequence number violation)
- [ ] Define ErrSessionNotFound (unknown session ID)
- [ ] Define ErrConnectionClosed (connection terminated)
- [ ] Define ErrTimeout (operation timeout)
- [ ] Define ErrAuthenticationFailed (auth failure)
- [ ] Define ErrAuthorizationDenied (authz failure)
- [ ] Define ErrAccountingFailed (acct failure)
- [ ] Write tests for error wrapping and unwrapping
- [ ] Run `yake tests` - verify pass with 80%+ coverage

### 2.3 Header Implementation

- [ ] Implement Header struct (12 bytes: version, type, seq_no, flags, session_id, length)
- [ ] Implement Header.MarshalBinary() for encoding (big-endian)
- [ ] Implement Header.UnmarshalBinary() for decoding
- [ ] Implement Header.Validate() for validation rules
- [ ] Implement NewHeader() constructor with defaults
- [ ] Write tests for header encoding/decoding roundtrip
- [ ] Write tests for header validation (invalid version, type, sequence)
- [ ] Write tests for boundary conditions (max values)
- [ ] Run `yake tests` - verify pass with 80%+ coverage

## 3. Body Obfuscation

### 3.1 Pseudo-pad Generation and Obfuscation

- [ ] Implement pseudoPad() function using MD5 (session_id + secret + version + seq_no)
- [ ] Implement Obfuscate() for body XOR with pseudo-pad
- [ ] Implement Deobfuscate() (same as Obfuscate - XOR is symmetric)
- [ ] Handle UNENCRYPTED_FLAG (skip obfuscation when set)
- [ ] Handle empty secret (no obfuscation)
- [ ] Write tests for pseudo-pad generation with known vectors
- [ ] Write tests for obfuscation/deobfuscation roundtrip
- [ ] Write tests for unencrypted flag handling
- [ ] Write tests for empty secret handling
- [ ] Write tests for various body lengths (shorter and longer than MD5 block)
- [ ] Run `yake tests` - verify pass with 80%+ coverage

## 4. Authentication Packets

### 4.1 Authentication START Packet

- [ ] Implement AuthenStart struct (action, priv_lvl, authen_type, authen_service, user, port, rem_addr, data)
- [ ] Implement AuthenStart.MarshalBinary() with length-prefixed fields
- [ ] Implement AuthenStart.UnmarshalBinary() with validation
- [ ] Implement NewAuthenStart() constructor
- [ ] Write tests for encoding/decoding roundtrip
- [ ] Write tests for various field combinations
- [ ] Write tests for maximum field lengths
- [ ] Write tests for invalid packet detection
- [ ] Run `yake tests` - verify pass with 80%+ coverage

### 4.2 Authentication REPLY Packet

- [ ] Implement AuthenReply struct (status, flags, server_msg, data)
- [ ] Implement AuthenReply.MarshalBinary()
- [ ] Implement AuthenReply.UnmarshalBinary()
- [ ] Implement NewAuthenReply() constructor
- [ ] Implement helper methods (IsPass(), IsFail(), NeedsInput(), etc.)
- [ ] Write tests for encoding/decoding roundtrip
- [ ] Write tests for all status codes
- [ ] Write tests for NOECHO flag handling
- [ ] Write tests for helper methods
- [ ] Run `yake tests` - verify pass with 80%+ coverage

### 4.3 Authentication CONTINUE Packet

- [ ] Implement AuthenContinue struct (flags, user_msg, data)
- [ ] Implement AuthenContinue.MarshalBinary()
- [ ] Implement AuthenContinue.UnmarshalBinary()
- [ ] Implement NewAuthenContinue() constructor
- [ ] Implement IsAbort() helper method
- [ ] Write tests for encoding/decoding roundtrip
- [ ] Write tests for abort flag handling
- [ ] Write tests for user_msg and data fields
- [ ] Run `yake tests` - verify pass with 80%+ coverage

## 5. Authorization Packets

### 5.1 Authorization REQUEST Packet

- [ ] Implement AuthorRequest struct (authen_method, priv_lvl, authen_type, authen_service, user, port, rem_addr, args)
- [ ] Implement AuthorRequest.MarshalBinary() with argument list encoding
- [ ] Implement AuthorRequest.UnmarshalBinary()
- [ ] Implement NewAuthorRequest() constructor
- [ ] Implement AddArg() and GetArgs() methods
- [ ] Write tests for encoding/decoding roundtrip
- [ ] Write tests for argument list handling (0, 1, many args)
- [ ] Write tests for argument format (key=value, key*value)
- [ ] Write tests for maximum argument count (255)
- [ ] Run `yake tests` - verify pass with 80%+ coverage

### 5.2 Authorization RESPONSE Packet

- [ ] Implement AuthorResponse struct (status, args, server_msg, data)
- [ ] Implement AuthorResponse.MarshalBinary()
- [ ] Implement AuthorResponse.UnmarshalBinary()
- [ ] Implement NewAuthorResponse() constructor
- [ ] Implement helper methods (IsPass(), IsFail(), GetArgs())
- [ ] Write tests for encoding/decoding roundtrip
- [ ] Write tests for all status codes
- [ ] Write tests for argument modification scenarios
- [ ] Run `yake tests` - verify pass with 80%+ coverage

## 6. Accounting Packets

### 6.1 Accounting REQUEST Packet

- [ ] Implement AcctRequest struct (flags, authen_method, priv_lvl, authen_type, authen_service, user, port, rem_addr, args)
- [ ] Implement AcctRequest.MarshalBinary()
- [ ] Implement AcctRequest.UnmarshalBinary()
- [ ] Implement NewAcctRequest() constructor
- [ ] Implement flag helpers (IsStart(), IsStop(), IsWatchdog())
- [ ] Write tests for encoding/decoding roundtrip
- [ ] Write tests for all flag combinations
- [ ] Write tests for argument list handling
- [ ] Run `yake tests` - verify pass with 80%+ coverage

### 6.2 Accounting REPLY Packet

- [ ] Implement AcctReply struct (status, server_msg, data)
- [ ] Implement AcctReply.MarshalBinary()
- [ ] Implement AcctReply.UnmarshalBinary()
- [ ] Implement NewAcctReply() constructor
- [ ] Implement helper methods (IsSuccess(), IsError())
- [ ] Write tests for encoding/decoding roundtrip
- [ ] Write tests for all status codes
- [ ] Run `yake tests` - verify pass with 80%+ coverage

## 7. Packet Interface and Factory

- [ ] Define Packet interface (Type(), MarshalBinary(), UnmarshalBinary())
- [ ] Implement packet type registry
- [ ] Implement ParsePacket() factory function
- [ ] Implement packet validation on parse
- [ ] Write tests for packet interface compliance
- [ ] Write tests for factory with all packet types
- [ ] Write tests for invalid packet type handling
- [ ] Run `yake tests` - verify pass with 80%+ coverage

## 8. Transport Layer

### 8.1 Transport Interfaces

- [ ] Define Conn interface (Read, Write, Close, SetDeadline, LocalAddr, RemoteAddr)
- [ ] Define Listener interface (Accept, Close, Addr)
- [ ] Define Dialer interface for client connections
- [ ] Write interface compliance tests

### 8.2 TCP Transport

- [ ] Implement TCPConn wrapper implementing Conn interface
- [ ] Implement TCPListener wrapper implementing Listener interface
- [ ] Implement TCPDialer for client connections
- [ ] Implement connection timeout handling
- [ ] Implement read/write deadline handling
- [ ] Write tests for TCP connection lifecycle
- [ ] Write tests for timeout behavior
- [ ] Write integration tests with local TCP server
- [ ] Run `yake tests` - verify pass with 80%+ coverage

### 8.3 TLS Transport

- [ ] Implement TLSConn wrapper implementing Conn interface
- [ ] Implement TLSListener wrapper implementing Listener interface
- [ ] Implement TLSDialer with TLS config options
- [ ] Implement TLS configuration helpers (server cert, client cert, CA)
- [ ] Write tests for TLS connection lifecycle
- [ ] Write tests for certificate validation
- [ ] Write tests for mutual TLS authentication
- [ ] Write integration tests with local TLS server
- [ ] Run `yake tests` - verify pass with 80%+ coverage

## 9. Session Management

### 9.1 Session Implementation

- [ ] Implement Session struct (id, state, seq_no, created, lastActivity)
- [ ] Implement session ID generation (crypto/rand)
- [ ] Implement sequence number management (odd for client, even for server)
- [ ] Implement session state machine (NEW, ACTIVE, COMPLETE, ERROR)
- [ ] Implement NextSeqNo() with validation
- [ ] Write tests for session lifecycle
- [ ] Write tests for sequence number rules
- [ ] Write tests for concurrent access safety
- [ ] Run `yake tests` - verify pass with 80%+ coverage

### 9.2 Session Store

- [ ] Define SessionStore interface (Get, Put, Delete, Cleanup)
- [ ] Implement MemorySessionStore with sync.Map
- [ ] Implement session expiration with configurable TTL
- [ ] Implement background cleanup goroutine
- [ ] Implement graceful shutdown for cleanup
- [ ] Write tests for store operations
- [ ] Write tests for expiration behavior
- [ ] Write tests for concurrent access
- [ ] Write tests for cleanup goroutine
- [ ] Run `yake tests` - verify pass with 80%+ coverage

## 10. Client SDK

### 10.1 Client Options

- [ ] Implement ClientOption function type
- [ ] Implement WithTimeout() option
- [ ] Implement WithTLSConfig() option
- [ ] Implement WithSecret() option
- [ ] Implement WithSingleConnect() option
- [ ] Implement WithDialer() option for custom transport
- [ ] Write tests for option application
- [ ] Run `yake tests` - verify pass with 80%+ coverage

### 10.2 Client Connection Management

- [ ] Implement Client struct with connection state
- [ ] Implement NewClient() constructor
- [ ] Implement Client.Connect() for establishing connection
- [ ] Implement Client.Close() for graceful shutdown
- [ ] Implement automatic reconnection logic
- [ ] Implement connection health check (ping)
- [ ] Implement single-connect mode session reuse
- [ ] Write tests for connection lifecycle
- [ ] Write tests for reconnection behavior
- [ ] Write tests for single-connect mode
- [ ] Run `yake tests` - verify pass with 80%+ coverage

### 10.3 Client Packet I/O

- [ ] Implement Client.sendPacket() with obfuscation
- [ ] Implement Client.recvPacket() with deobfuscation
- [ ] Implement packet framing (header + body)
- [ ] Implement read/write timeout handling
- [ ] Write tests for packet send/receive
- [ ] Write tests for obfuscation integration
- [ ] Write tests for timeout handling
- [ ] Run `yake tests` - verify pass with 80%+ coverage

### 10.4 Client Authentication API

- [ ] Implement Client.Authenticate() high-level method
- [ ] Implement AuthenContext for multi-step auth state
- [ ] Implement ASCII authentication flow
- [ ] Implement PAP authentication flow
- [ ] Implement CHAP authentication flow
- [ ] Implement GETDATA/GETUSER/GETPASS response handling
- [ ] Implement authentication callback interface for interactive auth
- [ ] Write tests for each authentication type
- [ ] Write tests for multi-step authentication
- [ ] Write tests for authentication failures
- [ ] Run `yake tests` - verify pass with 80%+ coverage

### 10.5 Client Authorization API

- [ ] Implement Client.Authorize() method
- [ ] Implement argument builder helpers
- [ ] Implement response argument parsing
- [ ] Handle PASS_ADD vs PASS_REPL semantics
- [ ] Write tests for authorization success scenarios
- [ ] Write tests for authorization failure scenarios
- [ ] Write tests for argument handling
- [ ] Run `yake tests` - verify pass with 80%+ coverage

### 10.6 Client Accounting API

- [ ] Implement Client.AccountingStart() method
- [ ] Implement Client.AccountingStop() method
- [ ] Implement Client.AccountingWatchdog() method
- [ ] Implement Client.Accounting() unified method with flags
- [ ] Write tests for each accounting operation
- [ ] Write tests for argument handling
- [ ] Write tests for accounting failures
- [ ] Run `yake tests` - verify pass with 80%+ coverage

## 11. Server SDK

### 11.1 Server Options

- [ ] Implement ServerOption function type
- [ ] Implement WithListener() option
- [ ] Implement WithSecretProvider() option for per-client secrets
- [ ] Implement WithSessionStore() option
- [ ] Implement WithReadTimeout() option
- [ ] Implement WithWriteTimeout() option
- [ ] Write tests for option application
- [ ] Run `yake tests` - verify pass with 80%+ coverage

### 11.2 Handler Interfaces

- [ ] Define AuthenticationHandler interface (HandleAuthenStart, HandleAuthenContinue)
- [ ] Define AuthorizationHandler interface (HandleAuthorRequest)
- [ ] Define AccountingHandler interface (HandleAcctRequest)
- [ ] Define Handler interface combining all three
- [ ] Define HandlerFunc types for simple handlers
- [ ] Write interface documentation with examples
- [ ] Run `yake tests` - verify pass

### 11.3 Server Connection Management

- [ ] Implement Server struct with listener management
- [ ] Implement NewServer() constructor
- [ ] Implement Server.Serve() for accepting connections
- [ ] Implement Server.Shutdown() for graceful shutdown
- [ ] Implement connection goroutine management
- [ ] Implement per-connection context
- [ ] Write tests for server lifecycle
- [ ] Write tests for graceful shutdown
- [ ] Write tests for concurrent connections
- [ ] Run `yake tests` - verify pass with 80%+ coverage

### 11.4 Server Packet I/O

- [ ] Implement server-side packet reading with deobfuscation
- [ ] Implement server-side packet writing with obfuscation
- [ ] Implement packet routing based on type
- [ ] Implement sequence number validation
- [ ] Write tests for packet I/O
- [ ] Write tests for sequence validation
- [ ] Run `yake tests` - verify pass with 80%+ coverage

### 11.5 Server Authentication Processing

- [ ] Implement authentication session state machine
- [ ] Implement START packet dispatch to handler
- [ ] Implement CONTINUE packet dispatch to handler
- [ ] Implement reply sending with proper status codes
- [ ] Implement authentication timeout handling
- [ ] Write tests for authentication flows
- [ ] Write tests for state machine transitions
- [ ] Write tests for timeout handling
- [ ] Run `yake tests` - verify pass with 80%+ coverage

### 11.6 Server Authorization Processing

- [ ] Implement authorization request dispatch
- [ ] Implement argument processing
- [ ] Implement response sending with argument modifications
- [ ] Write tests for authorization flows
- [ ] Write tests for argument handling
- [ ] Run `yake tests` - verify pass with 80%+ coverage

### 11.7 Server Accounting Processing

- [ ] Implement accounting request dispatch
- [ ] Implement accounting record context creation
- [ ] Implement reply sending
- [ ] Write tests for accounting flows
- [ ] Write tests for all flag combinations
- [ ] Run `yake tests` - verify pass with 80%+ coverage

## 12. Integration Testing

- [ ] Create testutil package with test helpers
- [ ] Implement mock handlers for testing
- [ ] Create client-server integration test framework
- [ ] Write ASCII authentication end-to-end test
- [ ] Write PAP authentication end-to-end test
- [ ] Write CHAP authentication end-to-end test
- [ ] Write multi-step authentication end-to-end test
- [ ] Write authorization end-to-end test
- [ ] Write accounting end-to-end test
- [ ] Write TLS transport end-to-end test
- [ ] Write single-connect mode end-to-end test
- [ ] Write concurrent client end-to-end test
- [ ] Run `yake tests` - verify all pass with 80%+ overall coverage

## 13. Example Binaries

### 13.1 Example Client (cmd/tacacs-client)

- [ ] Implement CLI with standard library `flag` package
- [ ] Implement flags (server, secret, timeout, tls-cert, tls-key, tls-ca)
- [ ] Implement mode flag for authenticate/authorize/accounting
- [ ] Implement verbose/debug output with standard `log` package
- [ ] Write tests for flag parsing
- [ ] Run `yake tests` - verify pass with 80%+ coverage

### 13.2 Example Server (cmd/tacacs-server)

- [ ] Implement CLI with standard library `flag` package
- [ ] Implement flags (listen, secret, tls-cert, tls-key, tls-ca)
- [ ] Implement file-based user authentication handler
- [ ] Implement basic authorization handler with rules
- [ ] Implement log-based accounting handler (standard `log` package)
- [ ] Write tests for flag parsing
- [ ] Write tests for handlers
- [ ] Run `yake tests` - verify pass with 80%+ coverage

## 14. Documentation and Final Validation

- [ ] Add package-level documentation for main package
- [ ] Add GoDoc examples for Client usage
- [ ] Add GoDoc examples for Server usage
- [ ] Add GoDoc examples for handler implementations
- [ ] Run `go fmt ./...` on all files
- [ ] Run `golangci-lint run` and fix all issues
- [ ] Verify overall test coverage >= 80%
- [ ] Run all tests with race detector: `go test -race ./...`
- [ ] Run `yake tests` - final verification
- [ ] Update dependencies: `go get -u ./...` and `go mod tidy`
