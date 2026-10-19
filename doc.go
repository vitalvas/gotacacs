// Package gotacacs implements the TACACS+ protocol as defined in RFC8907.
// It provides both client and server SDK interfaces for Authentication,
// Authorization, and Accounting (AAA) services.
//
// TACACS+ is a security protocol that provides centralized access control
// for network devices. This package supports shared-secret body obfuscation
// over TCP and TLS 1.3 transport with obfuscation disabled.
//
// # Client Usage
//
// Create a client to connect to a TACACS+ server:
//
//	client := gotacacs.NewClient(
//		gotacacs.WithAddress("tacacs.example.com:49"),
//		gotacacs.WithSecret("sharedsecret"),
//		gotacacs.WithTimeout(30*time.Second),
//	)
//	defer client.Close()
//
//	// Authenticate a user
//	reply, err := client.Authenticate(ctx, "username", "password")
//	if err != nil {
//		log.Fatal(err)
//	}
//	if reply.IsPass() {
//		fmt.Println("Authentication successful")
//	}
//
//	// Authorize a user
//	resp, err := client.Authorize(ctx, "username", []string{"service=shell", "cmd=show"})
//	if err != nil {
//		log.Fatal(err)
//	}
//	if resp.IsPass() {
//		fmt.Println("Authorization granted")
//	}
//
//	// Send accounting records
//	acctReply, err := client.Accounting(ctx, gotacacs.AcctFlagStart, "username", []string{
//		"task_id=123",
//		"service=shell",
//		"cmd=",
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	if acctReply.IsSuccess() {
//		fmt.Println("Accounting recorded")
//	}
//
// # Server Usage
//
// Create a server with custom handlers:
//
//	ln, err := gotacacs.ListenTCP(":49")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	server := gotacacs.NewServer(
//		gotacacs.WithServerListener(ln),
//		gotacacs.WithServerSecret("sharedsecret"),
//		gotacacs.WithHandler(&myHandler{}),
//	)
//
//	if err := server.Serve(); err != nil {
//		log.Fatal(err)
//	}
//
// # Handler Implementation
//
// Implement the Handler interface to process requests. This example supports
// PAP login; ASCII authentication requires application state for each step:
//
//	type myHandler struct{}
//
//	func (h *myHandler) HandleAuthenStart(_ context.Context, req *gotacacs.AuthenRequest) *gotacacs.AuthenReply {
//		if req.Start.Action != gotacacs.AuthenActionLogin ||
//			req.Start.AuthenType != gotacacs.AuthenTypePAP ||
//			req.Start.Service != gotacacs.AuthenServiceLogin {
//			return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusFail}
//		}
//		// Demo only: real deployments store salted password hashes. Compare in
//		// constant time so a reply cannot leak password-prefix timing.
//		if string(req.Start.User) == "admin" &&
//			subtle.ConstantTimeCompare(req.Start.Data, []byte("password")) == 1 {
//			return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusPass}
//		}
//		return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusFail}
//	}
//
//	func (h *myHandler) HandleAuthenContinue(_ context.Context, _ *gotacacs.AuthenContinueRequest) *gotacacs.AuthenReply {
//		return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusError, ServerMsg: []byte("CONTINUE not supported")}
//	}
//
//	func (h *myHandler) HandleAuthorRequest(_ context.Context, req *gotacacs.AuthorRequestContext) *gotacacs.AuthorResponse {
//		return &gotacacs.AuthorResponse{
//			Status:  gotacacs.AuthorStatusPassAdd,
//			RawArgs: gotacacs.ArgsFromMap(map[string]string{"priv-lvl": "15"}),
//		}
//	}
//
//	func (h *myHandler) HandleAcctRequest(_ context.Context, req *gotacacs.AcctRequestContext) *gotacacs.AcctReply {
//		return &gotacacs.AcctReply{Status: gotacacs.AcctStatusSuccess}
//	}
//
// # Per-Client Secret Provider
//
// Use SecretProviderFunc to return different secrets and custom user data per client:
//
//	secretProvider := gotacacs.SecretProviderFunc(func(_ context.Context, req gotacacs.SecretRequest) gotacacs.SecretResponse {
//		return gotacacs.SecretResponse{
//			Secret: []byte("sharedsecret"),
//			UserData: map[string]string{
//				"client_ip": req.RemoteAddr.String(),
//				"local_ip":  req.LocalAddr.String(),
//			},
//		}
//	})
//
//	server := gotacacs.NewServer(
//		gotacacs.WithServerListener(ln),
//		gotacacs.WithSecretProvider(secretProvider),
//		gotacacs.WithHandler(&myHandler{}),
//	)
//
// The UserData map is available in all handler request contexts via req.UserData.
//
// # CHAP Authentication
//
// CHAP (RFC 8907 Section 5.4.2.3) is a single START / single REPLY exchange.
// The client supplies the PPP id and challenge; AuthenticateCHAP computes the
// MD5 response from the shared secret and sends it in the START data field. A
// FAIL status returns the reply with ErrAuthenticationFailed:
//
//	challenge := make([]byte, 16) // SHOULD be >= 8 octets and unpredictable
//	if _, err := rand.Read(challenge); err != nil {
//		log.Fatal(err)
//	}
//	reply, err := client.AuthenticateCHAP(ctx, "username", id, []byte("sharedsecret"), challenge)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// A server handler verifies a received CHAP START with VerifyCHAP, which
// recomputes the response from the shared secret and compares it in constant
// time:
//
//	func (h *myHandler) HandleAuthenStart(_ context.Context, req *gotacacs.AuthenRequest) *gotacacs.AuthenReply {
//		if req.Start.AuthenType == gotacacs.AuthenTypeCHAP {
//			ok, err := gotacacs.VerifyCHAP(h.secretFor(string(req.Start.User)), req.Start.Data)
//			if err != nil || !ok {
//				return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusFail}
//			}
//			return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusPass}
//		}
//		// ... other authen types
//	}
//
// The helpers CHAPResponse, BuildCHAPData, ParseCHAPData, and NewCHAPStart are
// exported for callers assembling the exchange manually. MS-CHAP and
// MS-CHAPv2 are not implemented.
//
// # TLS Support (RFC 9887)
//
// Both client and server support TLS 1.3. RFC 9887 requires mutual
// authentication. Configure client and server certificates and trusted CA
// pools; the shared obfuscation secret is not used on TLS connections:
//
//	// Client with TLS
//	tlsConfig := &tls.Config{
//		Certificates: []tls.Certificate{clientCert},
//		RootCAs:      serverCAs,
//		ServerName:   "tacacs.example.com",
//	}
//	client := gotacacs.NewClient(
//		gotacacs.WithAddress("tacacs.example.com:300"),
//		gotacacs.WithTLSConfig(tlsConfig),
//	)
//	defer client.Close()
//
//	// Server with TLS
//	ln, err := gotacacs.ListenTLS(":300", &tls.Config{
//		Certificates: []tls.Certificate{serverCert},
//		ClientCAs:    clientCAs,
//		ClientAuth:   tls.RequireAndVerifyClientCert,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//
// The certificate variables above are loaded with tls.LoadX509KeyPair; the CA
// pools contain the trusted issuers for each peer. Applications must also
// configure the peer identity and certificate revocation checks required by
// RFC 9887 through tls.Config, including VerifyConnection. Go's default
// certificate verifier does not check revocation.
//
// # Single-Connect Mode
//
// Enable single-connect mode to request connection reuse. The first reply
// determines whether the server accepted it; later flags do not renegotiate:
//
//	client := gotacacs.NewClient(
//		gotacacs.WithAddress("tacacs.example.com:49"),
//		gotacacs.WithSecret("sharedsecret"),
//		gotacacs.WithSingleConnect(true),
//	)
//	defer client.Close()
//
// Context cancellation interrupts in-flight client network I/O and closes the
// connection. ASCII prompt callbacks run synchronously and must handle their
// own input cancellation. Server read timeouts also bound TLS handshakes.
//
// # Caller-Supplied Connections
//
// Server.ServeConn handles an existing net.Conn without requiring a listener.
// It shares the Serve packet handling loop and participates in Shutdown.
// ReadRawPacket and WriteRawPacket provide bounded raw packet forwarding
// without applying obfuscation or TLS flag policy.
//
// For more information about the TACACS+ protocol, see RFC8907:
// https://datatracker.ietf.org/doc/html/rfc8907
package gotacacs
