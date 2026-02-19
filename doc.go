// Package gotacacs implements the TACACS+ protocol as defined in RFC8907.
// It provides both client and server SDK interfaces for Authentication,
// Authorization, and Accounting (AAA) services.
//
// TACACS+ is a security protocol that provides centralized access control
// for network devices. This package supports TCP and TLS transports with
// body obfuscation using MD5-based pseudo-pad generation.
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
//	acctReply, err := client.Accounting(ctx, gotacacs.AcctFlagStart, "username", []string{"task_id=123"})
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
// Implement the Handler interface to process requests:
//
//	type myHandler struct{}
//
//	func (h *myHandler) HandleAuthenStart(_ context.Context, req *gotacacs.AuthenRequest) *gotacacs.AuthenReply {
//		if string(req.Start.User) == "admin" && string(req.Start.Data) == "password" {
//			return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusPass}
//		}
//		return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusFail}
//	}
//
//	func (h *myHandler) HandleAuthenContinue(_ context.Context, _ *gotacacs.AuthenContinueRequest) *gotacacs.AuthenReply {
//		return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusPass}
//	}
//
//	func (h *myHandler) HandleAuthorRequest(_ context.Context, req *gotacacs.AuthorRequestContext) *gotacacs.AuthorResponse {
//		return &gotacacs.AuthorResponse{
//			Status: gotacacs.AuthorStatusPassAdd,
//			Args:   [][]byte{[]byte("priv-lvl=15")},
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
//	secretProvider := gotacacs.SecretProviderFunc(func(ctx context.Context, req gotacacs.SecretRequest) gotacacs.SecretResponse {
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
// # TLS Support (RFC 9887)
//
// Both client and server support TLS 1.3 for secure communication.
// When using TLS, the shared secret is not needed as TLS provides encryption:
//
//	// Client with TLS
//	tlsConfig := &tls.Config{
//		RootCAs: certPool,
//	}
//	client := gotacacs.NewClient(
//		gotacacs.WithAddress("tacacs.example.com:300"),
//		gotacacs.WithTLSConfig(tlsConfig),
//	)
//
//	// Server with TLS
//	ln, err := gotacacs.ListenTLS(":300", tlsConfig)
//
// # Single-Connect Mode
//
// Enable single-connect mode to reuse connections for multiple requests:
//
//	client := gotacacs.NewClient(
//		gotacacs.WithAddress("tacacs.example.com:49"),
//		gotacacs.WithSecret("sharedsecret"),
//		gotacacs.WithSingleConnect(true),
//	)
//	defer client.Close()
//
// For more information about the TACACS+ protocol, see RFC8907:
// https://datatracker.ietf.org/doc/html/rfc8907
package gotacacs
