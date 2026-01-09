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
//	client := gotacacs.NewClient("tacacs.example.com:49",
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
//	acctReply, err := client.AccountingStart(ctx, "username", []string{"task_id=123"})
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
//	func (h *myHandler) HandleAuthenStart(ctx context.Context, req *gotacacs.AuthenRequest) *gotacacs.AuthenReply {
//		if string(req.Start.User) == "admin" && string(req.Start.Data) == "password" {
//			return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusPass}
//		}
//		return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusFail}
//	}
//
//	func (h *myHandler) HandleAuthenContinue(ctx context.Context, req *gotacacs.AuthenContinueRequest) *gotacacs.AuthenReply {
//		return &gotacacs.AuthenReply{Status: gotacacs.AuthenStatusPass}
//	}
//
//	func (h *myHandler) HandleAuthorRequest(ctx context.Context, req *gotacacs.AuthorRequestContext) *gotacacs.AuthorResponse {
//		return &gotacacs.AuthorResponse{
//			Status: gotacacs.AuthorStatusPassAdd,
//			Args:   [][]byte{[]byte("priv-lvl=15")},
//		}
//	}
//
//	func (h *myHandler) HandleAcctRequest(ctx context.Context, req *gotacacs.AcctRequestContext) *gotacacs.AcctReply {
//		return &gotacacs.AcctReply{Status: gotacacs.AcctStatusSuccess}
//	}
//
// # TLS Support
//
// Both client and server support TLS for secure communication:
//
//	// Client with TLS
//	tlsConfig := &tls.Config{
//		RootCAs: certPool,
//	}
//	client := gotacacs.NewClient("tacacs.example.com:49",
//		gotacacs.WithSecret("sharedsecret"),
//		gotacacs.WithTLSConfig(tlsConfig),
//	)
//
//	// Server with TLS
//	tlsConfig, err := gotacacs.NewTLSConfig("cert.pem", "key.pem")
//	if err != nil {
//		log.Fatal(err)
//	}
//	ln, err := gotacacs.ListenTLS(":49", tlsConfig)
//
// # Single-Connect Mode
//
// Enable single-connect mode to reuse connections for multiple requests:
//
//	client := gotacacs.NewClient("tacacs.example.com:49",
//		gotacacs.WithSecret("sharedsecret"),
//		gotacacs.WithSingleConnect(true),
//	)
//	defer client.Close()
//
// For more information about the TACACS+ protocol, see RFC8907:
// https://datatracker.ietf.org/doc/html/rfc8907
package gotacacs
