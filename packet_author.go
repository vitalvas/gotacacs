package gotacacs

import (
	"fmt"
)

// AuthorRequest represents a TACACS+ authorization REQUEST packet as defined in RFC8907 Section 6.1.
// This packet is sent by the client to request authorization for a specific action.
type AuthorRequest struct {
	AuthenMethod uint8    // Authentication method used
	PrivLevel    uint8    // Privilege level
	AuthenType   uint8    // Authentication type
	Service      uint8    // Authentication service
	User         []byte   // Username
	Port         []byte   // Port identifier
	RemoteAddr   []byte   // Remote address
	Args         [][]byte // Authorization arguments
}

// NewAuthorRequest creates a new AuthorRequest packet with the specified parameters.
func NewAuthorRequest(authenMethod, authenType, service uint8, user string) *AuthorRequest {
	return &AuthorRequest{
		AuthenMethod: authenMethod,
		PrivLevel:    1, // Default privilege level
		AuthenType:   authenType,
		Service:      service,
		User:         []byte(user),
	}
}

// AddArg adds an argument to the authorization request.
func (p *AuthorRequest) AddArg(arg string) {
	p.Args = append(p.Args, []byte(arg))
}

// GetArgs returns the arguments as strings.
func (p *AuthorRequest) GetArgs() []string {
	result := make([]string, len(p.Args))
	for i, arg := range p.Args {
		result[i] = string(arg)
	}
	return result
}

// MarshalBinary encodes the AuthorRequest packet to binary format.
func (p *AuthorRequest) MarshalBinary() ([]byte, error) {
	userLen := len(p.User)
	portLen := len(p.Port)
	remAddrLen := len(p.RemoteAddr)
	argCount := len(p.Args)

	if userLen > 255 || portLen > 255 || remAddrLen > 255 {
		return nil, fmt.Errorf("%w: field length exceeds 255 bytes", ErrInvalidPacket)
	}
	if argCount > 255 {
		return nil, fmt.Errorf("%w: argument count exceeds 255", ErrInvalidPacket)
	}

	// Calculate total args length and validate individual arg lengths
	totalArgsLen := 0
	for _, arg := range p.Args {
		if len(arg) > 255 {
			return nil, fmt.Errorf("%w: argument length exceeds 255 bytes", ErrInvalidPacket)
		}
		totalArgsLen += len(arg)
	}

	// Fixed header (8 bytes) + arg lengths (arg_count bytes) + variable fields
	size := 8 + argCount + userLen + portLen + remAddrLen + totalArgsLen
	buf := make([]byte, size)

	buf[0] = p.AuthenMethod
	buf[1] = p.PrivLevel
	buf[2] = p.AuthenType
	buf[3] = p.Service
	buf[4] = uint8(userLen)
	buf[5] = uint8(portLen)
	buf[6] = uint8(remAddrLen)
	buf[7] = uint8(argCount)

	offset := 8

	// Write argument lengths
	for _, arg := range p.Args {
		buf[offset] = uint8(len(arg))
		offset++
	}

	// Write variable fields
	copy(buf[offset:], p.User)
	offset += userLen
	copy(buf[offset:], p.Port)
	offset += portLen
	copy(buf[offset:], p.RemoteAddr)
	offset += remAddrLen

	// Write arguments
	for _, arg := range p.Args {
		copy(buf[offset:], arg)
		offset += len(arg)
	}

	return buf, nil
}

// UnmarshalBinary decodes the AuthorRequest packet from binary format.
func (p *AuthorRequest) UnmarshalBinary(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("%w: need at least 8 bytes, got %d", ErrBufferTooShort, len(data))
	}

	p.AuthenMethod = data[0]
	p.PrivLevel = data[1]
	p.AuthenType = data[2]
	p.Service = data[3]

	userLen := int(data[4])
	portLen := int(data[5])
	remAddrLen := int(data[6])
	argCount := int(data[7])

	// Calculate expected length
	minLen := 8 + argCount + userLen + portLen + remAddrLen
	if len(data) < minLen {
		return fmt.Errorf("%w: need at least %d bytes for header and lengths, got %d", ErrBufferTooShort, minLen, len(data))
	}

	offset := 8

	// Read argument lengths
	argLens := make([]int, argCount)
	totalArgsLen := 0
	for i := range argCount {
		argLens[i] = int(data[offset])
		totalArgsLen += argLens[i]
		offset++
	}

	// Verify we have enough data for all fields
	expectedLen := offset + userLen + portLen + remAddrLen + totalArgsLen
	if len(data) < expectedLen {
		return fmt.Errorf("%w: need %d bytes, got %d", ErrBufferTooShort, expectedLen, len(data))
	}

	// Read variable fields
	if userLen > 0 {
		p.User = make([]byte, userLen)
		copy(p.User, data[offset:offset+userLen])
	}
	offset += userLen

	if portLen > 0 {
		p.Port = make([]byte, portLen)
		copy(p.Port, data[offset:offset+portLen])
	}
	offset += portLen

	if remAddrLen > 0 {
		p.RemoteAddr = make([]byte, remAddrLen)
		copy(p.RemoteAddr, data[offset:offset+remAddrLen])
	}
	offset += remAddrLen

	// Read arguments
	if argCount > 0 {
		p.Args = make([][]byte, argCount)
		for i, argLen := range argLens {
			if argLen > 0 {
				p.Args[i] = make([]byte, argLen)
				copy(p.Args[i], data[offset:offset+argLen])
			}
			offset += argLen
		}
	}

	return nil
}

// AuthorResponse represents a TACACS+ authorization RESPONSE packet as defined in RFC8907 Section 6.2.
// This packet is sent by the server in response to an authorization request.
type AuthorResponse struct {
	Status    uint8    // Authorization status
	Args      [][]byte // Authorization arguments (may be modified from request)
	ServerMsg []byte   // Server message (optional)
	Data      []byte   // Additional data (optional)
}

// NewAuthorResponse creates a new AuthorResponse packet with the specified status.
func NewAuthorResponse(status uint8) *AuthorResponse {
	return &AuthorResponse{
		Status: status,
	}
}

// AddArg adds an argument to the authorization response.
func (p *AuthorResponse) AddArg(arg string) {
	p.Args = append(p.Args, []byte(arg))
}

// GetArgs returns the arguments as strings.
func (p *AuthorResponse) GetArgs() []string {
	result := make([]string, len(p.Args))
	for i, arg := range p.Args {
		result[i] = string(arg)
	}
	return result
}

// MarshalBinary encodes the AuthorResponse packet to binary format.
func (p *AuthorResponse) MarshalBinary() ([]byte, error) {
	serverMsgLen := len(p.ServerMsg)
	dataLen := len(p.Data)
	argCount := len(p.Args)

	if serverMsgLen > 65535 || dataLen > 65535 {
		return nil, fmt.Errorf("%w: field length exceeds 65535 bytes", ErrInvalidPacket)
	}
	if argCount > 255 {
		return nil, fmt.Errorf("%w: argument count exceeds 255", ErrInvalidPacket)
	}

	// Calculate total args length and validate individual arg lengths
	totalArgsLen := 0
	for _, arg := range p.Args {
		if len(arg) > 255 {
			return nil, fmt.Errorf("%w: argument length exceeds 255 bytes", ErrInvalidPacket)
		}
		totalArgsLen += len(arg)
	}

	// Fixed header (6 bytes) + arg lengths (arg_count bytes) + variable fields
	size := 6 + argCount + serverMsgLen + dataLen + totalArgsLen
	buf := make([]byte, size)

	buf[0] = p.Status
	buf[1] = uint8(argCount)
	buf[2] = uint8(serverMsgLen >> 8)
	buf[3] = uint8(serverMsgLen)
	buf[4] = uint8(dataLen >> 8)
	buf[5] = uint8(dataLen)

	offset := 6

	// Write argument lengths
	for _, arg := range p.Args {
		buf[offset] = uint8(len(arg))
		offset++
	}

	// Write variable fields
	copy(buf[offset:], p.ServerMsg)
	offset += serverMsgLen
	copy(buf[offset:], p.Data)
	offset += dataLen

	// Write arguments
	for _, arg := range p.Args {
		copy(buf[offset:], arg)
		offset += len(arg)
	}

	return buf, nil
}

// UnmarshalBinary decodes the AuthorResponse packet from binary format.
func (p *AuthorResponse) UnmarshalBinary(data []byte) error {
	if len(data) < 6 {
		return fmt.Errorf("%w: need at least 6 bytes, got %d", ErrBufferTooShort, len(data))
	}

	p.Status = data[0]
	argCount := int(data[1])
	serverMsgLen := int(data[2])<<8 | int(data[3])
	dataLen := int(data[4])<<8 | int(data[5])

	// Calculate minimum length needed
	minLen := 6 + argCount
	if len(data) < minLen {
		return fmt.Errorf("%w: need at least %d bytes for header and arg lengths, got %d", ErrBufferTooShort, minLen, len(data))
	}

	offset := 6

	// Read argument lengths
	argLens := make([]int, argCount)
	totalArgsLen := 0
	for i := range argCount {
		argLens[i] = int(data[offset])
		totalArgsLen += argLens[i]
		offset++
	}

	// Verify we have enough data for all fields
	expectedLen := offset + serverMsgLen + dataLen + totalArgsLen
	if len(data) < expectedLen {
		return fmt.Errorf("%w: need %d bytes, got %d", ErrBufferTooShort, expectedLen, len(data))
	}

	// Read variable fields
	if serverMsgLen > 0 {
		p.ServerMsg = make([]byte, serverMsgLen)
		copy(p.ServerMsg, data[offset:offset+serverMsgLen])
	}
	offset += serverMsgLen

	if dataLen > 0 {
		p.Data = make([]byte, dataLen)
		copy(p.Data, data[offset:offset+dataLen])
	}
	offset += dataLen

	// Read arguments
	if argCount > 0 {
		p.Args = make([][]byte, argCount)
		for i, argLen := range argLens {
			if argLen > 0 {
				p.Args[i] = make([]byte, argLen)
				copy(p.Args[i], data[offset:offset+argLen])
			}
			offset += argLen
		}
	}

	return nil
}

// IsPass returns true if the authorization passed (either PASS_ADD or PASS_REPL).
func (p *AuthorResponse) IsPass() bool {
	return p.Status == AuthorStatusPassAdd || p.Status == AuthorStatusPassRepl
}

// IsPassAdd returns true if the status is PASS_ADD.
func (p *AuthorResponse) IsPassAdd() bool {
	return p.Status == AuthorStatusPassAdd
}

// IsPassRepl returns true if the status is PASS_REPL.
func (p *AuthorResponse) IsPassRepl() bool {
	return p.Status == AuthorStatusPassRepl
}

// IsFail returns true if the authorization failed.
func (p *AuthorResponse) IsFail() bool {
	return p.Status == AuthorStatusFail
}

// IsError returns true if an error occurred.
func (p *AuthorResponse) IsError() bool {
	return p.Status == AuthorStatusError
}
