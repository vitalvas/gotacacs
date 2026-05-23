package gotacacs

import (
	"encoding"
	"fmt"
	"sort"
	"strings"
)

// Packet is the interface that all TACACS+ packet types implement.
type Packet interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

// ParseAuthenPacket parses an authentication packet body based on the sequence number.
// Odd sequence numbers indicate client packets (START, CONTINUE).
// Even sequence numbers indicate server packets (REPLY).
func ParseAuthenPacket(seqNo uint8, data []byte) (Packet, error) {
	if seqNo == 0 {
		return nil, fmt.Errorf("%w: sequence number cannot be 0", ErrInvalidSequence)
	}

	if seqNo == 1 {
		// First packet is always START
		p := &AuthenStart{}
		if err := p.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return p, nil
	}

	if seqNo%2 == 0 {
		// Even sequence numbers are server replies
		p := &AuthenReply{}
		if err := p.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return p, nil
	}

	// Odd sequence numbers > 1 are client continues
	p := &AuthenContinue{}
	if err := p.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return p, nil
}

// ParseAuthorPacket parses an authorization packet body based on the sequence number.
// Sequence number 1 indicates a REQUEST.
// Sequence number 2 indicates a RESPONSE.
func ParseAuthorPacket(seqNo uint8, data []byte) (Packet, error) {
	if seqNo == 0 {
		return nil, fmt.Errorf("%w: sequence number cannot be 0", ErrInvalidSequence)
	}

	if seqNo == 1 {
		// Request from client
		p := &AuthorRequest{}
		if err := p.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return p, nil
	}

	if seqNo == 2 {
		// Response from server
		p := &AuthorResponse{}
		if err := p.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return p, nil
	}

	return nil, fmt.Errorf("%w: authorization only supports sequence 1 (request) or 2 (response)", ErrInvalidSequence)
}

// ParseAcctPacket parses an accounting packet body based on the sequence number.
// Sequence number 1 indicates a REQUEST.
// Sequence number 2 indicates a REPLY.
func ParseAcctPacket(seqNo uint8, data []byte) (Packet, error) {
	if seqNo == 0 {
		return nil, fmt.Errorf("%w: sequence number cannot be 0", ErrInvalidSequence)
	}

	if seqNo == 1 {
		// Request from client
		p := &AcctRequest{}
		if err := p.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return p, nil
	}

	if seqNo == 2 {
		// Reply from server
		p := &AcctReply{}
		if err := p.UnmarshalBinary(data); err != nil {
			return nil, err
		}
		return p, nil
	}

	return nil, fmt.Errorf("%w: accounting only supports sequence 1 (request) or 2 (reply)", ErrInvalidSequence)
}

// ParsePacket parses a packet body based on the header information.
// It determines the packet type from the header and delegates to the appropriate parser.
func ParsePacket(header *Header, data []byte) (Packet, error) {
	if header == nil {
		return nil, fmt.Errorf("%w: header is nil", ErrInvalidHeader)
	}

	switch header.Type {
	case PacketTypeAuthen:
		return ParseAuthenPacket(header.SeqNo, data)
	case PacketTypeAuthor:
		return ParseAuthorPacket(header.SeqNo, data)
	case PacketTypeAcct:
		return ParseAcctPacket(header.SeqNo, data)
	default:
		return nil, fmt.Errorf("%w: %d", ErrInvalidType, header.Type)
	}
}

// PacketType returns the packet type constant for a given packet.
func PacketType(p Packet) uint8 {
	switch p.(type) {
	case *AuthenStart, *AuthenReply, *AuthenContinue:
		return PacketTypeAuthen
	case *AuthorRequest, *AuthorResponse:
		return PacketTypeAuthor
	case *AcctRequest, *AcctReply:
		return PacketTypeAcct
	default:
		return 0
	}
}

// IsClientPacket returns true if the packet is sent by the client.
func IsClientPacket(p Packet) bool {
	switch p.(type) {
	case *AuthenStart, *AuthenContinue:
		return true
	case *AuthorRequest:
		return true
	case *AcctRequest:
		return true
	default:
		return false
	}
}

// IsServerPacket returns true if the packet is sent by the server.
func IsServerPacket(p Packet) bool {
	switch p.(type) {
	case *AuthenReply:
		return true
	case *AuthorResponse:
		return true
	case *AcctReply:
		return true
	default:
		return false
	}
}

// isBadSecretError checks if a buffer size mismatch indicates bad secret.
// When a packet is deobfuscated with the wrong secret, the length fields
// become garbage, resulting in unreasonably large expected lengths.
// If expected length is more than double the actual + 16 bytes overhead,
// the length fields are likely corrupted from wrong secret deobfuscation.
// This is a best-effort heuristic; false positives are possible for very
// small packets where legitimate field values exceed the threshold.
func isBadSecretError(actualLen, expectedLen int) bool {
	return expectedLen > actualLen*2+16
}

// ArgValues maps TACACS+ argument keys to values.
// It is similar to net/url.Values, but Output returns TACACS+ "key=value"
// byte arguments without URL escaping.
type ArgValues map[string][]string

// Get returns the first value associated with key.
// It returns an empty string when key has no values.
func (v ArgValues) Get(key string) string {
	if vs := v[key]; len(vs) > 0 {
		return vs[0]
	}
	return ""
}

// Set sets key to a single value.
func (v ArgValues) Set(key, value string) {
	v[key] = []string{value}
}

// Add appends value to key.
func (v ArgValues) Add(key, value string) {
	v[key] = append(v[key], value)
}

// Del deletes key and all associated values.
func (v ArgValues) Del(key string) {
	delete(v, key)
}

// Has reports whether key is present.
func (v ArgValues) Has(key string) bool {
	_, ok := v[key]
	return ok
}

// Strings converts key-value pairs to TACACS+ argument format ("key=value").
// Keys are sorted for deterministic output. Keys with no values are omitted.
func (v ArgValues) Strings() []string {
	if len(v) == 0 {
		return nil
	}

	keys := make([]string, 0, len(v))
	argCount := 0
	for key, values := range v {
		if len(values) == 0 {
			continue
		}
		keys = append(keys, key)
		argCount += len(values)
	}
	if argCount == 0 {
		return nil
	}
	sort.Strings(keys)

	args := make([]string, 0, argCount)
	for _, key := range keys {
		for _, value := range v[key] {
			args = append(args, fmt.Sprintf("%s=%s", key, value))
		}
	}
	return args
}

// Output converts key-value pairs to TACACS+ raw byte arguments.
func (v ArgValues) Output() [][]byte {
	stringArgs := v.Strings()
	if len(stringArgs) == 0 {
		return nil
	}

	args := make([][]byte, 0, len(stringArgs))
	for _, arg := range stringArgs {
		args = append(args, []byte(arg))
	}
	return args
}

// ArgValuesFromArgs parses TACACS+ "key=value" arguments into ArgValues.
// Arguments without "=" are ignored.
func ArgValuesFromArgs(args []string) ArgValues {
	var values ArgValues
	for _, arg := range args {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			continue
		}
		if values == nil {
			values = make(ArgValues)
		}
		values.Add(key, value)
	}
	return values
}

// ArgValuesFromRawArgs parses TACACS+ raw byte arguments into ArgValues.
// Arguments without "=" are ignored.
func ArgValuesFromRawArgs(rawArgs [][]byte) ArgValues {
	var values ArgValues
	for _, arg := range rawArgs {
		key, value, ok := strings.Cut(string(arg), "=")
		if !ok {
			continue
		}
		if values == nil {
			values = make(ArgValues)
		}
		values.Add(key, value)
	}
	return values
}

// ArgsFromMap converts key-value pairs to TACACS+ argument format ("key=value").
func ArgsFromMap(m map[string]string) [][]byte {
	if len(m) == 0 {
		return nil
	}
	values := make(ArgValues, len(m))
	for k, v := range m {
		values.Set(k, v)
	}
	return values.Output()
}
