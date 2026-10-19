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

// TypeOf returns the packet type constant for a given packet.
func TypeOf(p Packet) PacketType {
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

// Arg is a single TACACS+ argument-value pair (RFC 8907 Section 6.1).
// A mandatory argument uses the "=" separator; an optional one uses "*".
type Arg struct {
	Name     string
	Value    string
	Optional bool
}

// IsValidName reports whether the argument name is legal per RFC 8907
// Section 6.1: a non-empty name that contains neither separator ("=" or "*").
func (a Arg) IsValidName() bool {
	return a.Name != "" &&
		strings.IndexByte(a.Name, '=') < 0 &&
		strings.IndexByte(a.Name, '*') < 0
}

// String renders the argument in wire form, "name=value" or "name*value".
func (a Arg) String() string {
	sep := "="
	if a.Optional {
		sep = "*"
	}
	return fmt.Sprintf("%s%s%s", a.Name, sep, a.Value)
}

// ParseArg splits a TACACS+ argument on the first "=" or "*" separator,
// per RFC 8907 Section 6.1: the name ends at the first separator and the
// value is everything after it, so a value may itself contain separators.
// It returns ok=false when the argument contains no separator.
func ParseArg(arg string) (Arg, bool) {
	eq := strings.IndexByte(arg, '=')
	star := strings.IndexByte(arg, '*')
	switch {
	case eq < 0 && star < 0:
		return Arg{}, false
	case star < 0 || (eq >= 0 && eq < star):
		return Arg{Name: arg[:eq], Value: arg[eq+1:]}, true
	default:
		return Arg{Name: arg[:star], Value: arg[star+1:], Optional: true}, true
	}
}

// ParseArgs parses raw wire arguments into Arg pairs, preserving the
// mandatory/optional distinction. Arguments with no separator are skipped.
func ParseArgs(rawArgs [][]byte) []Arg {
	var args []Arg
	for _, raw := range rawArgs {
		if arg, ok := ParseArg(string(raw)); ok {
			args = append(args, arg)
		}
	}
	return args
}

// MarshalArgs renders Arg pairs to raw wire arguments, the inverse of
// ParseArgs. Unlike ArgValues.Output, it preserves each argument's separator
// (mandatory "=" versus optional "*"), order, and duplicates, so it is the
// conformant way to emit authorization and accounting arguments. Arguments
// whose name is empty or contains a separator are skipped: RFC 8907
// Section 6.1 forbids a separator in a name, and emitting one would reparse to
// a different name and value. It returns nil when nothing valid remains.
func MarshalArgs(args []Arg) [][]byte {
	var out [][]byte
	for _, arg := range args {
		if !arg.IsValidName() {
			continue
		}
		out = append(out, []byte(arg.String()))
	}
	return out
}

// ArgValues maps TACACS+ argument keys to values.
// It is similar to net/url.Values, but Output returns TACACS+ "key=value"
// byte arguments without URL escaping. ArgValues does not preserve the
// mandatory/optional separator; use ParseArgs when that distinction matters.
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

// ArgValuesFromArgs parses TACACS+ arguments into ArgValues, splitting each on
// the first "=" or "*" separator. Arguments without a separator are ignored.
func ArgValuesFromArgs(args []string) ArgValues {
	var values ArgValues
	for _, arg := range args {
		parsed, ok := ParseArg(arg)
		if !ok {
			continue
		}
		if values == nil {
			values = make(ArgValues)
		}
		values.Add(parsed.Name, parsed.Value)
	}
	return values
}

// ArgValuesFromRawArgs parses TACACS+ raw byte arguments into ArgValues,
// splitting each on the first "=" or "*" separator. Arguments without a
// separator are ignored.
func ArgValuesFromRawArgs(rawArgs [][]byte) ArgValues {
	var values ArgValues
	for _, arg := range rawArgs {
		parsed, ok := ParseArg(string(arg))
		if !ok {
			continue
		}
		if values == nil {
			values = make(ArgValues)
		}
		values.Add(parsed.Name, parsed.Value)
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
