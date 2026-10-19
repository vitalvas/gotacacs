package gotacacs

import (
	"crypto/md5"
	"crypto/subtle"
	"fmt"
)

// CHAPResponseLength is the length in octets of a CHAP response value when the
// MD5 algorithm is used, which RFC 8907 Section 5.4.2.3 mandates for TACACS+.
const CHAPResponseLength = md5.Size

// CHAPResponse computes the PPP CHAP response value for the given id, shared
// secret, and challenge, as defined in RFC 1994 Section 4.1: the MD5 hash of
// the identifier octet followed by the secret followed by the challenge. The
// result is always CHAPResponseLength (16) octets.
func CHAPResponse(id byte, secret, challenge []byte) []byte {
	h := md5.New()
	h.Write([]byte{id})
	h.Write(secret)
	h.Write(challenge)
	return h.Sum(nil)
}

// BuildCHAPData assembles the authentication START data field for a CHAP login
// (RFC 8907 Section 5.4.2.3): the PPP id octet, the challenge, and the MD5
// response concatenated in that order. Clients place the result in
// AuthenStart.Data; see NewCHAPStart for the full START packet.
func BuildCHAPData(id byte, secret, challenge []byte) []byte {
	data := make([]byte, 0, 1+len(challenge)+CHAPResponseLength)
	data = append(data, id)
	data = append(data, challenge...)
	data = append(data, CHAPResponse(id, secret, challenge)...)
	return data
}

// ParseCHAPData splits a CHAP login data field into its id, challenge, and
// response components. Per RFC 8907 Section 5.4.2.3 the id is the first octet,
// the response is the final CHAPResponseLength (16) octets, and the challenge
// is everything in between. It returns ErrInvalidPacket when the field is too
// short to contain an id and a response.
func ParseCHAPData(data []byte) (id byte, challenge, response []byte, err error) {
	if len(data) < 1+CHAPResponseLength {
		return 0, nil, nil, fmt.Errorf("%w: CHAP data field needs at least %d bytes, got %d", ErrInvalidPacket, 1+CHAPResponseLength, len(data))
	}
	id = data[0]
	challenge = data[1 : len(data)-CHAPResponseLength]
	response = data[len(data)-CHAPResponseLength:]
	return id, challenge, response, nil
}

// VerifyCHAP reports whether the CHAP response in a login data field matches
// the one computed from the shared secret. It parses data with ParseCHAPData,
// recomputes the expected response with CHAPResponse, and compares the two in
// constant time. A parse failure returns ErrInvalidPacket; a byte mismatch
// returns (false, nil). Servers call this from a CHAP authentication handler.
func VerifyCHAP(secret, data []byte) (bool, error) {
	id, challenge, response, err := ParseCHAPData(data)
	if err != nil {
		return false, err
	}
	expected := CHAPResponse(id, secret, challenge)
	return subtle.ConstantTimeCompare(response, expected) == 1, nil
}

// NewCHAPStart builds an authentication START packet for a CHAP login
// (RFC 8907 Section 5.4.2.3): action LOGIN, authen_type CHAP, the username in
// the user field, and the id, challenge, and MD5 response in the data field.
// The caller sets the packet on the wire with minor_version 1 (NewCHAPStart
// leaves version to the header, which the client sets for CHAP).
func NewCHAPStart(user string, id byte, secret, challenge []byte) *AuthenStart {
	return &AuthenStart{
		Action:     AuthenActionLogin,
		PrivLevel:  1,
		AuthenType: AuthenTypeCHAP,
		Service:    AuthenServiceLogin,
		User:       []byte(user),
		Data:       BuildCHAPData(id, secret, challenge),
	}
}
