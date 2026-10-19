package gotacacs

import "fmt"

// ValidateText reports whether b is a valid TACACS+ text field per RFC 8907
// Section 3.7: a printable byte array of US-ASCII (RFC 20) that excludes the
// control characters of RFC 20 Section 5.2. Space (0x20) is printable and
// allowed; control characters (0x00-0x1F, 0x7F) and non-ASCII bytes (>= 0x80)
// are rejected. An empty field is valid. It returns ErrInvalidText otherwise.
func ValidateText(b []byte) error {
	for i, c := range b {
		if c < 0x20 || c >= 0x7f {
			return fmt.Errorf("%w: byte 0x%02x at offset %d is not printable US-ASCII", ErrInvalidText, c, i)
		}
	}
	return nil
}

// ValidateUsername reports whether b is a valid TACACS+ username per RFC 8907
// Section 3.7, which requires the RFC 8265 UsernameCasePreserved profile.
//
// Full RFC 8265 handling of non-ASCII code points (width mapping, NFC
// normalization, the bidi rule, and the IdentifierClass Unicode categories)
// requires Unicode tables this zero-dependency library does not carry. For the
// ASCII range the profile is exact: the PRECIS IdentifierClass allows printable
// non-space ASCII (U+0021-U+007E), the string must be non-empty, and ASCII needs
// no case mapping or normalization. ValidateUsername enforces that range and
// rejects any byte >= 0x80, so a non-ASCII username is refused rather than
// passed through unvalidated. A caller that must accept non-ASCII usernames
// should apply a PRECIS implementation before handing the username to the
// library. It returns ErrInvalidUsername on any violation.
func ValidateUsername(b []byte) error {
	if len(b) == 0 {
		return fmt.Errorf("%w: username is empty", ErrInvalidUsername)
	}
	for i, c := range b {
		switch {
		case c >= 0x80:
			return fmt.Errorf("%w: byte 0x%02x at offset %d is non-ASCII and cannot be validated without PRECIS tables", ErrInvalidUsername, c, i)
		case c <= 0x20 || c == 0x7f:
			return fmt.Errorf("%w: byte 0x%02x at offset %d is not a printable non-space ASCII character", ErrInvalidUsername, c, i)
		}
	}
	return nil
}
