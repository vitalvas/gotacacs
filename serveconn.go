package gotacacs

import (
	"fmt"
	"io"
)

// ReadRawPacket reads a single TACACS+ packet from r without deobfuscation.
// It reads the 12-byte header, validates it, then reads header.Length body
// bytes, returning both the raw header and raw body bytes exactly as received.
// A secret-less front-end can forward these bytes unchanged.
//
// The body length is rejected with ErrBodyTooLarge when it exceeds
// maxBodyLength. A short or malformed header returns the underlying read or
// validation error. No obfuscation or TLS unencrypted-flag policy is applied;
// those belong to the secret-aware paths.
func ReadRawPacket(r io.Reader, maxBodyLength uint32) (header, body []byte, err error) {
	headerBuf := make([]byte, HeaderLength)
	if _, err := io.ReadFull(r, headerBuf); err != nil {
		return nil, nil, err
	}

	h := &Header{}
	if err := h.UnmarshalBinary(headerBuf); err != nil {
		return nil, nil, err
	}

	if err := h.Validate(); err != nil {
		return nil, nil, err
	}

	if h.Length > maxBodyLength {
		return nil, nil, fmt.Errorf("%w: body length %d exceeds maximum %d", ErrBodyTooLarge, h.Length, maxBodyLength)
	}

	if h.Length > 0 {
		body = make([]byte, h.Length)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, nil, err
		}
	}

	return headerBuf, body, nil
}

// WriteRawPacket writes a TACACS+ packet's raw header and body bytes to w
// without obfuscation. It validates the header and verifies that its declared
// body length matches body before writing anything. It then writes the header
// fully followed by the body, handling partial writes. A secret-less front-end
// uses it to send relayed reply bytes unchanged.
func WriteRawPacket(w io.Writer, header, body []byte) error {
	if len(header) != HeaderLength {
		return fmt.Errorf("%w: header length %d, expected %d", ErrInvalidHeader, len(header), HeaderLength)
	}

	h := &Header{}
	if err := h.UnmarshalBinary(header); err != nil {
		return err
	}
	if err := h.Validate(); err != nil {
		return err
	}
	if uint64(h.Length) != uint64(len(body)) {
		return fmt.Errorf("%w: header body length %d does not match body length %d", ErrInvalidPacket, h.Length, len(body))
	}

	if err := writeAllWriter(w, header); err != nil {
		return err
	}
	if len(body) > 0 {
		if err := writeAllWriter(w, body); err != nil {
			return err
		}
	}
	return nil
}

// writeAllWriter writes all of data to w, handling partial writes. It mirrors
// writeAll but targets the io.Writer interface used by WriteRawPacket.
func writeAllWriter(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n < 0 || n > len(data) {
			return io.ErrShortWrite
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
