package gotacacs

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
)

type invalidCountWriter struct{}

func (invalidCountWriter) Write(p []byte) (int, error) {
	return len(p) + 1, nil
}

func TestReadRawPacketRoundTrip(t *testing.T) {
	t.Run("round trip preserves raw bytes", func(t *testing.T) {
		header := &Header{
			Version:   0xc0,
			Type:      PacketTypeAuthen,
			SeqNo:     1,
			SessionID: 42,
			Length:    3,
		}
		headerBuf, err := header.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		body := []byte{0x01, 0x02, 0x03}

		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()

		go func() {
			_ = WriteRawPacket(serverConn, headerBuf, body)
			serverConn.Close()
		}()

		gotHeader, gotBody, err := ReadRawPacket(clientConn, DefaultMaxBodyLength)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(gotHeader, headerBuf) {
			t.Errorf("got %v, want %v", gotHeader, headerBuf)
		}
		if !bytes.Equal(gotBody, body) {
			t.Errorf("got %v, want %v", gotBody, body)
		}
	})

	t.Run("empty body", func(t *testing.T) {
		header := &Header{Version: 0xc0, Type: PacketTypeAcct, SeqNo: 1, SessionID: 7, Length: 0}
		headerBuf, err := header.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()

		go func() {
			_ = WriteRawPacket(serverConn, headerBuf, nil)
			serverConn.Close()
		}()

		gotHeader, gotBody, err := ReadRawPacket(clientConn, DefaultMaxBodyLength)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(gotHeader, headerBuf) {
			t.Errorf("got %v, want %v", gotHeader, headerBuf)
		}
		if len(gotBody) != 0 {
			t.Errorf("expected empty, got %v", gotBody)
		}
	})
}

func TestReadRawPacketRejects(t *testing.T) {
	t.Run("oversized body", func(t *testing.T) {
		header := &Header{Version: 0xc0, Type: PacketTypeAuthen, SeqNo: 1, SessionID: 1, Length: 100}
		headerBuf, err := header.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()

		go func() {
			_ = writeAllWriter(serverConn, headerBuf)
			serverConn.Close()
		}()

		_, _, err = ReadRawPacket(clientConn, 10)
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, ErrBodyTooLarge) {
			t.Errorf("error %v is not %v", err, ErrBodyTooLarge)
		}
	})

	t.Run("short header", func(t *testing.T) {
		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()

		go func() {
			_ = writeAllWriter(serverConn, []byte{0x01, 0x02, 0x03})
			serverConn.Close()
		}()

		_, _, err := ReadRawPacket(clientConn, DefaultMaxBodyLength)
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("error %v is not %v", err, io.ErrUnexpectedEOF)
		}
	})

	t.Run("invalid header", func(t *testing.T) {
		// Valid length header with an invalid version so Validate rejects it.
		headerBuf := make([]byte, HeaderLength)
		headerBuf[0] = 0x00 // invalid version
		headerBuf[1] = PacketTypeAuthen
		headerBuf[2] = 1

		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()

		go func() {
			_ = writeAllWriter(serverConn, headerBuf)
			serverConn.Close()
		}()

		_, _, err := ReadRawPacket(clientConn, DefaultMaxBodyLength)
		if err == nil {
			t.Fatal("expected an error")
		}
	})
}

func TestWriteRawPacketRejectsInvalidWriteCount(t *testing.T) {
	header := &Header{Version: 0xc0, Type: PacketTypeAcct, SeqNo: 1, SessionID: 1}
	headerBuf, err := header.MarshalBinary()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = WriteRawPacket(invalidCountWriter{}, headerBuf, nil)
	if !errors.Is(err, io.ErrShortWrite) {
		t.Errorf("error %v is not %v", err, io.ErrShortWrite)
	}
}

func TestWriteRawPacketRejectsInvalidFraming(t *testing.T) {
	t.Run("short header", func(t *testing.T) {
		var dst bytes.Buffer
		err := WriteRawPacket(&dst, []byte{1, 2, 3}, nil)
		if !errors.Is(err, ErrInvalidHeader) {
			t.Errorf("error %v is not %v", err, ErrInvalidHeader)
		}
		if len(dst.Bytes()) != 0 {
			t.Errorf("expected empty, got %v", dst.Bytes())
		}
	})

	t.Run("invalid header", func(t *testing.T) {
		header := make([]byte, HeaderLength)
		header[1] = PacketTypeAuthen
		header[2] = 1
		var dst bytes.Buffer
		err := WriteRawPacket(&dst, header, nil)
		if !errors.Is(err, ErrInvalidVersion) {
			t.Errorf("error %v is not %v", err, ErrInvalidVersion)
		}
		if len(dst.Bytes()) != 0 {
			t.Errorf("expected empty, got %v", dst.Bytes())
		}
	})

	t.Run("body length mismatch", func(t *testing.T) {
		header := &Header{Version: 0xc0, Type: PacketTypeAcct, SeqNo: 1, SessionID: 1, Length: 2}
		headerBuf, err := header.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var dst bytes.Buffer
		err = WriteRawPacket(&dst, headerBuf, []byte{1})
		if !errors.Is(err, ErrInvalidPacket) {
			t.Errorf("error %v is not %v", err, ErrInvalidPacket)
		}
		if len(dst.Bytes()) != 0 {
			t.Errorf("expected empty, got %v", dst.Bytes())
		}
	})
}

func TestServeConnNilConnection(t *testing.T) {
	t.Run("nil interface", func(t *testing.T) {
		err := NewServer().ServeConn(nil)
		if err == nil {
			t.Fatal("expected an error")
		}
		if errors.Is(err, net.ErrClosed) {
			t.Errorf("expected false")
		}
	})

	t.Run("typed nil", func(t *testing.T) {
		var conn *net.TCPConn
		err := NewServer().ServeConn(conn)
		if err == nil {
			t.Fatal("expected an error")
		}
		if errors.Is(err, net.ErrClosed) {
			t.Errorf("expected false")
		}
	})
}
