package gotacacs

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		require.NoError(t, err)
		body := []byte{0x01, 0x02, 0x03}

		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()

		go func() {
			_ = WriteRawPacket(serverConn, headerBuf, body)
			serverConn.Close()
		}()

		gotHeader, gotBody, err := ReadRawPacket(clientConn, DefaultMaxBodyLength)
		require.NoError(t, err)
		assert.Equal(t, headerBuf, gotHeader)
		assert.Equal(t, body, gotBody)
	})

	t.Run("empty body", func(t *testing.T) {
		header := &Header{Version: 0xc0, Type: PacketTypeAcct, SeqNo: 1, SessionID: 7, Length: 0}
		headerBuf, err := header.MarshalBinary()
		require.NoError(t, err)

		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()

		go func() {
			_ = WriteRawPacket(serverConn, headerBuf, nil)
			serverConn.Close()
		}()

		gotHeader, gotBody, err := ReadRawPacket(clientConn, DefaultMaxBodyLength)
		require.NoError(t, err)
		assert.Equal(t, headerBuf, gotHeader)
		assert.Empty(t, gotBody)
	})
}

func TestReadRawPacketRejects(t *testing.T) {
	t.Run("oversized body", func(t *testing.T) {
		header := &Header{Version: 0xc0, Type: PacketTypeAuthen, SeqNo: 1, SessionID: 1, Length: 100}
		headerBuf, err := header.MarshalBinary()
		require.NoError(t, err)

		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()

		go func() {
			_ = writeAllWriter(serverConn, headerBuf)
			serverConn.Close()
		}()

		_, _, err = ReadRawPacket(clientConn, 10)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBodyTooLarge)
	})

	t.Run("short header", func(t *testing.T) {
		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()

		go func() {
			_ = writeAllWriter(serverConn, []byte{0x01, 0x02, 0x03})
			serverConn.Close()
		}()

		_, _, err := ReadRawPacket(clientConn, DefaultMaxBodyLength)
		require.Error(t, err)
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
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
		require.Error(t, err)
	})
}

func TestWriteRawPacketRejectsInvalidWriteCount(t *testing.T) {
	header := &Header{Version: 0xc0, Type: PacketTypeAcct, SeqNo: 1, SessionID: 1}
	headerBuf, err := header.MarshalBinary()
	require.NoError(t, err)

	err = WriteRawPacket(invalidCountWriter{}, headerBuf, nil)
	assert.ErrorIs(t, err, io.ErrShortWrite)
}

func TestWriteRawPacketRejectsInvalidFraming(t *testing.T) {
	t.Run("short header", func(t *testing.T) {
		var dst bytes.Buffer
		err := WriteRawPacket(&dst, []byte{1, 2, 3}, nil)
		assert.ErrorIs(t, err, ErrInvalidHeader)
		assert.Empty(t, dst.Bytes())
	})

	t.Run("invalid header", func(t *testing.T) {
		header := make([]byte, HeaderLength)
		header[1] = PacketTypeAuthen
		header[2] = 1
		var dst bytes.Buffer
		err := WriteRawPacket(&dst, header, nil)
		assert.ErrorIs(t, err, ErrInvalidVersion)
		assert.Empty(t, dst.Bytes())
	})

	t.Run("body length mismatch", func(t *testing.T) {
		header := &Header{Version: 0xc0, Type: PacketTypeAcct, SeqNo: 1, SessionID: 1, Length: 2}
		headerBuf, err := header.MarshalBinary()
		require.NoError(t, err)
		var dst bytes.Buffer
		err = WriteRawPacket(&dst, headerBuf, []byte{1})
		assert.ErrorIs(t, err, ErrInvalidPacket)
		assert.Empty(t, dst.Bytes())
	})
}

func TestServeConnNilConnection(t *testing.T) {
	t.Run("nil interface", func(t *testing.T) {
		err := NewServer().ServeConn(nil)
		require.Error(t, err)
		assert.False(t, errors.Is(err, net.ErrClosed))
	})

	t.Run("typed nil", func(t *testing.T) {
		var conn *net.TCPConn
		err := NewServer().ServeConn(conn)
		require.Error(t, err)
		assert.False(t, errors.Is(err, net.ErrClosed))
	})
}
