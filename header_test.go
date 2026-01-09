package gotacacs

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHeader(t *testing.T) {
	t.Run("authentication header", func(t *testing.T) {
		h := NewHeader(PacketTypeAuthen, 0x12345678)
		assert.Equal(t, uint8(0xc0), h.Version)
		assert.Equal(t, uint8(PacketTypeAuthen), h.Type)
		assert.Equal(t, uint8(1), h.SeqNo)
		assert.Equal(t, uint8(0), h.Flags)
		assert.Equal(t, uint32(0x12345678), h.SessionID)
		assert.Equal(t, uint32(0), h.Length)
	})

	t.Run("authorization header", func(t *testing.T) {
		h := NewHeader(PacketTypeAuthor, 0xABCDEF00)
		assert.Equal(t, uint8(PacketTypeAuthor), h.Type)
		assert.Equal(t, uint32(0xABCDEF00), h.SessionID)
	})

	t.Run("accounting header", func(t *testing.T) {
		h := NewHeader(PacketTypeAcct, 0xFFFFFFFF)
		assert.Equal(t, uint8(PacketTypeAcct), h.Type)
		assert.Equal(t, uint32(0xFFFFFFFF), h.SessionID)
	})

	t.Run("zero session ID", func(t *testing.T) {
		h := NewHeader(PacketTypeAuthen, 0)
		assert.Equal(t, uint32(0), h.SessionID)
	})
}

func TestHeaderMarshalBinary(t *testing.T) {
	t.Run("basic encoding", func(t *testing.T) {
		h := &Header{
			Version:   0xc0,
			Type:      PacketTypeAuthen,
			SeqNo:     1,
			Flags:     0,
			SessionID: 0x12345678,
			Length:    0x00000100,
		}

		data, err := h.MarshalBinary()
		require.NoError(t, err)
		require.Len(t, data, HeaderLength)

		assert.Equal(t, uint8(0xc0), data[0])
		assert.Equal(t, uint8(0x01), data[1])
		assert.Equal(t, uint8(0x01), data[2])
		assert.Equal(t, uint8(0x00), data[3])
		assert.Equal(t, []byte{0x12, 0x34, 0x56, 0x78}, data[4:8])
		assert.Equal(t, []byte{0x00, 0x00, 0x01, 0x00}, data[8:12])
	})

	t.Run("with flags", func(t *testing.T) {
		h := &Header{
			Version:   0xc1,
			Type:      PacketTypeAuthor,
			SeqNo:     5,
			Flags:     FlagUnencrypted | FlagSingleConnect,
			SessionID: 0xDEADBEEF,
			Length:    0xCAFEBABE,
		}

		data, err := h.MarshalBinary()
		require.NoError(t, err)

		assert.Equal(t, uint8(0xc1), data[0])
		assert.Equal(t, uint8(0x02), data[1])
		assert.Equal(t, uint8(0x05), data[2])
		assert.Equal(t, uint8(0x05), data[3])
		assert.Equal(t, []byte{0xDE, 0xAD, 0xBE, 0xEF}, data[4:8])
		assert.Equal(t, []byte{0xCA, 0xFE, 0xBA, 0xBE}, data[8:12])
	})

	t.Run("max values", func(t *testing.T) {
		h := &Header{
			Version:   0xFF,
			Type:      0xFF,
			SeqNo:     0xFF,
			Flags:     0xFF,
			SessionID: 0xFFFFFFFF,
			Length:    0xFFFFFFFF,
		}

		data, err := h.MarshalBinary()
		require.NoError(t, err)

		for i := range HeaderLength {
			assert.Equal(t, uint8(0xFF), data[i])
		}
	})
}

func TestHeaderUnmarshalBinary(t *testing.T) {
	t.Run("basic decoding", func(t *testing.T) {
		data := []byte{0xc0, 0x01, 0x01, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x01, 0x00}

		h := &Header{}
		err := h.UnmarshalBinary(data)
		require.NoError(t, err)

		assert.Equal(t, uint8(0xc0), h.Version)
		assert.Equal(t, uint8(0x01), h.Type)
		assert.Equal(t, uint8(0x01), h.SeqNo)
		assert.Equal(t, uint8(0x00), h.Flags)
		assert.Equal(t, uint32(0x12345678), h.SessionID)
		assert.Equal(t, uint32(0x00000100), h.Length)
	})

	t.Run("buffer too short", func(t *testing.T) {
		testCases := []struct {
			name string
			data []byte
		}{
			{"empty", []byte{}},
			{"1 byte", []byte{0xc0}},
			{"11 bytes", []byte{0xc0, 0x01, 0x01, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x01}},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				h := &Header{}
				err := h.UnmarshalBinary(tc.data)
				assert.Error(t, err)
				assert.True(t, errors.Is(err, ErrBufferTooShort))
			})
		}
	})

	t.Run("extra data ignored", func(t *testing.T) {
		data := []byte{0xc0, 0x01, 0x01, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x01, 0x00, 0xFF, 0xFF}

		h := &Header{}
		err := h.UnmarshalBinary(data)
		require.NoError(t, err)

		assert.Equal(t, uint32(0x00000100), h.Length)
	})
}

func TestHeaderMarshalUnmarshalRoundtrip(t *testing.T) {
	testCases := []struct {
		name   string
		header *Header
	}{
		{
			name: "authen default",
			header: &Header{
				Version:   0xc0,
				Type:      PacketTypeAuthen,
				SeqNo:     1,
				Flags:     0,
				SessionID: 0x12345678,
				Length:    100,
			},
		},
		{
			name: "author with flags",
			header: &Header{
				Version:   0xc1,
				Type:      PacketTypeAuthor,
				SeqNo:     3,
				Flags:     FlagUnencrypted,
				SessionID: 0xDEADBEEF,
				Length:    256,
			},
		},
		{
			name: "acct single connect",
			header: &Header{
				Version:   0xc0,
				Type:      PacketTypeAcct,
				SeqNo:     255,
				Flags:     FlagSingleConnect,
				SessionID: 0x00000001,
				Length:    0xFFFFFFFF,
			},
		},
		{
			name: "all flags",
			header: &Header{
				Version:   0xc0,
				Type:      PacketTypeAuthen,
				SeqNo:     2,
				Flags:     FlagUnencrypted | FlagSingleConnect,
				SessionID: 0xCAFEBABE,
				Length:    1024,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := tc.header.MarshalBinary()
			require.NoError(t, err)

			decoded := &Header{}
			err = decoded.UnmarshalBinary(data)
			require.NoError(t, err)

			assert.Equal(t, tc.header.Version, decoded.Version)
			assert.Equal(t, tc.header.Type, decoded.Type)
			assert.Equal(t, tc.header.SeqNo, decoded.SeqNo)
			assert.Equal(t, tc.header.Flags, decoded.Flags)
			assert.Equal(t, tc.header.SessionID, decoded.SessionID)
			assert.Equal(t, tc.header.Length, decoded.Length)
		})
	}
}

func TestHeaderValidate(t *testing.T) {
	t.Run("valid headers", func(t *testing.T) {
		validHeaders := []*Header{
			{Version: 0xc0, Type: PacketTypeAuthen, SeqNo: 1},
			{Version: 0xc1, Type: PacketTypeAuthor, SeqNo: 1},
			{Version: 0xc0, Type: PacketTypeAcct, SeqNo: 255},
			{Version: 0xc1, Type: PacketTypeAuthen, SeqNo: 100},
		}

		for _, h := range validHeaders {
			err := h.Validate()
			assert.NoError(t, err)
		}
	})

	t.Run("invalid major version", func(t *testing.T) {
		invalidVersions := []uint8{0x00, 0x10, 0xb0, 0xd0, 0xf0}

		for _, v := range invalidVersions {
			h := &Header{Version: v, Type: PacketTypeAuthen, SeqNo: 1}
			err := h.Validate()
			assert.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidVersion))
		}
	})

	t.Run("invalid minor version", func(t *testing.T) {
		invalidMinorVersions := []uint8{0xc2, 0xc3, 0xc4, 0xcf}

		for _, v := range invalidMinorVersions {
			h := &Header{Version: v, Type: PacketTypeAuthen, SeqNo: 1}
			err := h.Validate()
			assert.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidVersion))
		}
	})

	t.Run("invalid packet type", func(t *testing.T) {
		invalidTypes := []uint8{0x00, 0x04, 0x05, 0xFF}

		for _, pt := range invalidTypes {
			h := &Header{Version: 0xc0, Type: pt, SeqNo: 1}
			err := h.Validate()
			assert.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidType))
		}
	})

	t.Run("invalid sequence number zero", func(t *testing.T) {
		h := &Header{Version: 0xc0, Type: PacketTypeAuthen, SeqNo: 0}
		err := h.Validate()
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidSequence))
	})
}

func TestHeaderVersionMethods(t *testing.T) {
	t.Run("major version number", func(t *testing.T) {
		testCases := []struct {
			version uint8
			major   uint8
		}{
			{0xc0, 0x0c},
			{0xc1, 0x0c},
			{0xcf, 0x0c},
			{0x00, 0x00},
			{0xff, 0x0f},
		}

		for _, tc := range testCases {
			h := &Header{Version: tc.version}
			assert.Equal(t, tc.major, h.MajorVersionNumber())
		}
	})

	t.Run("minor version number", func(t *testing.T) {
		testCases := []struct {
			version uint8
			minor   uint8
		}{
			{0xc0, 0x00},
			{0xc1, 0x01},
			{0xcf, 0x0f},
			{0x00, 0x00},
			{0xff, 0x0f},
		}

		for _, tc := range testCases {
			h := &Header{Version: tc.version}
			assert.Equal(t, tc.minor, h.MinorVersionNumber())
		}
	})
}

func TestHeaderFlagMethods(t *testing.T) {
	t.Run("is unencrypted", func(t *testing.T) {
		testCases := []struct {
			flags       uint8
			unencrypted bool
		}{
			{0x00, false},
			{0x01, true},
			{0x04, false},
			{0x05, true},
			{0xFF, true},
		}

		for _, tc := range testCases {
			h := &Header{Flags: tc.flags}
			assert.Equal(t, tc.unencrypted, h.IsUnencrypted())
		}
	})

	t.Run("is single connect", func(t *testing.T) {
		testCases := []struct {
			flags         uint8
			singleConnect bool
		}{
			{0x00, false},
			{0x01, false},
			{0x04, true},
			{0x05, true},
			{0xFF, true},
		}

		for _, tc := range testCases {
			h := &Header{Flags: tc.flags}
			assert.Equal(t, tc.singleConnect, h.IsSingleConnect())
		}
	})

	t.Run("set unencrypted", func(t *testing.T) {
		h := &Header{Flags: 0x00}

		h.SetUnencrypted(true)
		assert.True(t, h.IsUnencrypted())
		assert.Equal(t, uint8(0x01), h.Flags)

		h.SetUnencrypted(false)
		assert.False(t, h.IsUnencrypted())
		assert.Equal(t, uint8(0x00), h.Flags)
	})

	t.Run("set single connect", func(t *testing.T) {
		h := &Header{Flags: 0x00}

		h.SetSingleConnect(true)
		assert.True(t, h.IsSingleConnect())
		assert.Equal(t, uint8(0x04), h.Flags)

		h.SetSingleConnect(false)
		assert.False(t, h.IsSingleConnect())
		assert.Equal(t, uint8(0x00), h.Flags)
	})

	t.Run("set flags preserves other flags", func(t *testing.T) {
		h := &Header{Flags: FlagSingleConnect}

		h.SetUnencrypted(true)
		assert.True(t, h.IsUnencrypted())
		assert.True(t, h.IsSingleConnect())
		assert.Equal(t, uint8(0x05), h.Flags)

		h.SetUnencrypted(false)
		assert.False(t, h.IsUnencrypted())
		assert.True(t, h.IsSingleConnect())
		assert.Equal(t, uint8(0x04), h.Flags)
	})
}

func TestHeaderBoundaryConditions(t *testing.T) {
	t.Run("max session ID", func(t *testing.T) {
		h := NewHeader(PacketTypeAuthen, 0xFFFFFFFF)
		data, err := h.MarshalBinary()
		require.NoError(t, err)

		decoded := &Header{}
		err = decoded.UnmarshalBinary(data)
		require.NoError(t, err)
		assert.Equal(t, uint32(0xFFFFFFFF), decoded.SessionID)
	})

	t.Run("max length", func(t *testing.T) {
		h := &Header{
			Version: 0xc0,
			Type:    PacketTypeAuthen,
			SeqNo:   1,
			Length:  0xFFFFFFFF,
		}

		data, err := h.MarshalBinary()
		require.NoError(t, err)

		decoded := &Header{}
		err = decoded.UnmarshalBinary(data)
		require.NoError(t, err)
		assert.Equal(t, uint32(0xFFFFFFFF), decoded.Length)
	})

	t.Run("max sequence number", func(t *testing.T) {
		h := &Header{
			Version: 0xc0,
			Type:    PacketTypeAuthen,
			SeqNo:   255,
		}

		err := h.Validate()
		assert.NoError(t, err)
	})
}

func BenchmarkHeaderMarshalBinary(b *testing.B) {
	h := &Header{
		Version:   0xc0,
		Type:      PacketTypeAuthen,
		SeqNo:     1,
		Flags:     0,
		SessionID: 0x12345678,
		Length:    256,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = h.MarshalBinary()
	}
}

func BenchmarkHeaderUnmarshalBinary(b *testing.B) {
	data := []byte{0xc0, 0x01, 0x01, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x01, 0x00}
	h := &Header{}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.UnmarshalBinary(data)
	}
}

func BenchmarkHeaderValidate(b *testing.B) {
	h := &Header{
		Version: 0xc0,
		Type:    PacketTypeAuthen,
		SeqNo:   1,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.Validate()
	}
}

func FuzzHeaderUnmarshalBinary(f *testing.F) {
	f.Add([]byte{0xc0, 0x01, 0x01, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x01, 0x00})
	f.Add([]byte{0xc1, 0x02, 0x02, 0x05, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		h := &Header{}
		err := h.UnmarshalBinary(data)
		if err != nil {
			return
		}

		marshaled, err := h.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal failed after successful unmarshal: %v", err)
		}

		if len(data) >= HeaderLength {
			for i := range HeaderLength {
				if marshaled[i] != data[i] {
					t.Fatalf("roundtrip mismatch at byte %d: got %02x, want %02x", i, marshaled[i], data[i])
				}
			}
		}
	})
}
