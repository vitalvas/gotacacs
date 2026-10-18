package gotacacs

import (
	"bytes"
	"errors"
	"testing"
)

func TestNewHeader(t *testing.T) {
	t.Run("authentication header", func(t *testing.T) {
		h := NewHeader(PacketTypeAuthen, 0x12345678)
		if h.Version != 0xc0 {
			t.Errorf("got %v, want %v", h.Version, uint8(0xc0))
		}
		if h.Type != PacketTypeAuthen {
			t.Errorf("got %v, want %v", h.Type, uint8(PacketTypeAuthen))
		}
		if h.SeqNo != uint8(1) {
			t.Errorf("got %v, want %v", h.SeqNo, uint8(1))
		}
		if h.Flags != 0 {
			t.Errorf("got %v, want %v", h.Flags, uint8(0))
		}
		if h.SessionID != uint32(0x12345678) {
			t.Errorf("got %v, want %v", h.SessionID, uint32(0x12345678))
		}
		if h.Length != uint32(0) {
			t.Errorf("got %v, want %v", h.Length, uint32(0))
		}
	})

	t.Run("authorization header", func(t *testing.T) {
		h := NewHeader(PacketTypeAuthor, 0xABCDEF00)
		if h.Type != PacketTypeAuthor {
			t.Errorf("got %v, want %v", h.Type, uint8(PacketTypeAuthor))
		}
		if h.SessionID != uint32(0xABCDEF00) {
			t.Errorf("got %v, want %v", h.SessionID, uint32(0xABCDEF00))
		}
	})

	t.Run("accounting header", func(t *testing.T) {
		h := NewHeader(PacketTypeAcct, 0xFFFFFFFF)
		if h.Type != PacketTypeAcct {
			t.Errorf("got %v, want %v", h.Type, uint8(PacketTypeAcct))
		}
		if h.SessionID != uint32(0xFFFFFFFF) {
			t.Errorf("got %v, want %v", h.SessionID, uint32(0xFFFFFFFF))
		}
	})

	t.Run("zero session ID", func(t *testing.T) {
		h := NewHeader(PacketTypeAuthen, 0)
		if h.SessionID != uint32(0) {
			t.Errorf("got %v, want %v", h.SessionID, uint32(0))
		}
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
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(data) != HeaderLength {
			t.Fatalf("len = %d, want %d", len(data), HeaderLength)
		}

		if data[0] != uint8(0xc0) {
			t.Errorf("got %v, want %v", data[0], uint8(0xc0))
		}
		if data[1] != uint8(0x01) {
			t.Errorf("got %v, want %v", data[1], uint8(0x01))
		}
		if data[2] != uint8(0x01) {
			t.Errorf("got %v, want %v", data[2], uint8(0x01))
		}
		if data[3] != uint8(0x00) {
			t.Errorf("got %v, want %v", data[3], uint8(0x00))
		}
		if !bytes.Equal(data[4:8], []byte{0x12, 0x34, 0x56, 0x78}) {
			t.Errorf("got %v, want %v", data[4:8], []byte{0x12, 0x34, 0x56, 0x78})
		}
		if !bytes.Equal(data[8:12], []byte{0x00, 0x00, 0x01, 0x00}) {
			t.Errorf("got %v, want %v", data[8:12], []byte{0x00, 0x00, 0x01, 0x00})
		}
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
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if data[0] != uint8(0xc1) {
			t.Errorf("got %v, want %v", data[0], uint8(0xc1))
		}
		if data[1] != uint8(0x02) {
			t.Errorf("got %v, want %v", data[1], uint8(0x02))
		}
		if data[2] != uint8(0x05) {
			t.Errorf("got %v, want %v", data[2], uint8(0x05))
		}
		if data[3] != uint8(0x05) {
			t.Errorf("got %v, want %v", data[3], uint8(0x05))
		}
		if !bytes.Equal(data[4:8], []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
			t.Errorf("got %v, want %v", data[4:8], []byte{0xDE, 0xAD, 0xBE, 0xEF})
		}
		if !bytes.Equal(data[8:12], []byte{0xCA, 0xFE, 0xBA, 0xBE}) {
			t.Errorf("got %v, want %v", data[8:12], []byte{0xCA, 0xFE, 0xBA, 0xBE})
		}
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
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for i := range HeaderLength {
			if data[i] != uint8(0xFF) {
				t.Errorf("got %v, want %v", data[i], uint8(0xFF))
			}
		}
	})
}

func TestHeaderUnmarshalBinary(t *testing.T) {
	t.Run("basic decoding", func(t *testing.T) {
		data := []byte{0xc0, 0x01, 0x01, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x01, 0x00}

		h := &Header{}
		err := h.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if h.Version != 0xc0 {
			t.Errorf("got %v, want %v", h.Version, uint8(0xc0))
		}
		if h.Type != 0x01 {
			t.Errorf("got %v, want %v", h.Type, uint8(0x01))
		}
		if h.SeqNo != uint8(0x01) {
			t.Errorf("got %v, want %v", h.SeqNo, uint8(0x01))
		}
		if h.Flags != 0x00 {
			t.Errorf("got %v, want %v", h.Flags, uint8(0x00))
		}
		if h.SessionID != uint32(0x12345678) {
			t.Errorf("got %v, want %v", h.SessionID, uint32(0x12345678))
		}
		if h.Length != uint32(0x00000100) {
			t.Errorf("got %v, want %v", h.Length, uint32(0x00000100))
		}
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
				if err == nil {
					t.Errorf("expected an error")
				}
				if !errors.Is(err, ErrBufferTooShort) {
					t.Errorf("error %v is not %v", err, ErrBufferTooShort)
				}
			})
		}
	})

	t.Run("extra data ignored", func(t *testing.T) {
		data := []byte{0xc0, 0x01, 0x01, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x01, 0x00, 0xFF, 0xFF}

		h := &Header{}
		err := h.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if h.Length != uint32(0x00000100) {
			t.Errorf("got %v, want %v", h.Length, uint32(0x00000100))
		}
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
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			decoded := &Header{}
			err = decoded.UnmarshalBinary(data)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if decoded.Version != tc.header.Version {
				t.Errorf("got %v, want %v", decoded.Version, tc.header.Version)
			}
			if decoded.Type != tc.header.Type {
				t.Errorf("got %v, want %v", decoded.Type, tc.header.Type)
			}
			if decoded.SeqNo != tc.header.SeqNo {
				t.Errorf("got %v, want %v", decoded.SeqNo, tc.header.SeqNo)
			}
			if decoded.Flags != tc.header.Flags {
				t.Errorf("got %v, want %v", decoded.Flags, tc.header.Flags)
			}
			if decoded.SessionID != tc.header.SessionID {
				t.Errorf("got %v, want %v", decoded.SessionID, tc.header.SessionID)
			}
			if decoded.Length != tc.header.Length {
				t.Errorf("got %v, want %v", decoded.Length, tc.header.Length)
			}
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
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		}
	})

	t.Run("invalid major version", func(t *testing.T) {
		invalidVersions := []Version{0x00, 0x10, 0xb0, 0xd0, 0xf0}

		for _, v := range invalidVersions {
			h := &Header{Version: v, Type: PacketTypeAuthen, SeqNo: 1}
			err := h.Validate()
			if err == nil {
				t.Errorf("expected an error")
			}
			if !errors.Is(err, ErrInvalidVersion) {
				t.Errorf("error %v is not %v", err, ErrInvalidVersion)
			}
		}
	})

	t.Run("invalid minor version", func(t *testing.T) {
		invalidMinorVersions := []Version{0xc2, 0xc3, 0xc4, 0xcf}

		for _, v := range invalidMinorVersions {
			h := &Header{Version: v, Type: PacketTypeAuthen, SeqNo: 1}
			err := h.Validate()
			if err == nil {
				t.Errorf("expected an error")
			}
			if !errors.Is(err, ErrInvalidVersion) {
				t.Errorf("error %v is not %v", err, ErrInvalidVersion)
			}
		}
	})

	t.Run("invalid packet type", func(t *testing.T) {
		invalidTypes := []PacketType{0x00, 0x04, 0x05, 0xFF}

		for _, pt := range invalidTypes {
			h := &Header{Version: 0xc0, Type: pt, SeqNo: 1}
			err := h.Validate()
			if err == nil {
				t.Errorf("expected an error")
			}
			if !errors.Is(err, ErrInvalidType) {
				t.Errorf("error %v is not %v", err, ErrInvalidType)
			}
		}
	})

	t.Run("invalid sequence number zero", func(t *testing.T) {
		h := &Header{Version: 0xc0, Type: PacketTypeAuthen, SeqNo: 0}
		err := h.Validate()
		if err == nil {
			t.Errorf("expected an error")
		}
		if !errors.Is(err, ErrInvalidSequence) {
			t.Errorf("error %v is not %v", err, ErrInvalidSequence)
		}
	})
}

func TestHeaderVersionMethods(t *testing.T) {
	t.Run("major version number", func(t *testing.T) {
		testCases := []struct {
			version Version
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
			if got := h.MajorVersionNumber(); got != tc.major {
				t.Errorf("got %v, want %v", got, tc.major)
			}
		}
	})

	t.Run("minor version number", func(t *testing.T) {
		testCases := []struct {
			version Version
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
			if got := h.MinorVersionNumber(); got != tc.minor {
				t.Errorf("got %v, want %v", got, tc.minor)
			}
		}
	})
}

func TestHeaderFlagMethods(t *testing.T) {
	t.Run("is unencrypted", func(t *testing.T) {
		testCases := []struct {
			flags       HeaderFlag
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
			if got := h.IsUnencrypted(); got != tc.unencrypted {
				t.Errorf("got %v, want %v", got, tc.unencrypted)
			}
		}
	})

	t.Run("is single connect", func(t *testing.T) {
		testCases := []struct {
			flags         HeaderFlag
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
			if got := h.IsSingleConnect(); got != tc.singleConnect {
				t.Errorf("got %v, want %v", got, tc.singleConnect)
			}
		}
	})

	t.Run("set unencrypted", func(t *testing.T) {
		h := &Header{Flags: 0x00}

		h.SetUnencrypted(true)
		if !h.IsUnencrypted() {
			t.Errorf("expected true")
		}
		if h.Flags != 0x01 {
			t.Errorf("got %v, want %v", h.Flags, uint8(0x01))
		}

		h.SetUnencrypted(false)
		if h.IsUnencrypted() {
			t.Errorf("expected false")
		}
		if h.Flags != 0x00 {
			t.Errorf("got %v, want %v", h.Flags, uint8(0x00))
		}
	})

	t.Run("set single connect", func(t *testing.T) {
		h := &Header{Flags: 0x00}

		h.SetSingleConnect(true)
		if !h.IsSingleConnect() {
			t.Errorf("expected true")
		}
		if h.Flags != 0x04 {
			t.Errorf("got %v, want %v", h.Flags, uint8(0x04))
		}

		h.SetSingleConnect(false)
		if h.IsSingleConnect() {
			t.Errorf("expected false")
		}
		if h.Flags != 0x00 {
			t.Errorf("got %v, want %v", h.Flags, uint8(0x00))
		}
	})

	t.Run("set flags preserves other flags", func(t *testing.T) {
		h := &Header{Flags: FlagSingleConnect}

		h.SetUnencrypted(true)
		if !h.IsUnencrypted() {
			t.Errorf("expected true")
		}
		if !h.IsSingleConnect() {
			t.Errorf("expected true")
		}
		if h.Flags != 0x05 {
			t.Errorf("got %v, want %v", h.Flags, uint8(0x05))
		}

		h.SetUnencrypted(false)
		if h.IsUnencrypted() {
			t.Errorf("expected false")
		}
		if !h.IsSingleConnect() {
			t.Errorf("expected true")
		}
		if h.Flags != 0x04 {
			t.Errorf("got %v, want %v", h.Flags, uint8(0x04))
		}
	})
}

func TestHeaderBoundaryConditions(t *testing.T) {
	t.Run("max session ID", func(t *testing.T) {
		h := NewHeader(PacketTypeAuthen, 0xFFFFFFFF)
		data, err := h.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		decoded := &Header{}
		err = decoded.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decoded.SessionID != uint32(0xFFFFFFFF) {
			t.Errorf("got %v, want %v", decoded.SessionID, uint32(0xFFFFFFFF))
		}
	})

	t.Run("max length", func(t *testing.T) {
		h := &Header{
			Version: 0xc0,
			Type:    PacketTypeAuthen,
			SeqNo:   1,
			Length:  0xFFFFFFFF,
		}

		data, err := h.MarshalBinary()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		decoded := &Header{}
		err = decoded.UnmarshalBinary(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decoded.Length != uint32(0xFFFFFFFF) {
			t.Errorf("got %v, want %v", decoded.Length, uint32(0xFFFFFFFF))
		}
	})

	t.Run("max sequence number", func(t *testing.T) {
		h := &Header{
			Version: 0xc0,
			Type:    PacketTypeAuthen,
			SeqNo:   255,
		}

		err := h.Validate()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
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
