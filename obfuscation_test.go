package gotacacs

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestObfuscate(t *testing.T) {
	t.Run("basic obfuscation", func(t *testing.T) {
		header := &Header{
			Version:   0xc0,
			SeqNo:     1,
			SessionID: 0x12345678,
		}
		secret := []byte("testsecret")
		body := []byte("hello world")

		obfuscated := Obfuscate(header, secret, body)

		assert.NotNil(t, obfuscated)
		assert.Len(t, obfuscated, len(body))
		assert.NotEqual(t, body, obfuscated)
	})

	t.Run("empty secret returns unchanged body", func(t *testing.T) {
		header := &Header{
			Version:   0xc0,
			SeqNo:     1,
			SessionID: 0x12345678,
		}
		body := []byte("hello world")

		obfuscated := Obfuscate(header, nil, body)
		assert.Equal(t, body, obfuscated)

		obfuscated = Obfuscate(header, []byte{}, body)
		assert.Equal(t, body, obfuscated)
	})

	t.Run("unencrypted flag returns unchanged body", func(t *testing.T) {
		header := &Header{
			Version:   0xc0,
			SeqNo:     1,
			Flags:     FlagUnencrypted,
			SessionID: 0x12345678,
		}
		secret := []byte("testsecret")
		body := []byte("hello world")

		obfuscated := Obfuscate(header, secret, body)
		assert.Equal(t, body, obfuscated)
	})

	t.Run("empty body returns empty", func(t *testing.T) {
		header := &Header{
			Version:   0xc0,
			SeqNo:     1,
			SessionID: 0x12345678,
		}
		secret := []byte("testsecret")

		obfuscated := Obfuscate(header, secret, []byte{})
		assert.Equal(t, []byte{}, obfuscated)

		obfuscated = Obfuscate(header, secret, nil)
		assert.Nil(t, obfuscated)
	})
}

func TestDeobfuscate(t *testing.T) {
	t.Run("deobfuscate is alias for obfuscate", func(t *testing.T) {
		header := &Header{
			Version:   0xc0,
			SeqNo:     1,
			SessionID: 0x12345678,
		}
		secret := []byte("testsecret")
		body := []byte("test data")

		obfuscated := Obfuscate(header, secret, body)
		deobfuscated := Deobfuscate(header, secret, obfuscated)

		assert.Equal(t, body, deobfuscated)
	})
}

func TestObfuscateDeobfuscateRoundtrip(t *testing.T) {
	testCases := []struct {
		name   string
		header *Header
		secret []byte
		body   []byte
	}{
		{
			name: "short body",
			header: &Header{
				Version:   0xc0,
				SeqNo:     1,
				SessionID: 0x12345678,
			},
			secret: []byte("secret"),
			body:   []byte("hi"),
		},
		{
			name: "exactly MD5 block size",
			header: &Header{
				Version:   0xc0,
				SeqNo:     1,
				SessionID: 0xDEADBEEF,
			},
			secret: []byte("mysecret"),
			body:   bytes.Repeat([]byte("x"), md5.Size),
		},
		{
			name: "longer than MD5 block",
			header: &Header{
				Version:   0xc1,
				SeqNo:     5,
				SessionID: 0xCAFEBABE,
			},
			secret: []byte("longsecretkey"),
			body:   bytes.Repeat([]byte("a"), md5.Size+10),
		},
		{
			name: "multiple MD5 blocks",
			header: &Header{
				Version:   0xc0,
				SeqNo:     255,
				SessionID: 0x00000001,
			},
			secret: []byte("s"),
			body:   bytes.Repeat([]byte("b"), md5.Size*3+5),
		},
		{
			name: "binary data",
			header: &Header{
				Version:   0xc0,
				SeqNo:     100,
				SessionID: 0xFFFFFFFF,
			},
			secret: []byte("binarysecret"),
			body:   []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD, 0x80, 0x7F},
		},
		{
			name: "large body",
			header: &Header{
				Version:   0xc0,
				SeqNo:     1,
				SessionID: 0x87654321,
			},
			secret: []byte("bigsecret"),
			body:   bytes.Repeat([]byte("large"), 1000),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			obfuscated := Obfuscate(tc.header, tc.secret, tc.body)
			require.NotNil(t, obfuscated)
			require.Len(t, obfuscated, len(tc.body))

			deobfuscated := Deobfuscate(tc.header, tc.secret, obfuscated)
			assert.Equal(t, tc.body, deobfuscated)
		})
	}
}

func TestObfuscateDifferentInputsProduceDifferentOutputs(t *testing.T) {
	t.Run("different session IDs", func(t *testing.T) {
		h1 := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x11111111}
		h2 := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x22222222}
		secret := []byte("secret")
		body := []byte("test data")

		o1 := Obfuscate(h1, secret, body)
		o2 := Obfuscate(h2, secret, body)

		assert.NotEqual(t, o1, o2)
	})

	t.Run("different secrets", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		body := []byte("test data")

		o1 := Obfuscate(header, []byte("secret1"), body)
		o2 := Obfuscate(header, []byte("secret2"), body)

		assert.NotEqual(t, o1, o2)
	})

	t.Run("different sequence numbers", func(t *testing.T) {
		h1 := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		h2 := &Header{Version: 0xc0, SeqNo: 2, SessionID: 0x12345678}
		secret := []byte("secret")
		body := []byte("test data")

		o1 := Obfuscate(h1, secret, body)
		o2 := Obfuscate(h2, secret, body)

		assert.NotEqual(t, o1, o2)
	})

	t.Run("different versions", func(t *testing.T) {
		h1 := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		h2 := &Header{Version: 0xc1, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("secret")
		body := []byte("test data")

		o1 := Obfuscate(h1, secret, body)
		o2 := Obfuscate(h2, secret, body)

		assert.NotEqual(t, o1, o2)
	})
}

func TestGeneratePseudoPad(t *testing.T) {
	t.Run("known vector verification", func(t *testing.T) {
		// Manually compute expected pseudo-pad for verification
		header := &Header{
			Version:   0xc0,
			SeqNo:     1,
			SessionID: 0x12345678,
		}
		secret := []byte("secret")

		// Compute expected first block:
		// MD5(session_id || secret || version || seq_no)
		sessionIDBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(sessionIDBytes, header.SessionID)

		h := md5.New()
		h.Write(sessionIDBytes)
		h.Write(secret)
		h.Write([]byte{header.Version})
		h.Write([]byte{header.SeqNo})
		expectedFirstBlock := h.Sum(nil)

		// Generate pad and verify first 16 bytes match
		pad := generatePseudoPad(header, secret, 16)
		assert.Equal(t, expectedFirstBlock, pad)
	})

	t.Run("pad length matches requested length", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("secret")

		for _, length := range []int{1, 5, 15, 16, 17, 32, 48, 100, 1000} {
			pad := generatePseudoPad(header, secret, length)
			assert.Len(t, pad, length)
		}
	})

	t.Run("zero length returns nil", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("secret")

		pad := generatePseudoPad(header, secret, 0)
		assert.Nil(t, pad)
	})

	t.Run("consecutive blocks are chained", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("secret")

		// Get 32 bytes (2 MD5 blocks)
		pad := generatePseudoPad(header, secret, 32)

		// First block
		sessionIDBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(sessionIDBytes, header.SessionID)

		h1 := md5.New()
		h1.Write(sessionIDBytes)
		h1.Write(secret)
		h1.Write([]byte{header.Version})
		h1.Write([]byte{header.SeqNo})
		firstBlock := h1.Sum(nil)

		// Second block should include first block
		h2 := md5.New()
		h2.Write(sessionIDBytes)
		h2.Write(secret)
		h2.Write([]byte{header.Version})
		h2.Write([]byte{header.SeqNo})
		h2.Write(firstBlock)
		secondBlock := h2.Sum(nil)

		expected := make([]byte, 0, 32)
		expected = append(expected, firstBlock...)
		expected = append(expected, secondBlock...)
		assert.Equal(t, expected, pad)
	})
}

func TestObfuscateDoesNotModifyOriginal(t *testing.T) {
	t.Run("original body unchanged", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("secret")
		original := []byte("test data")
		bodyCopy := make([]byte, len(original))
		copy(bodyCopy, original)

		_ = Obfuscate(header, secret, original)

		assert.Equal(t, bodyCopy, original)
	})

	t.Run("original secret unchanged", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("secret")
		secretCopy := make([]byte, len(secret))
		copy(secretCopy, secret)
		body := []byte("test data")

		_ = Obfuscate(header, secret, body)

		assert.Equal(t, secretCopy, secret)
	})
}

func TestObfuscateXORProperties(t *testing.T) {
	t.Run("double obfuscation returns original", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("secret")
		body := []byte("original data here")

		doubleObfuscated := Obfuscate(header, secret, Obfuscate(header, secret, body))
		assert.Equal(t, body, doubleObfuscated)
	})

	t.Run("obfuscating zeros reveals pad", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("secret")
		zeros := make([]byte, 32)

		obfuscated := Obfuscate(header, secret, zeros)
		pad := generatePseudoPad(header, secret, 32)

		assert.Equal(t, pad, obfuscated)
	})
}

func TestObfuscateEdgeCases(t *testing.T) {
	t.Run("single byte body", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("secret")
		body := []byte{0x42}

		obfuscated := Obfuscate(header, secret, body)
		assert.Len(t, obfuscated, 1)

		deobfuscated := Deobfuscate(header, secret, obfuscated)
		assert.Equal(t, body, deobfuscated)
	})

	t.Run("single byte secret", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := []byte("x")
		body := []byte("test data")

		obfuscated := Obfuscate(header, secret, body)
		deobfuscated := Deobfuscate(header, secret, obfuscated)
		assert.Equal(t, body, deobfuscated)
	})

	t.Run("long secret", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0x12345678}
		secret := bytes.Repeat([]byte("verylongsecret"), 100)
		body := []byte("test data")

		obfuscated := Obfuscate(header, secret, body)
		deobfuscated := Deobfuscate(header, secret, obfuscated)
		assert.Equal(t, body, deobfuscated)
	})

	t.Run("session ID zero", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0}
		secret := []byte("secret")
		body := []byte("test data")

		obfuscated := Obfuscate(header, secret, body)
		deobfuscated := Deobfuscate(header, secret, obfuscated)
		assert.Equal(t, body, deobfuscated)
	})

	t.Run("max session ID", func(t *testing.T) {
		header := &Header{Version: 0xc0, SeqNo: 1, SessionID: 0xFFFFFFFF}
		secret := []byte("secret")
		body := []byte("test data")

		obfuscated := Obfuscate(header, secret, body)
		deobfuscated := Deobfuscate(header, secret, obfuscated)
		assert.Equal(t, body, deobfuscated)
	})
}
