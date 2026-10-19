package gotacacs

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateText(t *testing.T) {
	// RFC 8907 Section 3.7 / RFC 20 Section 5.2: text fields are printable
	// US-ASCII and MUST exclude control characters. Space is printable.
	t.Run("accepts printable ascii including space", func(t *testing.T) {
		for _, s := range []string{"", "tty0", "192.0.2.1", "a b c", "~!@#$%^&*()_+"} {
			if err := ValidateText([]byte(s)); err != nil {
				t.Errorf("ValidateText(%q) = %v, want nil", s, err)
			}
		}
	})

	t.Run("rejects control characters", func(t *testing.T) {
		for _, b := range []byte{0x00, 0x09, 0x0a, 0x0d, 0x1f, 0x7f} {
			if err := ValidateText([]byte{'a', b, 'b'}); !errors.Is(err, ErrInvalidText) {
				t.Errorf("ValidateText with control 0x%02x = %v, want ErrInvalidText", b, err)
			}
		}
	})

	t.Run("rejects non-ascii bytes", func(t *testing.T) {
		if err := ValidateText([]byte{0x80}); !errors.Is(err, ErrInvalidText) {
			t.Errorf("ValidateText(0x80) = %v, want ErrInvalidText", err)
		}
	})
}

func TestValidateUsername(t *testing.T) {
	// RFC 8907 Section 3.7 requires the RFC 8265 UsernameCasePreserved profile.
	// For the ASCII range this is the PRECIS IdentifierClass: printable
	// non-space ASCII (U+0021-U+007E), non-empty, case preserved.
	t.Run("accepts printable non-space ascii", func(t *testing.T) {
		for _, s := range []string{"admin", "User123", "a.b-c_d", "root@host", "MixedCase"} {
			if err := ValidateUsername([]byte(s)); err != nil {
				t.Errorf("ValidateUsername(%q) = %v, want nil", s, err)
			}
		}
	})

	t.Run("rejects empty", func(t *testing.T) {
		if err := ValidateUsername(nil); !errors.Is(err, ErrInvalidUsername) {
			t.Errorf("ValidateUsername(nil) = %v, want ErrInvalidUsername", err)
		}
		if err := ValidateUsername([]byte{}); !errors.Is(err, ErrInvalidUsername) {
			t.Errorf("ValidateUsername(empty) = %v, want ErrInvalidUsername", err)
		}
	})

	t.Run("rejects space", func(t *testing.T) {
		// IdentifierClass disallows spaces (unlike FreeformClass).
		if err := ValidateUsername([]byte("ad min")); !errors.Is(err, ErrInvalidUsername) {
			t.Errorf("ValidateUsername with space = %v, want ErrInvalidUsername", err)
		}
	})

	t.Run("rejects control characters", func(t *testing.T) {
		for _, b := range []byte{0x00, 0x09, 0x1f, 0x7f} {
			if err := ValidateUsername([]byte{'a', b}); !errors.Is(err, ErrInvalidUsername) {
				t.Errorf("ValidateUsername with control 0x%02x = %v, want ErrInvalidUsername", b, err)
			}
		}
	})

	t.Run("rejects non-ascii as unvalidatable without PRECIS tables", func(t *testing.T) {
		// Full RFC 8265 of non-ASCII code points needs Unicode tables this
		// zero-dependency library does not carry, so non-ASCII is refused
		// rather than passed through unvalidated.
		err := ValidateUsername([]byte("admΙn")) // contains a non-ASCII rune
		if !errors.Is(err, ErrInvalidUsername) {
			t.Errorf("ValidateUsername(non-ascii) = %v, want ErrInvalidUsername", err)
		}
		if !strings.Contains(err.Error(), "non-ASCII") {
			t.Errorf("error %q should explain the non-ASCII limitation", err.Error())
		}
	})
}

func FuzzValidateUsername(f *testing.F) {
	f.Add("admin")
	f.Add("")
	f.Add("a b")
	f.Add("\x00")
	f.Fuzz(func(t *testing.T, s string) {
		err := ValidateUsername([]byte(s))
		if err != nil {
			return
		}
		// An accepted username is non-empty and every byte is printable
		// non-space ASCII.
		if len(s) == 0 {
			t.Fatal("accepted empty username")
		}
		for i := 0; i < len(s); i++ {
			if s[i] <= 0x20 || s[i] >= 0x7f {
				t.Fatalf("accepted username %q with byte 0x%02x at %d", s, s[i], i)
			}
		}
	})
}
