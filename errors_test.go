package gotacacs

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestErrorDefinitions(t *testing.T) {
	t.Run("errors are not nil", func(t *testing.T) {
		errs := []error{
			ErrInvalidHeader,
			ErrInvalidPacket,
			ErrInvalidVersion,
			ErrInvalidType,
			ErrInvalidSequence,
			ErrSessionNotFound,
			ErrConnectionClosed,
			ErrTimeout,
			ErrAuthenticationFailed,
			ErrAuthorizationDenied,
			ErrAccountingFailed,
			ErrBufferTooShort,
			ErrBodyTooLarge,
			ErrAuthenFollow,
			ErrAuthenRestart,
			ErrSequenceOverflow,
			ErrMaxPrompts,
			ErrBadSecret,
			ErrTooManySessions,
			ErrNoSecret,
			ErrInvalidUsername,
			ErrInvalidText,
		}

		for _, err := range errs {
			if err == nil {
				t.Errorf("expected non-nil")
			}
			if len(err.Error()) == 0 {
				t.Errorf("expected non-empty")
			}
		}
	})

	t.Run("errors are distinct", func(t *testing.T) {
		errs := []error{
			ErrInvalidHeader,
			ErrInvalidPacket,
			ErrInvalidVersion,
			ErrInvalidType,
			ErrInvalidSequence,
			ErrSessionNotFound,
			ErrConnectionClosed,
			ErrTimeout,
			ErrAuthenticationFailed,
			ErrAuthorizationDenied,
			ErrAccountingFailed,
			ErrBufferTooShort,
			ErrBodyTooLarge,
			ErrAuthenFollow,
			ErrAuthenRestart,
			ErrSequenceOverflow,
			ErrMaxPrompts,
			ErrBadSecret,
			ErrTooManySessions,
			ErrNoSecret,
			ErrInvalidUsername,
			ErrInvalidText,
		}

		for i, err1 := range errs {
			for j, err2 := range errs {
				if i != j && err1 == err2 {
					t.Errorf("should not equal %v", err1)
				}
			}
		}
	})
}

func TestErrorWrapping(t *testing.T) {
	t.Run("wrap and unwrap ErrInvalidHeader", func(t *testing.T) {
		wrapped := fmt.Errorf("custom context: %w", ErrInvalidHeader)
		if !errors.Is(wrapped, ErrInvalidHeader) {
			t.Errorf("expected true")
		}
		if !strings.Contains(wrapped.Error(), "custom context") {
			t.Errorf("expected %q to contain %q", wrapped.Error(), "custom context")
		}
		if !strings.Contains(wrapped.Error(), ErrInvalidHeader.Error()) {
			t.Errorf("expected %q to contain %q", wrapped.Error(), ErrInvalidHeader.Error())
		}
	})

	t.Run("wrap and unwrap ErrInvalidVersion", func(t *testing.T) {
		wrapped := fmt.Errorf("version mismatch: %w", ErrInvalidVersion)
		if !errors.Is(wrapped, ErrInvalidVersion) {
			t.Errorf("expected true")
		}
	})

	t.Run("wrap and unwrap ErrBufferTooShort", func(t *testing.T) {
		wrapped := fmt.Errorf("need 12 bytes: %w", ErrBufferTooShort)
		if !errors.Is(wrapped, ErrBufferTooShort) {
			t.Errorf("expected true")
		}
	})

	t.Run("nested wrapping", func(t *testing.T) {
		inner := fmt.Errorf("inner: %w", ErrInvalidPacket)
		outer := fmt.Errorf("outer: %w", inner)
		if !errors.Is(outer, ErrInvalidPacket) {
			t.Errorf("expected true")
		}
	})
}

func TestErrorMessages(t *testing.T) {
	tests := []struct {
		err     error
		message string
	}{
		{ErrInvalidHeader, "invalid header"},
		{ErrInvalidPacket, "invalid packet"},
		{ErrInvalidVersion, "invalid version"},
		{ErrInvalidType, "invalid packet type"},
		{ErrInvalidSequence, "invalid sequence number"},
		{ErrSessionNotFound, "session not found"},
		{ErrConnectionClosed, "connection closed"},
		{ErrTimeout, "operation timeout"},
		{ErrAuthenticationFailed, "authentication failed"},
		{ErrAuthorizationDenied, "authorization denied"},
		{ErrAccountingFailed, "accounting failed"},
		{ErrBufferTooShort, "buffer too short"},
		{ErrBodyTooLarge, "body too large"},
		{ErrAuthenFollow, "authentication follow requested"},
		{ErrAuthenRestart, "authentication restart requested"},
		{ErrSequenceOverflow, "sequence number overflow"},
		{ErrMaxPrompts, "maximum prompt count exceeded"},
		{ErrBadSecret, "bad secret"},
		{ErrTooManySessions, "too many sessions"},
		{ErrNoSecret, "no shared secret for non-TLS connection"},
		{ErrInvalidUsername, "invalid username"},
		{ErrInvalidText, "invalid text field"},
	}

	for _, tt := range tests {
		t.Run(tt.message, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.message {
				t.Errorf("got %v, want %v", got, tt.message)
			}
		})
	}
}
