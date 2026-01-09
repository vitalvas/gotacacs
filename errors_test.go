package gotacacs

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
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
		}

		for _, err := range errs {
			assert.NotNil(t, err)
			assert.NotEmpty(t, err.Error())
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
		}

		for i, err1 := range errs {
			for j, err2 := range errs {
				if i != j {
					assert.NotEqual(t, err1, err2)
				}
			}
		}
	})
}

func TestErrorWrapping(t *testing.T) {
	t.Run("wrap and unwrap ErrInvalidHeader", func(t *testing.T) {
		wrapped := fmt.Errorf("custom context: %w", ErrInvalidHeader)
		assert.True(t, errors.Is(wrapped, ErrInvalidHeader))
		assert.Contains(t, wrapped.Error(), "custom context")
		assert.Contains(t, wrapped.Error(), ErrInvalidHeader.Error())
	})

	t.Run("wrap and unwrap ErrInvalidVersion", func(t *testing.T) {
		wrapped := fmt.Errorf("version mismatch: %w", ErrInvalidVersion)
		assert.True(t, errors.Is(wrapped, ErrInvalidVersion))
	})

	t.Run("wrap and unwrap ErrBufferTooShort", func(t *testing.T) {
		wrapped := fmt.Errorf("need 12 bytes: %w", ErrBufferTooShort)
		assert.True(t, errors.Is(wrapped, ErrBufferTooShort))
	})

	t.Run("nested wrapping", func(t *testing.T) {
		inner := fmt.Errorf("inner: %w", ErrInvalidPacket)
		outer := fmt.Errorf("outer: %w", inner)
		assert.True(t, errors.Is(outer, ErrInvalidPacket))
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
	}

	for _, tt := range tests {
		t.Run(tt.message, func(t *testing.T) {
			assert.Equal(t, tt.message, tt.err.Error())
		})
	}
}
