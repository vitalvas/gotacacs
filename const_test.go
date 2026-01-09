package gotacacs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionConstants(t *testing.T) {
	t.Run("major version", func(t *testing.T) {
		assert.Equal(t, uint8(0x0c), uint8(MajorVersion))
	})

	t.Run("minor versions", func(t *testing.T) {
		assert.Equal(t, uint8(0x00), uint8(MinorVersionDefault))
		assert.Equal(t, uint8(0x01), uint8(MinorVersionOne))
	})
}

func TestPacketTypeConstants(t *testing.T) {
	t.Run("packet types", func(t *testing.T) {
		assert.Equal(t, uint8(0x01), uint8(PacketTypeAuthen))
		assert.Equal(t, uint8(0x02), uint8(PacketTypeAuthor))
		assert.Equal(t, uint8(0x03), uint8(PacketTypeAcct))
	})
}

func TestFlagConstants(t *testing.T) {
	t.Run("header flags", func(t *testing.T) {
		assert.Equal(t, uint8(0x01), uint8(FlagUnencrypted))
		assert.Equal(t, uint8(0x04), uint8(FlagSingleConnect))
	})
}

func TestAuthenActionConstants(t *testing.T) {
	t.Run("authentication actions", func(t *testing.T) {
		assert.Equal(t, uint8(0x01), uint8(AuthenActionLogin))
		assert.Equal(t, uint8(0x02), uint8(AuthenActionChPass))
		assert.Equal(t, uint8(0x04), uint8(AuthenActionSendAuth))
	})
}

func TestAuthenTypeConstants(t *testing.T) {
	t.Run("authentication types", func(t *testing.T) {
		assert.Equal(t, uint8(0x01), uint8(AuthenTypeASCII))
		assert.Equal(t, uint8(0x02), uint8(AuthenTypePAP))
		assert.Equal(t, uint8(0x03), uint8(AuthenTypeCHAP))
		assert.Equal(t, uint8(0x05), uint8(AuthenTypeMSCHAP))
		assert.Equal(t, uint8(0x06), uint8(AuthenTypeMSCHAPV2))
	})
}

func TestAuthenServiceConstants(t *testing.T) {
	t.Run("authentication services", func(t *testing.T) {
		assert.Equal(t, uint8(0x00), uint8(AuthenServiceNone))
		assert.Equal(t, uint8(0x01), uint8(AuthenServiceLogin))
		assert.Equal(t, uint8(0x02), uint8(AuthenServiceEnable))
		assert.Equal(t, uint8(0x03), uint8(AuthenServicePPP))
		assert.Equal(t, uint8(0x05), uint8(AuthenServicePT))
		assert.Equal(t, uint8(0x06), uint8(AuthenServiceRCMD))
		assert.Equal(t, uint8(0x07), uint8(AuthenServiceX25))
		assert.Equal(t, uint8(0x08), uint8(AuthenServiceNASI))
	})
}

func TestAuthenStatusConstants(t *testing.T) {
	t.Run("authentication status codes", func(t *testing.T) {
		assert.Equal(t, uint8(0x01), uint8(AuthenStatusPass))
		assert.Equal(t, uint8(0x02), uint8(AuthenStatusFail))
		assert.Equal(t, uint8(0x03), uint8(AuthenStatusGetData))
		assert.Equal(t, uint8(0x04), uint8(AuthenStatusGetUser))
		assert.Equal(t, uint8(0x05), uint8(AuthenStatusGetPass))
		assert.Equal(t, uint8(0x06), uint8(AuthenStatusRestart))
		assert.Equal(t, uint8(0x07), uint8(AuthenStatusError))
		assert.Equal(t, uint8(0x21), uint8(AuthenStatusFollow))
	})
}

func TestAuthenReplyFlagConstants(t *testing.T) {
	t.Run("authentication reply flags", func(t *testing.T) {
		assert.Equal(t, uint8(0x01), uint8(AuthenReplyFlagNoEcho))
	})
}

func TestAuthenContinueFlagConstants(t *testing.T) {
	t.Run("authentication continue flags", func(t *testing.T) {
		assert.Equal(t, uint8(0x01), uint8(AuthenContinueFlagAbort))
	})
}

func TestAuthorStatusConstants(t *testing.T) {
	t.Run("authorization status codes", func(t *testing.T) {
		assert.Equal(t, uint8(0x01), uint8(AuthorStatusPassAdd))
		assert.Equal(t, uint8(0x02), uint8(AuthorStatusPassRepl))
		assert.Equal(t, uint8(0x10), uint8(AuthorStatusFail))
		assert.Equal(t, uint8(0x11), uint8(AuthorStatusError))
		assert.Equal(t, uint8(0x21), uint8(AuthorStatusFollow))
	})
}

func TestAcctFlagConstants(t *testing.T) {
	t.Run("accounting flags", func(t *testing.T) {
		assert.Equal(t, uint8(0x02), uint8(AcctFlagStart))
		assert.Equal(t, uint8(0x04), uint8(AcctFlagStop))
		assert.Equal(t, uint8(0x08), uint8(AcctFlagWatchdog))
	})
}

func TestAcctStatusConstants(t *testing.T) {
	t.Run("accounting status codes", func(t *testing.T) {
		assert.Equal(t, uint8(0x01), uint8(AcctStatusSuccess))
		assert.Equal(t, uint8(0x02), uint8(AcctStatusError))
		assert.Equal(t, uint8(0x21), uint8(AcctStatusFollow))
	})
}

func TestMiscConstants(t *testing.T) {
	t.Run("header length", func(t *testing.T) {
		assert.Equal(t, 12, HeaderLength)
	})

	t.Run("default port", func(t *testing.T) {
		assert.Equal(t, 49, DefaultPort)
	})

	t.Run("max body length", func(t *testing.T) {
		assert.Equal(t, uint32(0xFFFFFFFF), uint32(MaxBodyLength))
	})
}
