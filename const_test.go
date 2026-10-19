package gotacacs

import (
	"testing"
)

func TestVersionConstants(t *testing.T) {
	for _, c := range []struct{ got, want Version }{
		{MajorVersion, 0x0c},
		{MinorVersionDefault, 0x00},
		{MinorVersionOne, 0x01},
	} {
		if c.got != c.want {
			t.Errorf("got %v, want %v", c.got, c.want)
		}
	}
}

func TestPacketTypeConstants(t *testing.T) {
	for _, c := range []struct{ got, want PacketType }{
		{PacketTypeAuthen, 0x01},
		{PacketTypeAuthor, 0x02},
		{PacketTypeAcct, 0x03},
	} {
		if c.got != c.want {
			t.Errorf("got %v, want %v", c.got, c.want)
		}
	}
}

func TestFlagConstants(t *testing.T) {
	for _, c := range []struct{ got, want HeaderFlag }{
		{FlagUnencrypted, 0x01},
		{FlagSingleConnect, 0x04},
	} {
		if c.got != c.want {
			t.Errorf("got %v, want %v", c.got, c.want)
		}
	}
}

func TestAuthenActionConstants(t *testing.T) {
	for _, c := range []struct{ got, want AuthenAction }{
		{AuthenActionLogin, 0x01},
		{AuthenActionChPass, 0x02},
		{AuthenActionSendAuth, 0x04},
	} {
		if c.got != c.want {
			t.Errorf("got %v, want %v", c.got, c.want)
		}
	}
}

func TestAuthenTypeConstants(t *testing.T) {
	for _, c := range []struct{ got, want AuthenType }{
		{AuthenTypeASCII, 0x01},
		{AuthenTypePAP, 0x02},
		{AuthenTypeCHAP, 0x03},
		{AuthenTypeMSCHAP, 0x05},
		{AuthenTypeMSCHAPV2, 0x06},
	} {
		if c.got != c.want {
			t.Errorf("got %v, want %v", c.got, c.want)
		}
	}
}

func TestAuthenServiceConstants(t *testing.T) {
	for _, c := range []struct{ got, want AuthenService }{
		{AuthenServiceNone, 0x00},
		{AuthenServiceLogin, 0x01},
		{AuthenServiceEnable, 0x02},
		{AuthenServicePPP, 0x03},
		{AuthenServicePT, 0x05},
		{AuthenServiceRCMD, 0x06},
		{AuthenServiceX25, 0x07},
		{AuthenServiceNASI, 0x08},
	} {
		if c.got != c.want {
			t.Errorf("got %v, want %v", c.got, c.want)
		}
	}
}

func TestAuthenStatusConstants(t *testing.T) {
	for _, c := range []struct{ got, want AuthenStatus }{
		{AuthenStatusPass, 0x01},
		{AuthenStatusFail, 0x02},
		{AuthenStatusGetData, 0x03},
		{AuthenStatusGetUser, 0x04},
		{AuthenStatusGetPass, 0x05},
		{AuthenStatusRestart, 0x06},
		{AuthenStatusError, 0x07},
		{AuthenStatusFollow, 0x21},
	} {
		if c.got != c.want {
			t.Errorf("got %v, want %v", c.got, c.want)
		}
	}
}

func TestAuthenReplyFlagConstants(t *testing.T) {
	if AuthenReplyFlagNoEcho != 0x01 {
		t.Errorf("got %v, want %v", AuthenReplyFlagNoEcho, 0x01)
	}
}

func TestAuthenContinueFlagConstants(t *testing.T) {
	if AuthenContinueFlagAbort != 0x01 {
		t.Errorf("got %v, want %v", AuthenContinueFlagAbort, 0x01)
	}
}

func TestAuthenMethodConstants(t *testing.T) {
	for _, c := range []struct{ got, want AuthenMethod }{
		{AuthenMethodNotSet, 0x00},
		{AuthenMethodNone, 0x01},
		{AuthenMethodKRB5, 0x02},
		{AuthenMethodLine, 0x03},
		{AuthenMethodEnable, 0x04},
		{AuthenMethodLocal, 0x05},
		{AuthenMethodTACACSPlus, 0x06},
		{AuthenMethodGuest, 0x08},
		{AuthenMethodRadius, 0x10},
		{AuthenMethodKRB4, 0x11},
		{AuthenMethodRCMD, 0x20},
	} {
		if c.got != c.want {
			t.Errorf("got %v, want %v", c.got, c.want)
		}
	}
}

func TestAuthorStatusConstants(t *testing.T) {
	for _, c := range []struct{ got, want AuthorStatus }{
		{AuthorStatusPassAdd, 0x01},
		{AuthorStatusPassRepl, 0x02},
		{AuthorStatusFail, 0x10},
		{AuthorStatusError, 0x11},
		{AuthorStatusFollow, 0x21},
	} {
		if c.got != c.want {
			t.Errorf("got %v, want %v", c.got, c.want)
		}
	}
}

func TestAcctFlagConstants(t *testing.T) {
	for _, c := range []struct{ got, want AcctFlag }{
		{AcctFlagStart, 0x02},
		{AcctFlagStop, 0x04},
		{AcctFlagWatchdog, 0x08},
	} {
		if c.got != c.want {
			t.Errorf("got %v, want %v", c.got, c.want)
		}
	}
}

func TestAcctStatusConstants(t *testing.T) {
	for _, c := range []struct{ got, want AcctStatus }{
		{AcctStatusSuccess, 0x01},
		{AcctStatusError, 0x02},
		{AcctStatusFollow, 0x21},
	} {
		if c.got != c.want {
			t.Errorf("got %v, want %v", c.got, c.want)
		}
	}
}

func TestMiscConstants(t *testing.T) {
	t.Run("header length", func(t *testing.T) {
		if HeaderLength != 12 {
			t.Errorf("got %v, want %v", HeaderLength, 12)
		}
	})

	t.Run("default port", func(t *testing.T) {
		if DefaultPort != 49 {
			t.Errorf("got %v, want %v", DefaultPort, 49)
		}
	})

	t.Run("default TLS port (RFC 9887)", func(t *testing.T) {
		if DefaultTLSPort != 300 {
			t.Errorf("got %v, want %v", DefaultTLSPort, 300)
		}
	})

	t.Run("minimum PSK length (RFC 9887)", func(t *testing.T) {
		if MinPSKLength != 16 {
			t.Errorf("got %v, want %v", MinPSKLength, 16)
		}
	})

	t.Run("TLS session ticket key length", func(t *testing.T) {
		if TLSSessionTicketKeyLength != 32 {
			t.Errorf("got %v, want %v", TLSSessionTicketKeyLength, 32)
		}
	})

	t.Run("default max body length", func(t *testing.T) {
		if got := uint32(DefaultMaxBodyLength); got != uint32(256*1024) {
			t.Errorf("got %v, want %v", got, uint32(256*1024))
		}
	})
}
