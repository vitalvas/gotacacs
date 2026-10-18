package gotacacs

import (
	"testing"
)

func TestVersionConstants(t *testing.T) {
	for _, c := range []struct{ got, want uint8 }{
		{uint8(MajorVersion), 0x0c},
		{uint8(MinorVersionDefault), 0x00},
		{uint8(MinorVersionOne), 0x01},
	} {
		if c.got != c.want {
			t.Errorf("got %v, want %v", c.got, c.want)
		}
	}
}

func TestPacketTypeConstants(t *testing.T) {
	for _, c := range []struct{ got, want uint8 }{
		{uint8(PacketTypeAuthen), 0x01},
		{uint8(PacketTypeAuthor), 0x02},
		{uint8(PacketTypeAcct), 0x03},
	} {
		if c.got != c.want {
			t.Errorf("got %v, want %v", c.got, c.want)
		}
	}
}

func TestFlagConstants(t *testing.T) {
	for _, c := range []struct{ got, want uint8 }{
		{uint8(FlagUnencrypted), 0x01},
		{uint8(FlagSingleConnect), 0x04},
	} {
		if c.got != c.want {
			t.Errorf("got %v, want %v", c.got, c.want)
		}
	}
}

func TestAuthenActionConstants(t *testing.T) {
	for _, c := range []struct{ got, want uint8 }{
		{uint8(AuthenActionLogin), 0x01},
		{uint8(AuthenActionChPass), 0x02},
		{uint8(AuthenActionSendAuth), 0x04},
	} {
		if c.got != c.want {
			t.Errorf("got %v, want %v", c.got, c.want)
		}
	}
}

func TestAuthenTypeConstants(t *testing.T) {
	for _, c := range []struct{ got, want uint8 }{
		{uint8(AuthenTypeASCII), 0x01},
		{uint8(AuthenTypePAP), 0x02},
		{uint8(AuthenTypeCHAP), 0x03},
		{uint8(AuthenTypeMSCHAP), 0x05},
		{uint8(AuthenTypeMSCHAPV2), 0x06},
	} {
		if c.got != c.want {
			t.Errorf("got %v, want %v", c.got, c.want)
		}
	}
}

func TestAuthenServiceConstants(t *testing.T) {
	for _, c := range []struct{ got, want uint8 }{
		{uint8(AuthenServiceNone), 0x00},
		{uint8(AuthenServiceLogin), 0x01},
		{uint8(AuthenServiceEnable), 0x02},
		{uint8(AuthenServicePPP), 0x03},
		{uint8(AuthenServicePT), 0x05},
		{uint8(AuthenServiceRCMD), 0x06},
		{uint8(AuthenServiceX25), 0x07},
		{uint8(AuthenServiceNASI), 0x08},
	} {
		if c.got != c.want {
			t.Errorf("got %v, want %v", c.got, c.want)
		}
	}
}

func TestAuthenStatusConstants(t *testing.T) {
	for _, c := range []struct{ got, want uint8 }{
		{uint8(AuthenStatusPass), 0x01},
		{uint8(AuthenStatusFail), 0x02},
		{uint8(AuthenStatusGetData), 0x03},
		{uint8(AuthenStatusGetUser), 0x04},
		{uint8(AuthenStatusGetPass), 0x05},
		{uint8(AuthenStatusRestart), 0x06},
		{uint8(AuthenStatusError), 0x07},
		{uint8(AuthenStatusFollow), 0x21},
	} {
		if c.got != c.want {
			t.Errorf("got %v, want %v", c.got, c.want)
		}
	}
}

func TestAuthenReplyFlagConstants(t *testing.T) {
	got := uint8(AuthenReplyFlagNoEcho)
	if got != 0x01 {
		t.Errorf("got %v, want %v", got, uint8(0x01))
	}
}

func TestAuthenContinueFlagConstants(t *testing.T) {
	got := uint8(AuthenContinueFlagAbort)
	if got != 0x01 {
		t.Errorf("got %v, want %v", got, uint8(0x01))
	}
}

func TestAuthenMethodConstants(t *testing.T) {
	for _, c := range []struct{ got, want uint8 }{
		{uint8(AuthenMethodNotSet), 0x00},
		{uint8(AuthenMethodNone), 0x01},
		{uint8(AuthenMethodKRB5), 0x02},
		{uint8(AuthenMethodLine), 0x03},
		{uint8(AuthenMethodEnable), 0x04},
		{uint8(AuthenMethodLocal), 0x05},
		{uint8(AuthenMethodTACACSPlus), 0x06},
		{uint8(AuthenMethodGuest), 0x08},
		{uint8(AuthenMethodRadius), 0x10},
		{uint8(AuthenMethodKRB4), 0x11},
		{uint8(AuthenMethodRCMD), 0x20},
	} {
		if c.got != c.want {
			t.Errorf("got %v, want %v", c.got, c.want)
		}
	}
}

func TestAuthorStatusConstants(t *testing.T) {
	for _, c := range []struct{ got, want uint8 }{
		{uint8(AuthorStatusPassAdd), 0x01},
		{uint8(AuthorStatusPassRepl), 0x02},
		{uint8(AuthorStatusFail), 0x10},
		{uint8(AuthorStatusError), 0x11},
		{uint8(AuthorStatusFollow), 0x21},
	} {
		if c.got != c.want {
			t.Errorf("got %v, want %v", c.got, c.want)
		}
	}
}

func TestAcctFlagConstants(t *testing.T) {
	for _, c := range []struct{ got, want uint8 }{
		{uint8(AcctFlagStart), 0x02},
		{uint8(AcctFlagStop), 0x04},
		{uint8(AcctFlagWatchdog), 0x08},
	} {
		if c.got != c.want {
			t.Errorf("got %v, want %v", c.got, c.want)
		}
	}
}

func TestAcctStatusConstants(t *testing.T) {
	for _, c := range []struct{ got, want uint8 }{
		{uint8(AcctStatusSuccess), 0x01},
		{uint8(AcctStatusError), 0x02},
		{uint8(AcctStatusFollow), 0x21},
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
