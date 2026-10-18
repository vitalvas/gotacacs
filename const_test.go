package gotacacs

import (
	"testing"
)

func TestVersionConstants(t *testing.T) {
	t.Run("major version", func(t *testing.T) {
		if got := uint8(MajorVersion); got != uint8(0x0c) {
			t.Errorf("got %v, want %v", got, uint8(0x0c))
		}
	})

	t.Run("minor versions", func(t *testing.T) {
		if got := uint8(MinorVersionDefault); got != uint8(0x00) {
			t.Errorf("got %v, want %v", got, uint8(0x00))
		}
		if got := uint8(MinorVersionOne); got != uint8(0x01) {
			t.Errorf("got %v, want %v", got, uint8(0x01))
		}
	})
}

func TestPacketTypeConstants(t *testing.T) {
	t.Run("packet types", func(t *testing.T) {
		if got := uint8(PacketTypeAuthen); got != uint8(0x01) {
			t.Errorf("got %v, want %v", got, uint8(0x01))
		}
		if got := uint8(PacketTypeAuthor); got != uint8(0x02) {
			t.Errorf("got %v, want %v", got, uint8(0x02))
		}
		if got := uint8(PacketTypeAcct); got != uint8(0x03) {
			t.Errorf("got %v, want %v", got, uint8(0x03))
		}
	})
}

func TestFlagConstants(t *testing.T) {
	t.Run("header flags", func(t *testing.T) {
		if got := uint8(FlagUnencrypted); got != uint8(0x01) {
			t.Errorf("got %v, want %v", got, uint8(0x01))
		}
		if got := uint8(FlagSingleConnect); got != uint8(0x04) {
			t.Errorf("got %v, want %v", got, uint8(0x04))
		}
	})
}

func TestAuthenActionConstants(t *testing.T) {
	t.Run("authentication actions", func(t *testing.T) {
		if got := uint8(AuthenActionLogin); got != uint8(0x01) {
			t.Errorf("got %v, want %v", got, uint8(0x01))
		}
		if got := uint8(AuthenActionChPass); got != uint8(0x02) {
			t.Errorf("got %v, want %v", got, uint8(0x02))
		}
		if got := uint8(AuthenActionSendAuth); got != uint8(0x04) {
			t.Errorf("got %v, want %v", got, uint8(0x04))
		}
	})
}

func TestAuthenTypeConstants(t *testing.T) {
	t.Run("authentication types", func(t *testing.T) {
		if got := uint8(AuthenTypeASCII); got != uint8(0x01) {
			t.Errorf("got %v, want %v", got, uint8(0x01))
		}
		if got := uint8(AuthenTypePAP); got != uint8(0x02) {
			t.Errorf("got %v, want %v", got, uint8(0x02))
		}
		if got := uint8(AuthenTypeCHAP); got != uint8(0x03) {
			t.Errorf("got %v, want %v", got, uint8(0x03))
		}
		if got := uint8(AuthenTypeMSCHAP); got != uint8(0x05) {
			t.Errorf("got %v, want %v", got, uint8(0x05))
		}
		if got := uint8(AuthenTypeMSCHAPV2); got != uint8(0x06) {
			t.Errorf("got %v, want %v", got, uint8(0x06))
		}
	})
}

func TestAuthenServiceConstants(t *testing.T) {
	cases := []struct {
		got  uint8
		want uint8
	}{
		{uint8(AuthenServiceNone), 0x00},
		{uint8(AuthenServiceLogin), 0x01},
		{uint8(AuthenServiceEnable), 0x02},
		{uint8(AuthenServicePPP), 0x03},
		{uint8(AuthenServicePT), 0x05},
		{uint8(AuthenServiceRCMD), 0x06},
		{uint8(AuthenServiceX25), 0x07},
		{uint8(AuthenServiceNASI), 0x08},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("got %v, want %v", c.got, c.want)
		}
	}
}

func TestAuthenStatusConstants(t *testing.T) {
	cases := []struct {
		got  uint8
		want uint8
	}{
		{uint8(AuthenStatusPass), 0x01},
		{uint8(AuthenStatusFail), 0x02},
		{uint8(AuthenStatusGetData), 0x03},
		{uint8(AuthenStatusGetUser), 0x04},
		{uint8(AuthenStatusGetPass), 0x05},
		{uint8(AuthenStatusRestart), 0x06},
		{uint8(AuthenStatusError), 0x07},
		{uint8(AuthenStatusFollow), 0x21},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("got %v, want %v", c.got, c.want)
		}
	}
}

func TestAuthenReplyFlagConstants(t *testing.T) {
	t.Run("authentication reply flags", func(t *testing.T) {
		if got := uint8(AuthenReplyFlagNoEcho); got != uint8(0x01) {
			t.Errorf("got %v, want %v", got, uint8(0x01))
		}
	})
}

func TestAuthenContinueFlagConstants(t *testing.T) {
	t.Run("authentication continue flags", func(t *testing.T) {
		if got := uint8(AuthenContinueFlagAbort); got != uint8(0x01) {
			t.Errorf("got %v, want %v", got, uint8(0x01))
		}
	})
}

func TestAuthenMethodConstants(t *testing.T) {
	t.Run("authentication methods", func(t *testing.T) {
		if got := uint8(AuthenMethodNotSet); got != uint8(0x00) {
			t.Errorf("got %v, want %v", got, uint8(0x00))
		}
		if got := uint8(AuthenMethodNone); got != uint8(0x01) {
			t.Errorf("got %v, want %v", got, uint8(0x01))
		}
		if got := uint8(AuthenMethodKRB5); got != uint8(0x02) {
			t.Errorf("got %v, want %v", got, uint8(0x02))
		}
		if got := uint8(AuthenMethodLine); got != uint8(0x03) {
			t.Errorf("got %v, want %v", got, uint8(0x03))
		}
		if got := uint8(AuthenMethodEnable); got != uint8(0x04) {
			t.Errorf("got %v, want %v", got, uint8(0x04))
		}
		if got := uint8(AuthenMethodLocal); got != uint8(0x05) {
			t.Errorf("got %v, want %v", got, uint8(0x05))
		}
		if got := uint8(AuthenMethodTACACSPlus); got != uint8(0x06) {
			t.Errorf("got %v, want %v", got, uint8(0x06))
		}
		if got := uint8(AuthenMethodGuest); got != uint8(0x08) {
			t.Errorf("got %v, want %v", got, uint8(0x08))
		}
		if got := uint8(AuthenMethodRadius); got != uint8(0x10) {
			t.Errorf("got %v, want %v", got, uint8(0x10))
		}
		if got := uint8(AuthenMethodKRB4); got != uint8(0x11) {
			t.Errorf("got %v, want %v", got, uint8(0x11))
		}
		if got := uint8(AuthenMethodRCMD); got != uint8(0x20) {
			t.Errorf("got %v, want %v", got, uint8(0x20))
		}
	})
}

func TestAuthorStatusConstants(t *testing.T) {
	t.Run("authorization status codes", func(t *testing.T) {
		if got := uint8(AuthorStatusPassAdd); got != uint8(0x01) {
			t.Errorf("got %v, want %v", got, uint8(0x01))
		}
		if got := uint8(AuthorStatusPassRepl); got != uint8(0x02) {
			t.Errorf("got %v, want %v", got, uint8(0x02))
		}
		if got := uint8(AuthorStatusFail); got != uint8(0x10) {
			t.Errorf("got %v, want %v", got, uint8(0x10))
		}
		if got := uint8(AuthorStatusError); got != uint8(0x11) {
			t.Errorf("got %v, want %v", got, uint8(0x11))
		}
		if got := uint8(AuthorStatusFollow); got != uint8(0x21) {
			t.Errorf("got %v, want %v", got, uint8(0x21))
		}
	})
}

func TestAcctFlagConstants(t *testing.T) {
	t.Run("accounting flags", func(t *testing.T) {
		if got := uint8(AcctFlagStart); got != uint8(0x02) {
			t.Errorf("got %v, want %v", got, uint8(0x02))
		}
		if got := uint8(AcctFlagStop); got != uint8(0x04) {
			t.Errorf("got %v, want %v", got, uint8(0x04))
		}
		if got := uint8(AcctFlagWatchdog); got != uint8(0x08) {
			t.Errorf("got %v, want %v", got, uint8(0x08))
		}
	})
}

func TestAcctStatusConstants(t *testing.T) {
	t.Run("accounting status codes", func(t *testing.T) {
		if got := uint8(AcctStatusSuccess); got != uint8(0x01) {
			t.Errorf("got %v, want %v", got, uint8(0x01))
		}
		if got := uint8(AcctStatusError); got != uint8(0x02) {
			t.Errorf("got %v, want %v", got, uint8(0x02))
		}
		if got := uint8(AcctStatusFollow); got != uint8(0x21) {
			t.Errorf("got %v, want %v", got, uint8(0x21))
		}
	})
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
