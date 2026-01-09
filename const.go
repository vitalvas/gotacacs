package gotacacs

// TACACS+ protocol version constants as defined in RFC8907.
const (
	// MajorVersion is the TACACS+ major version (0x0c).
	MajorVersion = 0x0c

	// MinorVersionDefault is the default minor version.
	MinorVersionDefault = 0x00

	// MinorVersionOne indicates minor version 1.
	MinorVersionOne = 0x01
)

// Packet type constants as defined in RFC8907 Section 4.1.
const (
	// PacketTypeAuthen indicates an authentication packet.
	PacketTypeAuthen = 0x01

	// PacketTypeAuthor indicates an authorization packet.
	PacketTypeAuthor = 0x02

	// PacketTypeAcct indicates an accounting packet.
	PacketTypeAcct = 0x03
)

// Header flag constants as defined in RFC8907 Section 4.1.
const (
	// FlagUnencrypted indicates the packet body is not obfuscated.
	FlagUnencrypted = 0x01

	// FlagSingleConnect indicates the client wants to use single-connection mode.
	FlagSingleConnect = 0x04
)

// Authentication action types as defined in RFC8907 Section 5.1.
const (
	// AuthenActionLogin indicates a login action.
	AuthenActionLogin = 0x01

	// AuthenActionChPass indicates a password change action.
	AuthenActionChPass = 0x02

	// AuthenActionSendAuth indicates a send authentication action.
	AuthenActionSendAuth = 0x04
)

// Authentication types as defined in RFC8907 Section 5.1.
const (
	// AuthenTypeASCII indicates ASCII authentication.
	AuthenTypeASCII = 0x01

	// AuthenTypePAP indicates PAP authentication.
	AuthenTypePAP = 0x02

	// AuthenTypeCHAP indicates CHAP authentication.
	AuthenTypeCHAP = 0x03

	// AuthenTypeMSCHAP indicates MS-CHAP v1 authentication.
	AuthenTypeMSCHAP = 0x05

	// AuthenTypeMSCHAPV2 indicates MS-CHAP v2 authentication.
	AuthenTypeMSCHAPV2 = 0x06
)

// Authentication service types as defined in RFC8907 Section 5.1.
const (
	// AuthenServiceNone indicates no service.
	AuthenServiceNone = 0x00

	// AuthenServiceLogin indicates login service.
	AuthenServiceLogin = 0x01

	// AuthenServiceEnable indicates enable service.
	AuthenServiceEnable = 0x02

	// AuthenServicePPP indicates PPP service.
	AuthenServicePPP = 0x03

	// AuthenServicePT indicates PT service.
	AuthenServicePT = 0x05

	// AuthenServiceRCMD indicates RCMD service.
	AuthenServiceRCMD = 0x06

	// AuthenServiceX25 indicates X25 service.
	AuthenServiceX25 = 0x07

	// AuthenServiceNASI indicates NASI service.
	AuthenServiceNASI = 0x08
)

// Authentication status codes as defined in RFC8907 Section 5.2.
const (
	// AuthenStatusPass indicates authentication passed.
	AuthenStatusPass = 0x01

	// AuthenStatusFail indicates authentication failed.
	AuthenStatusFail = 0x02

	// AuthenStatusGetData indicates server needs more data.
	AuthenStatusGetData = 0x03

	// AuthenStatusGetUser indicates server needs the username.
	AuthenStatusGetUser = 0x04

	// AuthenStatusGetPass indicates server needs the password.
	AuthenStatusGetPass = 0x05

	// AuthenStatusRestart indicates authentication should restart.
	AuthenStatusRestart = 0x06

	// AuthenStatusError indicates an error occurred.
	AuthenStatusError = 0x07

	// AuthenStatusFollow indicates the client should follow to another server.
	AuthenStatusFollow = 0x21
)

// Authentication reply flags as defined in RFC8907 Section 5.2.
const (
	// AuthenReplyFlagNoEcho indicates the server wants no echo of user input.
	AuthenReplyFlagNoEcho = 0x01
)

// Authentication continue flags as defined in RFC8907 Section 5.3.
const (
	// AuthenContinueFlagAbort indicates the client wants to abort authentication.
	AuthenContinueFlagAbort = 0x01
)

// Authorization status codes as defined in RFC8907 Section 6.2.
const (
	// AuthorStatusPassAdd indicates authorization passed with additional arguments.
	AuthorStatusPassAdd = 0x01

	// AuthorStatusPassRepl indicates authorization passed with replacement arguments.
	AuthorStatusPassRepl = 0x02

	// AuthorStatusFail indicates authorization failed.
	AuthorStatusFail = 0x10

	// AuthorStatusError indicates an error occurred.
	AuthorStatusError = 0x11

	// AuthorStatusFollow indicates the client should follow to another server.
	AuthorStatusFollow = 0x21
)

// Accounting flags as defined in RFC8907 Section 7.1.
const (
	// AcctFlagStart indicates the start of a task.
	AcctFlagStart = 0x02

	// AcctFlagStop indicates the end of a task.
	AcctFlagStop = 0x04

	// AcctFlagWatchdog indicates an update for an ongoing task.
	AcctFlagWatchdog = 0x08
)

// Accounting status codes as defined in RFC8907 Section 7.2.
const (
	// AcctStatusSuccess indicates the accounting record was accepted.
	AcctStatusSuccess = 0x01

	// AcctStatusError indicates an error occurred.
	AcctStatusError = 0x02

	// AcctStatusFollow indicates the client should follow to another server.
	AcctStatusFollow = 0x21
)

// HeaderLength is the fixed size of a TACACS+ header in bytes.
const HeaderLength = 12

// DefaultPort is the default TACACS+ port as defined in RFC8907.
const DefaultPort = 49

// MaxBodyLength is the maximum body length (2^32 - 1 bytes).
const MaxBodyLength = 0xFFFFFFFF
