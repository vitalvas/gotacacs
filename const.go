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

// Authentication method constants as defined in RFC8907 Section 6.1.
// These indicate how the user was authenticated in authorization/accounting requests.
const (
	// AuthenMethodNotSet indicates the authentication method was not set.
	AuthenMethodNotSet = 0x00

	// AuthenMethodNone indicates no authentication was performed.
	AuthenMethodNone = 0x01

	// AuthenMethodKRB5 indicates Kerberos 5 authentication.
	AuthenMethodKRB5 = 0x02

	// AuthenMethodLine indicates line authentication (e.g., console password).
	AuthenMethodLine = 0x03

	// AuthenMethodEnable indicates enable authentication.
	AuthenMethodEnable = 0x04

	// AuthenMethodLocal indicates local database authentication.
	AuthenMethodLocal = 0x05

	// AuthenMethodTACACSPlus indicates TACACS+ authentication.
	AuthenMethodTACACSPlus = 0x06

	// AuthenMethodGuest indicates guest authentication.
	AuthenMethodGuest = 0x08

	// AuthenMethodRadius indicates RADIUS authentication.
	AuthenMethodRadius = 0x10

	// AuthenMethodKRB4 indicates Kerberos 4 authentication.
	AuthenMethodKRB4 = 0x11

	// AuthenMethodRCMD indicates RCMD authentication.
	AuthenMethodRCMD = 0x20
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

// DefaultTLSPort is the default TACACS+ over TLS port as defined in RFC9887.
// RFC 9887 specifies port 300 for TLS-secured TACACS+ connections (service name "tacacss").
const DefaultTLSPort = 300

// MinPSKLength is the minimum Pre-Shared Key length required by RFC 9887.
// RFC 9887 specifies a minimum of 16 octets for PSK.
const MinPSKLength = 16

// TLSSessionTicketKeyLength is the required length for TLS session ticket keys.
// Go's TLS implementation requires 32 bytes for session ticket keys.
const TLSSessionTicketKeyLength = 32

// DefaultMaxBodyLength is the default maximum allowed body length (256KB).
// This prevents memory exhaustion attacks from malicious peers.
const DefaultMaxBodyLength = 256 * 1024
