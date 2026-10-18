package gotacacs

// Version is the TACACS+ protocol version byte (major nibble << 4 | minor nibble).
type Version uint8

// TACACS+ protocol version constants as defined in RFC8907.
const (
	// MajorVersion is the TACACS+ major version (0x0c).
	MajorVersion Version = 0x0c

	// MinorVersionDefault is the default minor version.
	MinorVersionDefault Version = 0x00

	// MinorVersionOne indicates minor version 1.
	MinorVersionOne Version = 0x01
)

// PacketType identifies the kind of TACACS+ packet.
type PacketType uint8

// Packet type constants as defined in RFC8907 Section 4.1.
const (
	// PacketTypeAuthen indicates an authentication packet.
	PacketTypeAuthen PacketType = 0x01

	// PacketTypeAuthor indicates an authorization packet.
	PacketTypeAuthor PacketType = 0x02

	// PacketTypeAcct indicates an accounting packet.
	PacketTypeAcct PacketType = 0x03
)

// HeaderFlag is a TACACS+ header flag bitmask.
type HeaderFlag uint8

// Header flag constants as defined in RFC8907 Section 4.1.
const (
	// FlagUnencrypted indicates the packet body is not obfuscated.
	FlagUnencrypted HeaderFlag = 0x01

	// FlagSingleConnect indicates the client wants to use single-connection mode.
	FlagSingleConnect HeaderFlag = 0x04
)

// AuthenAction is a TACACS+ authentication action.
type AuthenAction uint8

// Authentication action types as defined in RFC8907 Section 5.1.
const (
	// AuthenActionLogin indicates a login action.
	AuthenActionLogin AuthenAction = 0x01

	// AuthenActionChPass indicates a password change action.
	AuthenActionChPass AuthenAction = 0x02

	// AuthenActionSendAuth indicates a send authentication action.
	AuthenActionSendAuth AuthenAction = 0x04
)

// AuthenType is a TACACS+ authentication type.
type AuthenType uint8

// Authentication types as defined in RFC8907 Section 5.1.
const (
	// AuthenTypeASCII indicates ASCII authentication.
	AuthenTypeASCII AuthenType = 0x01

	// AuthenTypePAP indicates PAP authentication.
	AuthenTypePAP AuthenType = 0x02

	// AuthenTypeCHAP indicates CHAP authentication.
	AuthenTypeCHAP AuthenType = 0x03

	// AuthenTypeMSCHAP indicates MS-CHAP v1 authentication.
	AuthenTypeMSCHAP AuthenType = 0x05

	// AuthenTypeMSCHAPV2 indicates MS-CHAP v2 authentication.
	AuthenTypeMSCHAPV2 AuthenType = 0x06
)

// AuthenService is a TACACS+ authentication service.
type AuthenService uint8

// Authentication service types as defined in RFC8907 Section 5.1.
const (
	// AuthenServiceNone indicates no service.
	AuthenServiceNone AuthenService = 0x00

	// AuthenServiceLogin indicates login service.
	AuthenServiceLogin AuthenService = 0x01

	// AuthenServiceEnable indicates enable service.
	AuthenServiceEnable AuthenService = 0x02

	// AuthenServicePPP indicates PPP service.
	AuthenServicePPP AuthenService = 0x03

	// AuthenServicePT indicates PT service.
	AuthenServicePT AuthenService = 0x05

	// AuthenServiceRCMD indicates RCMD service.
	AuthenServiceRCMD AuthenService = 0x06

	// AuthenServiceX25 indicates X25 service.
	AuthenServiceX25 AuthenService = 0x07

	// AuthenServiceNASI indicates NASI service.
	AuthenServiceNASI AuthenService = 0x08
)

// AuthenStatus is a TACACS+ authentication status code.
type AuthenStatus uint8

// Authentication status codes as defined in RFC8907 Section 5.2.
const (
	// AuthenStatusPass indicates authentication passed.
	AuthenStatusPass AuthenStatus = 0x01

	// AuthenStatusFail indicates authentication failed.
	AuthenStatusFail AuthenStatus = 0x02

	// AuthenStatusGetData indicates server needs more data.
	AuthenStatusGetData AuthenStatus = 0x03

	// AuthenStatusGetUser indicates server needs the username.
	AuthenStatusGetUser AuthenStatus = 0x04

	// AuthenStatusGetPass indicates server needs the password.
	AuthenStatusGetPass AuthenStatus = 0x05

	// AuthenStatusRestart indicates authentication should restart.
	AuthenStatusRestart AuthenStatus = 0x06

	// AuthenStatusError indicates an error occurred.
	AuthenStatusError AuthenStatus = 0x07

	// AuthenStatusFollow indicates the client should follow to another server.
	AuthenStatusFollow AuthenStatus = 0x21
)

// AuthenReplyFlag is a TACACS+ authentication reply flag bitmask.
type AuthenReplyFlag uint8

// Authentication reply flags as defined in RFC8907 Section 5.2.
const (
	// AuthenReplyFlagNoEcho indicates the server wants no echo of user input.
	AuthenReplyFlagNoEcho AuthenReplyFlag = 0x01
)

// AuthenContinueFlag is a TACACS+ authentication continue flag bitmask.
type AuthenContinueFlag uint8

// Authentication continue flags as defined in RFC8907 Section 5.3.
const (
	// AuthenContinueFlagAbort indicates the client wants to abort authentication.
	AuthenContinueFlagAbort AuthenContinueFlag = 0x01
)

// AuthenMethod is a TACACS+ authentication method.
type AuthenMethod uint8

// Authentication method constants as defined in RFC8907 Section 6.1.
// These indicate how the user was authenticated in authorization/accounting requests.
const (
	// AuthenMethodNotSet indicates the authentication method was not set.
	AuthenMethodNotSet AuthenMethod = 0x00

	// AuthenMethodNone indicates no authentication was performed.
	AuthenMethodNone AuthenMethod = 0x01

	// AuthenMethodKRB5 indicates Kerberos 5 authentication.
	AuthenMethodKRB5 AuthenMethod = 0x02

	// AuthenMethodLine indicates line authentication (e.g., console password).
	AuthenMethodLine AuthenMethod = 0x03

	// AuthenMethodEnable indicates enable authentication.
	AuthenMethodEnable AuthenMethod = 0x04

	// AuthenMethodLocal indicates local database authentication.
	AuthenMethodLocal AuthenMethod = 0x05

	// AuthenMethodTACACSPlus indicates TACACS+ authentication.
	AuthenMethodTACACSPlus AuthenMethod = 0x06

	// AuthenMethodGuest indicates guest authentication.
	AuthenMethodGuest AuthenMethod = 0x08

	// AuthenMethodRadius indicates RADIUS authentication.
	AuthenMethodRadius AuthenMethod = 0x10

	// AuthenMethodKRB4 indicates Kerberos 4 authentication.
	AuthenMethodKRB4 AuthenMethod = 0x11

	// AuthenMethodRCMD indicates RCMD authentication.
	AuthenMethodRCMD AuthenMethod = 0x20
)

// AuthorStatus is a TACACS+ authorization status code.
type AuthorStatus uint8

// Authorization status codes as defined in RFC8907 Section 6.2.
const (
	// AuthorStatusPassAdd indicates authorization passed with additional arguments.
	AuthorStatusPassAdd AuthorStatus = 0x01

	// AuthorStatusPassRepl indicates authorization passed with replacement arguments.
	AuthorStatusPassRepl AuthorStatus = 0x02

	// AuthorStatusFail indicates authorization failed.
	AuthorStatusFail AuthorStatus = 0x10

	// AuthorStatusError indicates an error occurred.
	AuthorStatusError AuthorStatus = 0x11

	// AuthorStatusFollow indicates the client should follow to another server.
	AuthorStatusFollow AuthorStatus = 0x21
)

// AcctFlag is a TACACS+ accounting flag bitmask.
type AcctFlag uint8

// Accounting flags as defined in RFC8907 Section 7.1.
const (
	// AcctFlagStart indicates the start of a task.
	AcctFlagStart AcctFlag = 0x02

	// AcctFlagStop indicates the end of a task.
	AcctFlagStop AcctFlag = 0x04

	// AcctFlagWatchdog indicates an update for an ongoing task.
	AcctFlagWatchdog AcctFlag = 0x08
)

// AcctStatus is a TACACS+ accounting status code.
type AcctStatus uint8

// Accounting status codes as defined in RFC8907 Section 7.2.
const (
	// AcctStatusSuccess indicates the accounting record was accepted.
	AcctStatusSuccess AcctStatus = 0x01

	// AcctStatusError indicates an error occurred.
	AcctStatusError AcctStatus = 0x02

	// AcctStatusFollow indicates the client should follow to another server.
	AcctStatusFollow AcctStatus = 0x21
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
