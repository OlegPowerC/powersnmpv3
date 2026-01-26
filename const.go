// PowerSNMPv3 - SNMP library for Go
// Автор: Волков Олег, ООО "Пауэр Си"
// Author: Volkov Oleg, PowerC LLC
// License: MIT (commercial version with support available)
// Лицензия: MIT (доступна коммерческая версия с поддержкой)
package PowerSNMPv3

// ASN.1/BER tag encoding constants.
// Bits 7-6: Class (Universal=00, Application=01, Context=10, Private=11)
// Bit 5: Constructed flag (0=primitive, 1=constructed/compound like SEQUENCE)
// Bits 4-0: Tag Number
//
// Example: Class=0x01 (Application), Tag=0x03 → 0x43 (APPLICATION 3 = SNMP TIMETICKS)

const (
	// SNMP Application Types (Class=1)
	SNMP_type_IPADDR    = 0
	SNMP_type_COUNTER32 = 1
	SNMP_type_GAUGE32   = 2
	SNMP_type_TIMETICKS = 3
	SNMP_type_OPAQUE    = 4
	SNMP_type_COUNTER64 = 6

	// Limits & Defaults
	SNMP_MAXIMUMWALK              = 1000000
	SNMP_BUFFERSIZE               = 65535
	SNMP_MAXTIMEOUT_MS            = 1000
	SNMP_DEFAULTTIMEOUT_MS        = 300
	SNMP_MAXIMUM_RETRY            = 10
	SNMP_DEFAULTRETRY             = 3
	SNMP_MAXREPETITION     uint16 = 80
	SNMP_DEFAULTREPETITION uint16 = 25
	SNMP_MAXMSGSIZE        uint16 = 65535
	SNMP_DEFAULTMSGSITE    uint16 = 1360
	SNMP_MINMSGSITE        uint16 = 500

	// SNMPv2 Exception Tags (ContextSpecific)
	tagERR_noSuchObject           = 0
	tagandclassERR_noSuchObject   = 0x80
	tagERR_noSuchInstance         = 1
	tagandclassERR_noSuchInstance = 0x81
	tagERR_EndOfMib               = 2
	tagandclassERR_EndOfMib       = 0x82
)

const (
	// SNMPv3 Message Flags (msgFlags byte)
	msgFlag_Reportable_Bit    = 2
	msgFlag_Encrypted_Bit     = 1
	msgFlag_Authenticated_Bit = 0
)

const (
	// SNMPv3 Security Models
	msgSecurityModel_USM = 3
)

const (
	// SNMPv2 PDU Types (RFC3416)
	SNMPv2_REQUEST_GET      = 0
	SNMPv2_REQUEST_GETNEXT  = 1
	SNMPv2_REQUEST_RESPONSE = 2
	SNMPv2_REQUEST_SET      = 3
	SNMPv2_REQUEST_GETBULK  = 5
)

const (
	// SNMPv3 USM Authentication Protocols
	AUTH_PROTOCOL_NONE   = 0
	AUTH_PROTOCOL_MD5    = 1
	AUTH_PROTOCOL_SHA    = 2
	AUTH_PROTOCOL_SHA224 = 3
	AUTH_PROTOCOL_SHA256 = 4
	AUTH_PROTOCOL_SHA384 = 5
	AUTH_PROTOCOL_SHA512 = 6
)

const (
	// SNMPv3 USM Privacy Protocols
	PRIV_PROTOCOL_NONE    = 0
	PRIV_PROTOCOL_AES128  = 1
	PRIV_PROTOCOL_DES     = 2
	PRIV_PROTOCOL_AES192  = 3
	PRIV_PROTOCOL_AES256  = 4
	PRIV_PROTOCOL_AES192A = 5
	PRIV_PROTOCOL_AES256A = 6
)

const (
	// SNMPv3 Security Levels (RFC3411)
	SECLEVEL_NOAUTH_NOPRIV = 0
	SECLEVEL_AUTHNOPRIV    = 1
	SECLEVEL_AUTHPRIV      = 2
)

const (
	// SNMP Notification Types
	REPORT_MESSAGE = 1
	TRAP_MESSAGE   = 2
	INFORM_MESSAGE = 3
)

const (
	// Internal Parser Errors
	PARCE_ERR_WRONGMSGID = 0xf1
	PARCE_ERR_WRONGREQID = 0xf2
)

const (
	// SNMP Error Status Codes (RFC3416 §4.1.2.1 + USM/RFC3826)
	sNMP_ErrNoError                    = 0x00
	sNMP_ErrResponseTooLarge           = 0x01
	sNMP_ErrBadOID                     = 0x02
	sNMP_ErrBadValue                   = 0x03
	sNMP_ErrReadOnly                   = 0x04
	sNMP_ErrGeneralError               = 0x05
	sNMP_ErrNoAccess                   = 0x06
	sNMP_ErrWrongType                  = 0x07
	sNMP_ErrWrongLength                = 0x08
	sNMP_ErrWrongEncoding              = 0x09
	sNMP_ErrValueCannotBeAssigned      = 0x0A
	sNMP_ErrCannotCreateVariable       = 0x0B
	sNMP_ErrInconsistentValue          = 0x0C
	sNMP_ErrResourcesUnavailable       = 0x0D
	sNMP_ErrNoVariablesUpdated         = 0x0E
	sNMP_ErrUndoFailed                 = 0x0F
	sNMP_ErrAuthorizationError         = 0x10
	sNMP_ErrNotWritable                = 0x11
	sNMP_ErrInconsistentName           = 0x12
	sNMP_ErrMaxRetriesExceeded         = 0x13
	sNMP_ErrOIDOrSyntaxNotInLocalMIB   = 0x14
	sNMP_ErrPortNotConnected           = 0x15
	sNMP_ErrPortIncompatible           = 0x16
	sNMP_ErrPortInvalid                = 0x17
	sNMP_ErrNoSuchInstanceAtOID        = 0x18
	sNMP_ErrNoSuchObjectAtOID          = 0x19
	sNMP_ErrUnknownSNMPVersion         = 0x1A
	sNMP_ErrUnknownSNMPSecurityModel   = 0x1B
	sNMP_ErrInvalidSecurityFlags       = 0x1C
	sNMP_ErrCannotParseIncomingPacket  = 0x1D
	sNMP_ErrCannotEncodeOutgoingPacket = 0x1E
	// USM/RFC3826 Errors (ScopedPDU level)
	sNMP_ErrUnsupportedSecurityLevel = 0x1F
	sNMP_ErrMessageNotInTimeWindow   = 0x20
	sNMP_ErrUnknownUsername          = 0x21
	sNMP_ErrUnknownEngineID          = 0x22
	sNMP_ErrAuthenticationFailed     = 0x23
	sNMP_ErrDecryptionFailed         = 0x24
	sNMP_ErrEncryptionFailed         = 0x25

	sNMP_ErrResponseParametersMismatch        = 0x26
	sNMP_ErrUnexpectedPDUType                 = 0x27
	sNMP_ErrRequestIDMismatch                 = 0x28
	sNMP_ErrUnexpectedInternalSNMPDriverError = 0x29
	sNMP_ErrNoHandlerForPDU                   = 0x2A
	sNMP_ErrErrorAddingUserCredentials        = 0x2B
)
