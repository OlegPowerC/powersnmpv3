// PowerSNMPv3 - SNMP library for Go
// Автор: Волков Олег, ООО "Пауэр Си"
// Author: Volkov Oleg, PowerC LLC
// License: MIT (commercial version with support available)
// Лицензия: MIT (доступна коммерческая версия с поддержкой)
package PowerSNMPv3

import (
	"net"
	"sync"
	"sync/atomic"

	ASNber "github.com/OlegPowerC/asn1modsnmp"
)

var SNMPErrorNames = map[int]string{
	sNMP_ErrNoError:                           "NoError",
	sNMP_ErrResponseTooLarge:                  "ResponseTooLarge",
	sNMP_ErrBadOID:                            "BadOID",
	sNMP_ErrBadValue:                          "BadValue",
	sNMP_ErrReadOnly:                          "ReadOnly",
	sNMP_ErrGeneralError:                      "GeneralError",
	sNMP_ErrNoAccess:                          "NoAccess",
	sNMP_ErrWrongType:                         "WrongType",
	sNMP_ErrWrongLength:                       "WrongLength",
	sNMP_ErrWrongEncoding:                     "WrongEncoding",
	sNMP_ErrValueCannotBeAssigned:             "ValueCannotBeAssigned",
	sNMP_ErrCannotCreateVariable:              "CannotCreateVariable",
	sNMP_ErrInconsistentValue:                 "InconsistentValue",
	sNMP_ErrResourcesUnavailable:              "ResourcesUnavailable",
	sNMP_ErrNoVariablesUpdated:                "NoVariablesUpdated",
	sNMP_ErrUndoFailed:                        "UndoFailed",
	sNMP_ErrAuthorizationError:                "AuthorizationError",
	sNMP_ErrNotWritable:                       "NotWritable",
	sNMP_ErrInconsistentName:                  "InconsistentName",
	sNMP_ErrMaxRetriesExceeded:                "MaxRetriesExceeded",
	sNMP_ErrOIDOrSyntaxNotInLocalMIB:          "OIDOrSyntaxNotInLocalMIB",
	sNMP_ErrPortNotConnected:                  "PortNotConnected",
	sNMP_ErrPortIncompatible:                  "PortIncompatible",
	sNMP_ErrPortInvalid:                       "PortInvalid",
	sNMP_ErrNoSuchInstanceAtOID:               "NoSuchInstanceAtOID",
	sNMP_ErrNoSuchObjectAtOID:                 "NoSuchObjectAtOID",
	sNMP_ErrUnknownSNMPVersion:                "UnknownSNMPVersion",
	sNMP_ErrUnknownSNMPSecurityModel:          "UnknownSNMPSecurityModel",
	sNMP_ErrInvalidSecurityFlags:              "InvalidSecurityFlags",
	sNMP_ErrCannotParseIncomingPacket:         "CannotParseIncomingPacket",
	sNMP_ErrCannotEncodeOutgoingPacket:        "CannotEncodeOutgoingPacket",
	sNMP_ErrUnsupportedSecurityLevel:          "UnsupportedSecurityLevel",
	sNMP_ErrMessageNotInTimeWindow:            "MessageNotInTimeWindow",
	sNMP_ErrUnknownUsername:                   "UnknownUsername",
	sNMP_ErrUnknownEngineID:                   "UnknownEngineID",
	sNMP_ErrAuthenticationFailed:              "AuthenticationFailed",
	sNMP_ErrDecryptionFailed:                  "DecryptionFailed",
	sNMP_ErrEncryptionFailed:                  "EncryptionFailed",
	sNMP_ErrResponseParametersMismatch:        "ResponseParametersMismatch",
	sNMP_ErrUnexpectedPDUType:                 "UnexpectedPDUType",
	sNMP_ErrRequestIDMismatch:                 "RequestIDMismatch",
	sNMP_ErrUnexpectedInternalSNMPDriverError: "UnexpectedInternalSNMPDriverError",
	sNMP_ErrNoHandlerForPDU:                   "NoHandlerForPDU",
	sNMP_ErrErrorAddingUserCredentials:        "ErrorAddingUserCredentials",

	//Error in VarBind
	tagandclassERR_noSuchObject:   "NoSuchObject",
	tagandclassERR_noSuchInstance: "NoSuchInstance",
	tagandclassERR_EndOfMib:       "EndOfMib",
}

type SNMPv3_DecodePacket struct {
	Version          int
	GlobalData       SNMPv3_GlobalData
	SecuritySettings SNMPv3_SecSeq
	V3PDU            SNMPv3_DecodedPDU
	MessageType      int
}

type SNMPv2_DecodePacket struct {
	Version     int
	Community   []byte
	V2PDU       SNMP_Packet_V2_decoded_PDU
	MessageType int
}

type SNMP_UnknownVersionPacket struct {
	Version int
	PtData  ASNber.RawValue
}

type SNMPv3_Packet struct {
	Version          int
	GlobalData       ASNber.RawValue
	SecuritySettings []byte //asn1.RawValue
	PtData           ASNber.RawValue
}

type SNMPv3_SecSeq struct {
	AuthEng    []byte
	Boots      int32
	Time       int32
	User       []byte
	AuthParams []byte
	PrivParams []byte
}

type SNMPne_Errors struct {
	Failedoids []PowerSNMPv3_Errors_FailedOids_Error
}

type SNMPwrongReqID_MsgId_Errors struct {
	ErrorStatusCode uint8
}

type SNMPfe_Errors struct {
	ErrorStatusRaw int32
	ErrorIndexRaw  int32
	FailedOID      []int
	RequestType    uint32
}

type SNMPud_OidError struct {
	Failedoid        []int
	Error_id         int32
	ErrorDescription string
}

type SNMPud_Errors struct {
	IsFatal bool
	Oids    []SNMPud_OidError
}

type PowerSNMPv3_Errors_FailedOids_Error struct {
	Failedoid []int
	Error_id  int
}

type SNMPv3_GlobalData struct {
	MsgID            int32
	MsgMaxSize       int
	MsgFlag          []byte
	MsgSecurityModel int
}

type SNMPv3_PDU struct {
	ContextEngineId []byte
	ContextName     []byte
	V2VarBind       ASNber.RawValue
}

type SNMPv3_DecodedPDU struct {
	ContextEngineId []byte
	ContextName     []byte
	V2VarBind       SNMP_Packet_V2_decoded_PDU
}

type SNMP_Packet_V2_PDU struct {
	RequestID      int32
	ErrorStatusRaw int32
	ErrorIndexRaw  int32
	VarBinds       []SNMP_Packet_V2_VarBind
}

// SNMP_Packet_V2_decoded_PDU represents decoded SNMPv2 PDU (RFC3416 §4.1 compliant).
//
// **Unified structure** for ALL SNMPv2 operations: GET/SET/GETBULK/WALK + TRAP/INFORM/REPORT.
// Exact field mapping from BER-decoded PDU: request-id, error-status, error-index, varbind-list.
//
// Fields:
//
//	RequestID      - **UNIQUE identifier** [1..2147483647]
//	                 • GET/SET/INFORM: matches original request
//	                 • TRAP: **unique per trap**
//	                 • RESPONSE: matches request
//	ErrorStatusRaw - Raw SNMP errorStatus (0=noError, 2=noSuchName, 17=notWritable)
//	                 • TRAP/INFORM: **always 0** (ignored)
//	ErrorIndexRaw  - 1-based index of first failed VarBind (0=no errors)
//	                 • TRAP/INFORM: **always 0** (ignored)
//	VarBinds       - Response data (same length/order как input)
//
// **Production usage patterns:**
//
// ```go
// // 1. GET response validation
// resp, err := sess.SNMP_Get(sysDescrOID)
//
//	if resp.ErrorStatusRaw != 0 {
//	    panic(fmt.Sprintf("PDU error %d at index %d",
//	        resp.ErrorStatusRaw, resp.ErrorIndexRaw))
//	}
//
// value := resp.VarBinds  // Guaranteed valid!
//
// // 2. TRAP receiver (RequestID ≠ 0!)
// version, msgType, pdu, _ := ParseTrapWithCredentials(pkt, creds)
// fmt.Printf("TRAP RequestID=%d: %d events\n", pdu.RequestID, len(pdu.VarBinds))
//
// // 3. BulkWalk partial response
// resp, err := sess.SNMP_BulkWalk(ifTableOID)
//
//	if resp.ErrorStatusRaw == 0 {
//	    // All VarBinds valid, process all
//	} else if len(resp.VarBinds) > 0 {
//
//	    // Partial success: process valid + log failed at ErrorIndexRaw
//	}
//
// ```
//
// **Wireshark field mapping (100% точное соответствие):**
// ```
// snmp.request-id     → RequestID
// snmp.error-status   → ErrorStatusRaw
// snmp.error-index    → ErrorIndexRaw
// snmp.varbind-list   → VarBinds
// ```
//
// **Error conditions:**
// • ErrorStatusRaw != 0 → **PDU-level failure**, check ErrorIndexRaw
// • TRAP/INFORM: RequestID=unique, ErrorStatusRaw=0, ErrorIndexRaw=0
// • VarBind exceptions (noSuchObject/endOfMibView) → individual VarBind.Tag
type SNMP_Packet_V2_decoded_PDU struct {
	RequestID      int32
	ErrorStatusRaw int32
	ErrorIndexRaw  int32
	VarBinds       []SNMP_Packet_V2_Decoded_VarBind
}

type SNMP_Packet_V2 struct {
	Version            int
	V2CcommunityString []byte
	V2VarBind          ASNber.RawValue
}

type SNMP_Packet_V2_VarBind struct {
	RSnmpOID ASNber.ObjectIdentifier
	RSnmpVar ASNber.RawValue
}

// SNMP_Packet_V2_Decoded_VarBind represents single SNMP VarBind (OID + Value pair).
//
// **RFC3416 §4.1.2.2** compliant structure: ObjectName + ObjectSyntax.
// Exact 1:1 mapping from BER-decoded VarBind SEQUENCE { ObjectName, ObjectSyntax }.
//
// Fields:
//
//	RSnmpOID - **Raw OID** as ASNber.ObjectIdentifier ([]int):
//	           • Input:  []int{1,3,6,1,2,1,1,1,0} → sysDescr.0
//	           • TRAP:   Unique event OID (linkDown=1.3.6.1.6.3.1.1.5.3)
//	           • WALK:   Lexicographic progression (ifInOctets.1 → .2 → .3)
//	RSnmpVar - Value metadata + raw bytes (see SNMPVar docs)
//
// **Core usage patterns:**
//
// ```go
// // 1. Value extraction helpers (public API)
// oidStr := Convert_OID_IntArrayToString_RAW(vb.RSnmpOID)    // "1.3.6.1.2.1.1.1.0"
// value  := Convert_Variable_To_String(vb.RSnmpVar)          // "Cisco IOS v15.1"
// typ    := Convert_ClassTag_to_String(vb.RSnmpVar)          // "OCTET STRING"
//
// // 2. Type-specific decoding
// if vb.RSnmpVar.ValueClass == 1 && vb.RSnmpVar.ValueType == 1 {  // COUNTER32
//
//	    counter := binary.BigEndian.Uint32(vb.RSnmpVar.Value)
//	}
//
// // 3. Exception handling (walk continuation)
// if vb.RSnmpVar.ValueClass == 2 {  // ContextSpecific
//
//	    switch vb.RSnmpVar.ValueType {
//	    case TAGERR_noSuchObject:    // Continue walk
//	    case TAGERR_noSuchInstance:  // Continue walk
//	    case TAGERR_EndOfMibView:    // Walk END
//	    }
//	}
//
// // 4. TRAP processing
// if oidStr == "1.3.6.1.6.3.1.1.5.3" {  // linkDown
//
//	    ifName := Convert_Variable_To_String(vb.RSnmpVar)  // "GigabitEthernet0/1"
//	}
//
// ```
//
// **Wireshark field mapping:**
// ```
// snmp.name          → RSnmpOID
// snmp.value         → RSnmpVar (Tag+Class+Bytes)
// snmp.value.type    → RSnmpVar.ValueType
// snmp.value.string  → Convert_Variable_To_String(RSnmpVar)
// ```
//
// **Memory layout (zero-allocation):**
// • RSnmpOID:  []int (pointer to BER-decoded subidentifiers)
// • RSnmpVar:  Raw bytes slice (NO copy, direct from packet)
// • **Total: ~32 bytes** per VarBind (scalable to 100k+ objects)
//
// **Production guarantees:**
// • **Order preserved** (input → output 1:1)
// • **Exceptions marked** (noSuchObject в ValueClass=2)
// • **TRAP first VarBind** = snmpTrapOID (mandatory RFC1907)
type SNMP_Packet_V2_Decoded_VarBind struct {
	RSnmpOID ASNber.ObjectIdentifier
	RSnmpVar SNMPVar
}

// SNMPVar represents ASN.1/BER decoded SNMP variable (VarBind value).
//
// **Exact mapping** from ASN.1 Tag byte: [Class:биты7-6][Constructed:бит5][Tag#:биты4-0]
// Contains raw Value bytes (NO auto-decoding) + metadata for type-safe processing.
//
// Fields:
//
//	ValueType  - Tag Number (0-31): INTEGER=2, OCTET STRING=4, OID=6, COUNTER32=1
//	ValueClass - Class (0-3):
//	             • 0=Universal (INTEGER/OCTET/OID/NULL)
//	             • 1=Application (COUNTER32/IPADDR/TIMETICKS)
//	             • 2=ContextSpecific (noSuchObject=0, endOfMibView=2)
//	IsCompound - Constructed flag: true=SEQUENCE/SET, false=primitive
//	Value      - **Raw BER content octets** (NO TLV wrapper, NO decoding):
//	             • INTEGER:     [0x00,0x01,0x2C] → sysUpTime=300
//	             • OCTET:       []byte("Cisco")
//	             • IPADDR:      [192,168,1,1]
//	             • OID:         [0x2B,0x06,0x01,0x02,0x01,0x01] → "1.3.6.1.2.1.1"
//
// **Production usage:**
//
// ```go
// // 1. Type-safe value extraction
//
//	for _, vb := range pdu.VarBinds {
//	    switch vb.RSnmpVar {
//	    case ValueClass==1 && ValueType==1:  // COUNTER32
//	        counter := binary.BigEndian.Uint32(vb.RSnmpVar.Value)
//	    case ValueClass==0 && ValueType==4:  // OCTET STRING
//	        str := string(vb.RSnmpVar.Value)
//	    case ValueClass==1 && ValueType==0:  // IPADDR
//	        ip := net.IP(vb.RSnmpVar.Value).String()
//	    }
//	}
//
// // 2. Human-readable (library helpers)
// fmt.Printf("%s=%s (%s)\n",
//
//	Convert_OID_IntArrayToString_RAW(vb.RSnmpOID),
//	Convert_Variable_To_String(vb.RSnmpVar),
//	Convert_ClassTag_to_String(vb.RSnmpVar))
//
// // 3. Exception detection (ContextSpecific)
// if vb.RSnmpVar.ValueClass == 2 {  // ContextSpecific
//
//	    switch vb.RSnmpVar.ValueType {
//	    case 0: log.Println("noSuchObject")     // Continue walk!
//	    case 1: log.Println("noSuchInstance")   // Continue walk!
//	    case 2: log.Println("endOfMibView")     // Walk complete!
//	    }
//	}
//
// ```
//
// **Raw Value philosophy:**
// • **NO auto-conversion** → 100% type safety
// • **Raw bytes** → user controls decoding (int32/uint64/IP/string)
// • **Wireshark exact** → Value=content octets после TLV stripping
//
// **ASN.1 Tag decoding example:**
// ```
// BER: 41 04 C0 A8 01 01  → Class=1(App), Constructed=0, Tag=0(IPADDR)
//
//	→ SNMPVar{ValueType:0, ValueClass:1, IsCompound:false, Value:}[2]
//
// ```
type SNMPVar struct {
	ValueType  int
	ValueClass int
	IsCompound bool
	Value      []byte
}

var SNMPvbNullValue = SNMPVar{ValueType: ASNber.NullRawValue.Tag}

type NetworkDevice struct {
	IPaddress      string
	Port           int
	SSHusername    string
	SSHPassword    string
	SNMPparameters SNMPUserParameters
	DebugLevel     uint8
}

// Пользовательские данные
type SNMPUserParameters struct {
	SNMPversion      int
	Username         string
	AuthKey          string
	AuthProtocol     string
	PrivKey          string
	PrivProtocol     string
	ContextName      string
	RetryCount       int
	TimeoutBtwRepeat int
	MaxRepetitions   uint16
	MaxMsgSize       uint16
	Community        string
}

// Пользовательские данные
type SNMPTrapParameters struct {
	SNMPversion  int
	Username     string
	AuthKey      string
	AuthProtocol string
	PrivKey      string
	PrivProtocol string
	Community    string
}

type SNMPv3Session struct {
	IPaddress  string
	Port       int
	Debuglevel uint8
	SNMPparams SNMPParameters
	// Для переиспользования сокета
	conn net.Conn
	cmux sync.Mutex
}

// Данные SNMP о текущей сессии SNMP
type SNMPParameters struct {
	//Атомарные переменные
	PrivParameter    uint64
	PrivParameterDes uint32
	MessageId        int32
	MessageIDv2      int32
	RBoots           int32
	RTime            int32
	DataFlag         uint32
	SNMPversion      int
	// Authoritative Engine ID (RFC 3414) - получается через Discovery
	// Используется для генерации локализованных ключей (security)
	EngineID            []byte
	DiscoveredEngineId  atomic.Bool
	DiscoveredTimeBoots atomic.Bool

	Username         string
	AuthKey          string
	AuthProtocol     int
	PrivKey          string
	PrivProtocol     int
	SecurityLevel    int
	LocalizedKeyAuth []byte
	LocalizedKeyPriv []byte
	ContextName      string
	// Context Engine ID (RFC 3412) - для Scoped PDU
	// Обычно совпадает с EngineID, может отличаться при proxy
	ContextEngineId  []byte
	RetryCount       int
	TimeoutBtwRepeat int
	MaxRepetitions   int32
	MaxMsgSize       uint16
	Community        string
}
