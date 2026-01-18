package PowerSNMPv3

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	ASNber "github.com/OlegPowerC/asn1modsnmp"
)

func divmod(numerator, denominator int) (quotient, remainder int) {
	quotient = numerator / denominator
	remainder = numerator % denominator
	return
}

// Convert_OID_StringToIntArray converts OID string to BER-encoded int array.
//
// Handles both decimal OID strings and subidentifier encoding (>127 → 2x uint8).
// Used by SNMPv3 BER encoders for packet construction.
//
// Arguments:
//
//	OIDStr - "1.3.6.1.2.1.1.1" or "1.3.6.1.4.1.9.9.91.1.1.1.1"
//
// Returns:
//
//	[]int  - BER subidentifiers (128→[0x81,0], 150→[0x82,22])
//	error  - strconv.Atoi failures
//
// BER encoding (RFC2578 §7.2):
//   - 0-127     → single uint8
//   - 128-16383 → 0x81-N + mod128
//
// Examples:
//
//	"1.3.6.1.2.1" → [1,3,6,1,2,1]
//	"1.3.6.1.4.1.9.9.129.1" → [1,3,6,1,4,1,9,9,129→[0x81,1],1]
func Convert_OID_StringToIntArray(OIDStr string) (OIDIntArray []int, err error) {
	OIDStr = strings.Trim(OIDStr, ".")
	OIDStringArray := strings.Split(OIDStr, ".")
	var RetArray []int
	var IntPm_div, IntPm_mod int
	for _, OidStringVal := range OIDStringArray {
		OidIntVal, OidElement_Error_Conversion := strconv.Atoi(OidStringVal)
		if OidElement_Error_Conversion != nil {
			return RetArray, OidElement_Error_Conversion
		} else {
			if OidIntVal >= 0x80 {
				IntPm_div, IntPm_mod = divmod(OidIntVal, 128)
				IntPm_div += 0x80
				RetArray = append(RetArray, IntPm_div)
				RetArray = append(RetArray, IntPm_mod)
			} else {
				RetArray = append(RetArray, OidIntVal)
			}
		}
	}
	return RetArray, nil
}

// Convert_OID_StringToIntArray_RAW converts OID string to raw decimal int array.
//
// Direct decimal parsing WITHOUT BER subidentifier encoding (>127 stays single int).
// Used for SNMP API calls, InSubTreeCheck(), lexicographic comparisons.
//
// Arguments:
//
//	OIDStr - "1.3.6.1.2.1.1.1" or "1.3.6.1.4.1.9.9.129.1"
//
// Returns:
//
//	[]int  - Raw decimals [1,3,6,1,4,1,9,9,129,1]
//	error  - strconv.Atoi failures
//
// vs Convert_OID_StringToIntArray():
//
//	| Input      | RAW           | BER Encoded       |
//	|------------|---------------|-------------------|
//	| "1.3.6.129"| [1,3,6,129]  | [1,3,6,0x81,1]   |
//	| "1.3.6.1"  | [1,3,6,1]    | [1,3,6,1]        |
//
// SNMP Walk/BulkWalk API usage:
//
//	ifTableOID, _ := Convert_OID_StringToIntArray_RAW("1.3.6.1.2.1.2.2.1")
//	results, _ := sess.SNMP_BulkWalk(ifTableOID)
func Convert_OID_StringToIntArray_RAW(OIDStr string) (OIDIntArray []int, err error) {
	OIDStr = strings.Trim(OIDStr, ".")
	OIDStringArray := strings.Split(OIDStr, ".")
	var RetArray []int
	for _, OidStringVal := range OIDStringArray {
		OidIntVal, OidElement_Error_Conversion := strconv.Atoi(OidStringVal)
		if OidElement_Error_Conversion != nil {
			return RetArray, OidElement_Error_Conversion
		} else {
			RetArray = append(RetArray, OidIntVal)
		}
	}
	return RetArray, nil
}

// Convert_OID_IntArrayToString_RAW - INTERNAL utility. Raw OID array → dotted string.
//
// **NOT for API calls!** Use ONLY for logging, JSON export, fmt.Printf(), debugging.
// SNMP Walk/BulkWalk/Get accept []int ONLY - this is visualization helper.
//
// Args:
//
//	OIDIntArray - [1,3,6,1,2,1,2,2,1,2,1]
//
// Returns:
//
//	"1.3.6.1.2.1.2.2.1.2.1"
func Convert_OID_IntArrayToString_RAW(OIDIntArray []int) (OIDStr string) {
	RetStr := ""
	for varind, val := range OIDIntArray {
		RetStr += strconv.Itoa(val)
		if varind < len(OIDIntArray)-1 {
			RetStr += "."
		}
	}
	return RetStr
}

// Convert_OID_IntArrayToString - INTERNAL. BER-encoded OID array → human-readable string.
//
// **NOT for API calls!** Decodes subidentifiers (>127) back to decimal.
// SNMP Walk/BulkWalk/Get accept []int ONLY.
//
// Args:
//
//	OIDIntArray - BER encoded [1,3,6,1,4,1,0x81,1,1]  (129→[0x81,1])
//
// Returns:
//
//	"1.3.6.1.4.1.129.1.1"
//
// BER decoding (RFC2578 §7.2):
//   - 0x81,1 → 129
//   - 0-127 → single decimal
//   - 0x2b (first) → "1.3" (ITU T.1 encoding)
//
// vs Convert_OID_IntArrayToString_RAW():
//
//	| BER Input     | This       | RAW         |
//	|---------------|------------|-------------|
//	| [1,3,0x81,1] | "1.3.129" | "1.3.129.1" |
//	| [1,3,6,1]    | "1.3.6.1" | "1.3.6.1"   |
func Convert_OID_IntArrayToString(OIDIntArray []int) (OIDStr string) {
	RetStr := ""
	IntPmFirstByte := 0
	largevalue := false
	for varind, val := range OIDIntArray {
		if val >= 0x80 {
			IntPmFirstByte = IntPmFirstByte * 128
			IntPmFirstByte = IntPmFirstByte + ((val - 0x80) * 128)
			largevalue = true
			continue
		}
		//Тут значение уже меньше 0x80 но если предыдущие были больше то это последний байт в мультибайтовом значении ASN.1
		if largevalue {
			pmdatafull := IntPmFirstByte + val
			RetStr += strconv.Itoa(pmdatafull)
			largevalue = false
		} else {
			//первый байт 0x2b (43) заменяется на 1.3
			if varind == 0 && val == 0x2b {
				RetStr += "1.3"
			} else {
				RetStr += strconv.Itoa(val)
			}
		}
		IntPmFirstByte = 0
		if varind < len(OIDIntArray)-1 {
			RetStr += "."
		}
	}
	return RetStr
}

// Convert_bytearray_to_intarray - INTERNAL. []byte → []int zero-copy cast.
//
// Simple uint8→int conversion. NO BER decoding. Used before full BER processing.
func Convert_bytearray_to_intarray(bytearray []byte) (intarray []int) {
	retvar := make([]int, 0)
	for _, val := range bytearray {
		retvar = append(retvar, int(val))
	}
	return retvar
}

// Convert_bytearray_to_intarray_with_multibyte_data - INTERNAL. BER byte stream → decoded OID.
//
// **REAL BER DECODING!** Converts raw BER bytes with multi-byte subidentifiers (>127) to decimal.
// Used by SNMPv3 packet decoders for complete OID reconstruction.
//
// Args:
//
//	bytearray - Raw BER [0x01,0x03,0x81,0x01,0x02]
//
// Returns:
//
//	[]int     - [1,3,129,2] (0x81,0x01 → 129 decoded)
//
// BER decoding (RFC2578 §7.2):
//   - 0x81,0x01 → (0x81-0x80)*128 + 0x01 = 129
//   - 0x00-0x7F → single byte value
//
// Pipeline:
//
//	packet[oidOffset:] → []byte → THIS → []int → Walk/BulkWalk validation
//
// vs simple cast:
//
//	| BER Input    | Simple Cast     | This (Decoded) |
//	|--------------|-----------------|----------------|
//	| [0x81,0x01] | [129,1]        | [129]         |
//	| [0x01,0x03] | [1,3]          | [1,3]         |
func Convert_bytearray_to_intarray_with_multibyte_data(bytearray []byte) (intarray []int) {
	retvar := make([]int, 0)
	multibyte_val := 0
	ivaltoa := 0
	largevalue := false
	for _, val := range bytearray {
		if val >= 0x80 {
			multibyte_val = multibyte_val * 128
			multibyte_val = multibyte_val + ((int(val) - 0x80) * 128)
			largevalue = true
			continue
		}
		//Тут значение уже меньше 0x80 но если предыдущие были больше то это последний байт в мультибайтовом значении ASN.1
		if largevalue {
			pmdatafull := multibyte_val + int(val)
			ivaltoa = pmdatafull
			largevalue = false
		} else {
			ivaltoa = int(val)
		}
		multibyte_val = 0
		retvar = append(retvar, ivaltoa)
	}
	return retvar
}

// Convert_snmpint_to_int32 - INTERNAL. SNMP INTEGER value bytes → int32.
//
// **NO BER decoding** - ASN.1 parser already stripped TLV.
// Pure BigEndian conversion of raw INTEGER content octets (1-4 bytes).
//
// Usage: sysUpTime.0 → [0x00,0x01,0x2C] → 300
func Convert_snmpint_to_int32(bytearray []byte) (intdata int32) {
	bytearray32 := []byte{0, 0, 0, 0}
	switch len(bytearray) {
	case 1:
		return int32(int8(bytearray[0]))
	case 2:
		return int32(int16(binary.BigEndian.Uint16(bytearray)))
	case 3:
		copy(bytearray32[1:], bytearray)
		return int32(binary.BigEndian.Uint32(bytearray32))
	case 4:
		return int32(binary.BigEndian.Uint32(bytearray))
	default:
		return 0
	}
}

// Convert_snmpint_to_uint32 - INTERNAL. SNMP unsigned INTEGER → uint32.
//
// **NO BER decoding** - ASN.1 parser already stripped TLV.
// Pure BigEndian conversion of raw Counter32/Gauge32 content (1-4 bytes).
//
// Usage: ifInOctets → [0x00,0xFF,0xFF,0xFF] → 16777215
func Convert_snmpint_to_uint32(bytearray []byte) (intdata uint32) {
	bytearray32 := []byte{0, 0, 0, 0}
	switch len(bytearray) {
	case 1:
		return uint32(bytearray[0])
	case 2:
		return uint32(binary.BigEndian.Uint16(bytearray))
	case 3:
		copy(bytearray32[1:], bytearray)
		return binary.BigEndian.Uint32(bytearray32)
	case 4:
		return binary.BigEndian.Uint32(bytearray)
	default:
		return 0
	}
}

// Convert_bytearray_to_int - INTERNAL. SNMP signed INTEGER → int64 (1-8 bytes).
//
// **NO BER decoding** - ASN.1 parser stripped TLV. Full BigEndian + sign extension.
// Handles all SNMP INTEGER sizes: sysUpTime, ifHCInOctets, Timeticks.
//
// Usage: ifHCInOctets → [0x00,0x00,0x00,0x01,0xFF,0xFF,0xFF,0xFF] → 4294967295
func Convert_bytearray_to_int(bytearray []byte) (intdata int64) {
	bytearray32 := []byte{0, 0, 0, 0}
	bytearray64 := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	switch len(bytearray) {
	case 1:
		return int64(int8(bytearray[0]))
	case 2:
		return int64(int16(binary.BigEndian.Uint16(bytearray)))
	case 3:
		copy(bytearray32[1:], bytearray)
		return int64(int32(binary.BigEndian.Uint32(bytearray32)))
	case 4:
		return int64(int32(binary.BigEndian.Uint32(bytearray)))
	case 5:
		copy(bytearray64[3:], bytearray)
		return int64(binary.BigEndian.Uint64(bytearray64))
	case 6:
		copy(bytearray64[2:], bytearray)
		return int64(binary.BigEndian.Uint64(bytearray64))
	case 7:
		copy(bytearray64[1:], bytearray)
		return int64(binary.BigEndian.Uint64(bytearray64))
	case 8:
		return int64(binary.BigEndian.Uint64(bytearray))
	default:
		return 0
	}
}

// Convert_bytearray_to_uint - INTERNAL. SNMP unsigned INTEGER → uint64 (1-8 bytes).
//
// **NO BER decoding** - ASN.1 parser stripped TLV. Full BigEndian unsigned conversion.
// Handles Counter64, ifHCInOctets, Gauge64, Timeticks.
//
// Usage: ifHCInOctets → [0x00,0x00,0x00,0x01,0xFF,0xFF,0xFF,0xFF] → 1099511627775
func Convert_bytearray_to_uint(bytearray []byte) (intdata uint64) {
	bytearray32 := []byte{0, 0, 0, 0}
	bytearray64 := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	switch len(bytearray) {
	case 1:
		return uint64(bytearray[0])
	case 2:
		return uint64(binary.BigEndian.Uint16(bytearray))
	case 3:
		copy(bytearray32[1:], bytearray)
		return uint64(binary.BigEndian.Uint32(bytearray32))
	case 4:
		return uint64(binary.BigEndian.Uint32(bytearray))
	case 5:
		copy(bytearray64[3:], bytearray)
		return binary.BigEndian.Uint64(bytearray64)
	case 6:
		copy(bytearray64[2:], bytearray)
		return binary.BigEndian.Uint64(bytearray64)
	case 7:
		copy(bytearray64[1:], bytearray)
		return binary.BigEndian.Uint64(bytearray64)
	case 8:
		return binary.BigEndian.Uint64(bytearray)
	default:
		return 0
	}
}

func isAscii(datab []byte) (AsciiString bool, LastAsciSymbolIndex int) {
	FirstZeroPos := -1
	LastAscipos := 0
	hasPrintable := false
	for i := 0; i < len(datab); i++ {
		if datab[i] < 0x20 || datab[i] > 0x7e {
			if datab[i] == 0x09 || datab[i] == 0x0a || datab[i] == 0x0d {
				continue
			}
			if datab[i] == 0x00 {
				if FirstZeroPos == -1 {
					FirstZeroPos = i
				}
				continue
			}
			return false, LastAscipos
		} else {
			LastAscipos = i
			hasPrintable = true
		}
	}
	if FirstZeroPos > -1 && FirstZeroPos < LastAscipos {
		return false, LastAscipos
	}
	return hasPrintable, LastAscipos
}

// Convert_ClassTag_to_String converts SNMPVar to human-readable ASN.1/SNMP type string.
//
// Parameters:
//
//	Var - SNMP variable with Class, Type, IsCompound, Value bytes
//
// Algorithm:
//
//	**Universal Class**: BOOLEAN/INTEGER/BITSTRING/OCTET_STRING/NULL/OID/SEQUENCE/SET
//	**OCTET_STRING**: isAscii() → "OCTET STRING" vs "HEX STRING"
//	**Application Class**: IPADDR/COUNTER32/GAUGE32/TIMETICKS/COUNTER64/OPAQUE
//
// Returns:
//
//	StringType - Descriptive type name ("Universal OID", "COUNTER32", "IP ADDRESS")
func Convert_ClassTag_to_String(Var SNMPVar) string {
	StringType := "Unknown"
	switch Var.ValueClass {
	case ASNber.ClassUniversal:
		switch Var.ValueType {
		case ASNber.TagBoolean:
			StringType = "Universal BOOLEAN"
		case ASNber.TagInteger:
			StringType = "Universal INTEGER"
		case ASNber.TagBitString:
			StringType = "Universal BITSTRING"
		case ASNber.TagOctetString:
			AsVal, _ := isAscii(Var.Value)
			if AsVal {
				StringType = "Universal OCTET STRING"
			} else {
				StringType = "Universal HEX STRING"
			}
		case ASNber.TagNull:
			StringType = "Universal NULL"

		case ASNber.TagOID:
			StringType = "Universal OID"
		case ASNber.TagSequence:
			if Var.IsCompound {
				StringType = "Universal SEQUENCE"
			}
		case ASNber.TagSet:
			if Var.IsCompound {
				StringType = "Universal SET"
			}
		default:
			StringType = "Unknown Universal"

		}

	case ASNber.ClassApplication:
		switch Var.ValueType {
		case SNMP_type_IPADDR:
			StringType = "IP ADDRESS"
		case SNMP_type_COUNTER32:
			StringType = "COUNTER32"
		case SNMP_type_GAUGE32:
			StringType = "GAUGE32"
		case SNMP_type_COUNTER64:
			StringType = "COUNTER64"
		case SNMP_type_TIMETICKS:
			StringType = "TIMETICKS"
		case SNMP_type_OPAQUE:
			StringType = "OPAQUE"

		default:
			StringType = "Unknown APPLICATION"
		}
	}
	return StringType
}

// SetSNMPVar_OctetString creates SNMP OctetString VarBind for SET operations.
//
// **NO BER encoding** - returns raw ASN.1-ready bytes for packet builder.
// Tag=0x04, string → []byte. Used in SNMP SET for sysName.0, ifAlias.
//
// Usage:
//
//	sysName := SetSNMPVar_OctetString("my-router")
//	vb := SNMP_Packet_V2_Decoded_VarBind{RSnmpOID: sysNameOID, RSnmpVar: sysName}
//	sess.SNMP_SET([]vb)
func SetSNMPVar_OctetString(str string) SNMPVar {
	return SNMPVar{ValueClass: ASNber.ClassUniversal, ValueType: ASNber.TagOctetString, IsCompound: false, Value: []byte(str)}
}

// SetSNMPVar_Int creates SNMP INTEGER VarBind for SET operations.
//
// **NO BER encoding** - returns raw ASN.1-ready BigEndian bytes (4 bytes fixed).
// Tag=0x02. Used in SNMP SET for ifAdminStatus.1, sysContact.0.
//
// Usage:
//
//	ifUp := SetSNMPVar_Int(1)  // ifAdminStatus up
//	vb := SNMP_Packet_V2_Decoded_VarBind{...}
//	sess.SNMP_SET([]vb)
func SetSNMPVar_Int(ival int32) SNMPVar {
	Bval := make([]byte, 4)
	binary.BigEndian.PutUint32(Bval, uint32(ival))
	return SNMPVar{ValueClass: ASNber.ClassUniversal, ValueType: ASNber.TagInteger, IsCompound: false, Value: Bval}
}

// SetSNMPVar_IpAddr creates SNMP IpAddress VarBind for SET operations.
//
// **NO BER encoding** - returns raw ASN.1-ready IPv4 bytes (4 bytes fixed).
// Application Tag=1 (RFC2578). Used in SNMP SET for ipAdEntAddr.
//
// Usage:
//
//	ipVar := SetSNMPVar_IpAddr(net.ParseIP("192.168.1.1"))
//	vb := SNMP_Packet_V2_Decoded_VarBind{...}
//	sess.SNMP_SET([]vb)
func SetSNMPVar_IpAddr(ipval net.IP) (SNMPVar, error) {
	Bval := ipval.To4()
	if Bval == nil {
		return SNMPVar{}, errors.New("cannot convert IP to 4x bytes")
	}
	return SNMPVar{ValueClass: ASNber.ClassApplication, ValueType: SNMP_type_IPADDR, IsCompound: false, Value: Bval}, nil
}

// Convert_setvar_toasn1raw converts SNMPVar to ASN.1 RawValue for SET requests.
//
// Parameters:
//
//	invar - Source SNMPVar (parsed from previous GET or user input)
//
// Algorithm:
//
//	Direct field mapping: ValueType→Tag, ValueClass→Class, Value→Bytes
//	Preserves original BER encoding from SNMPVar.Value
//
// Returns:
//
//	Retvar - ASN.1 RawValue ready for SNMP SET packet marshaling
func Convert_setvar_toasn1raw(invar SNMPVar) ASNber.RawValue {
	Retvar := ASNber.NullRawValue
	Retvar.Tag = invar.ValueType
	Retvar.Class = invar.ValueClass
	Retvar.Bytes = invar.Value
	return Retvar
}

// Convert_Variable_To_String formats SNMPVar value as human-readable string.
//
// Parameters:
//
//	Var - SNMP variable with decoded Class/Type/Value
//
// Algorithm:
// **Universal Types**: INTEGER→decimal, OCTET_STRING→ASCII/HEX, OID→dotted notation
// **Application Types**:
//   - IPADDR→"x.x.x.x"
//   - TIMETICKS→"Xh Ym Zs" (×10ms → time.Duration)
//   - COUNTER32/GAUGE32→decimal
//   - COUNTER64→decimal (int64)
//   - OPAQUE→hex
//
// **Compound** (SEQUENCE/SET)→hex dump
//
// Returns:
//
//	Formatted string for logging/display ("123", "1.3.6.1...", "192.168.1.1")
func Convert_Variable_To_String(Var SNMPVar) string {
	if !Var.IsCompound {
		switch Var.ValueClass {
		case ASNber.ClassUniversal:
			switch Var.ValueType {
			case ASNber.TagInteger:
				return fmt.Sprintf("%d", Convert_snmpint_to_int32(Var.Value))
			case ASNber.TagBitString:
				return fmt.Sprintf("%d", Convert_bytearray_to_int(Var.Value))
			case ASNber.TagOctetString:
				return formatOctetString(Var.Value)
			case ASNber.TagOID:
				return Convert_OID_IntArrayToString(Convert_bytearray_to_intarray(Var.Value))
			default:
				return string(Var.Value)
			}
		case ASNber.ClassApplication:
			switch Var.ValueType {
			case SNMP_type_IPADDR:
				return formatIPAddress(Var.Value)
			case SNMP_type_TIMETICKS:
				TimetickInt := Convert_bytearray_to_int(Var.Value)
				timetickinmillisecond := time.Duration(TimetickInt * 10)
				return (time.Millisecond * timetickinmillisecond).String()
			case SNMP_type_COUNTER32:
				return fmt.Sprintf("%d", Convert_snmpint_to_int32(Var.Value))
			case SNMP_type_GAUGE32:
				return fmt.Sprintf("%d", Convert_snmpint_to_int32(Var.Value))
			case SNMP_type_COUNTER64:
				return fmt.Sprintf("%d", Convert_bytearray_to_int(Var.Value))
			case SNMP_type_OPAQUE:
				//Бинарные данные
				return hex.EncodeToString(Var.Value)
			}
		}
	} else {
		//Это SEQUENCE или SET, выводим HEX строку
		return hex.EncodeToString(Var.Value)
	}
	return ""
}

// formatIPAddress formats SNMPv3 Application IPADDR (4-byte IPv4) as dotted decimal.
//
// Parameters:
//
//	data - 4-byte BER-decoded IP address bytes (big-endian)
//
// Algorithm:
//  1. **Strict 4-byte validation** (SNMP IPADDR format)
//  2. net.IP(data) → automatic "192.168.1.1" formatting
//  3. Invalid length → "Invalid IP (len=X): <hex>" diagnostic
//
// Returns:
//
//	Formatted IPv4 string or hex diagnostic for non-IPADDR data
func formatIPAddress(data []byte) string {
	// Проверяем длину, если это не ipv4 то вернем HEX строку
	if len(data) != 4 {
		return fmt.Sprintf("Invalid IP (len=%d): %s", len(data), hex.EncodeToString(data))
	}
	ip := net.IP(data)
	if ip == nil {
		return hex.EncodeToString(data)
	}
	return ip.String()
}

// formatOctetString formats SNMP OCTET STRING as ASCII or HEX dump.
//
// Parameters:
//
//	data - BER-decoded OCTET STRING bytes
//
// Algorithm:
//  1. **ASCII validation**: isAscii() checks printable chars (0x20-0x7E)
//  2. **C-string trim**: Cuts trailing NUL bytes using LastAsciSymbolIndex
//  3. Valid ASCII → string conversion with trim
//  4. Binary data → lowercase hex dump
//
// Returns:
//
//	Human-readable: "hostname123" or "cafebabe010203"
func formatOctetString(data []byte) string {
	// Проверяем, это ASCII текст?
	if isAsciiFl, lastIndex := isAscii(data); isAsciiFl {
		if lastIndex < len(data)-1 {
			return string(data[:lastIndex+1])
		}
		return string(data)
	}
	// Иначе выводим как HEX строку
	return hex.EncodeToString(data)
}
