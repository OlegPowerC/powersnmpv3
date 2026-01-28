# PowerSNMPv3
[![Go](https://img.shields.io/badge/go-%3E%3D1.21-blue.svg)](https://pkg.go.dev/github.com/OlegPowerC/powersnmpv3)
[![Go Report Card](https://goreportcard.com/badge/github.com/OlegPowerC/powersnmpv3)](https://goreportcard.com/report/github.com/OlegPowerC/powersnmpv3)
[![PowerSNMPv3 CI](https://github.com/OlegPowerC/powersnmpv3/actions/workflows/ci.yml/badge.svg)](https://github.com/OlegPowerC/powersnmpv3/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![LibHunt](https://img.shields.io/badge/LibHunt-trending-brightgreen)](https://www.libhunt.com/r/powersnmpv3)
[![GitHub stars](https://img.shields.io/github/stars/OlegPowerC/powersnmpv3?style=social)](https://github.com/OlegPowerC/powersnmpv3/stargazers)
[![DEV.to Article](https://img.shields.io/badge/DEV.to-Article-blue)](https://dev.to/olegpowerc/powersnmpv3-a-new-pure-go-snmp-library-with-better-error-handling-10d1)


📖 **Quick Links:**
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Security Level Mismatch Handling](#security-level-mismatch-handling) 
- [Performance](#performance)
- [Examples](#examples)  
---
**Pure Go SNMP v2c/v3 Library**

Author: Volkov Oleg
License: MIT (commercial version with support available)
Contact: oleg.powerc@gmail.com

---

## Features

- SNMPv2c and SNMPv3 support
- Authentication: MD5, SHA, SHA-224, SHA-256, SHA-384, SHA-512
- Encryption: DES, AES-128, AES-192, AES-256 (including AGENT++ variants)
- SNMP operations: Get, GetMulti, Set, SetMulti, Walk, BulkWalk
- Streaming operations via channels: Walk_WChan, BulkWalk_WChan
- TRAP/INFORM reception with automatic ACK
- Minimal dependencies: only `github.com/OlegPowerC/asn1modsnmp`
- Partial error handling support

---

## Installation

```bash
go get github.com/OlegPowerC/powersnmpv3
```

---

## Quick Start

### SNMPv3 Get

```
package main

import (
    "fmt"
    "log"

    snmp "github.com/OlegPowerC/powersnmpv3"
)

func main() {
    device := snmp.NetworkDevice{
        IPaddress: "192.168.1.1",
        Port:      161,
        SNMPparameters: snmp.SNMPUserParameters{
            SNMPversion:      3,
            Username:         "snmpuser",
            AuthProtocol:     "sha",
            AuthKey:          "authpass123",
            PrivProtocol:     "aes",
            PrivKey:          "privpass123",
            RetryCount:       3,
            TimeoutBtwRepeat: 500,
        },
    }

    sess, err := snmp.SNMP_Init(device)
    if err != nil {
        log.Fatal(err)
    }
    defer sess.Close()

    // sysDescr.0
    oid, _ := snmp.ParseOID("1.3.6.1.2.1.1.1.0")
    result, err := sess.SNMP_Get(oid)
    if err != nil {
        log.Fatal(err)
    }

    for _, vb := range result {
        fmt.Printf("%s = %s\n",
            snmp.Convert_OID_IntArrayToString_RAW(vb.RSnmpOID),
            snmp.Convert_Variable_To_String(vb.RSnmpVar))
    }
}
```

### SNMPv2c Get

```
device := snmp.NetworkDevice{
    IPaddress: "192.168.1.1",
    Port:      161,
    SNMPparameters: snmp.SNMPUserParameters{
        SNMPversion:      2,
        Community:        "public",
        RetryCount:       3,
        TimeoutBtwRepeat: 500,
    },
}

sess, err := snmp.SNMP_Init(device)
// ...
```

### Smart Session Parameters

| Parameter            | Default    | Feature                                     |
|----------------------|------------|---------------------------------------------|
| **TimeoutBtwRepeat** | 300ms      | `base × (attempt+1)`: 300→600→900ms backoff |
| **MaxMsgSize**       | 1360 bytes | Like TCP MSS — prevents IP fragmentation    |
| **MaxRepetitions**   | 25         | BulkWalk without packet loss                |

---

## Data Types

### NetworkDevice

Device configuration for session initialization.

```
type NetworkDevice struct {
    IPaddress      string             // Device IP address
    Port           int                // UDP port (usually 161)
    SNMPparameters SNMPUserParameters // SNMP parameters
    DebugLevel     uint8              // Debug level (0-3)
}
```

### SNMPUserParameters

SNMP session parameters.

```
type SNMPUserParameters struct {
    SNMPversion      int    // 2 for v2c, 3 for v3
    Username         string // Username (v3)
    AuthKey          string // Authentication password (v3)
    AuthProtocol     string // "md5", "sha", "sha224", "sha256", "sha384", "sha512"
    PrivKey          string // Privacy password (v3)
    PrivProtocol     string // "des", "aes", "aes192", "aes256", "aes192a", "aes256a"
    ContextName      string // SNMPv3 context (optional)
    RetryCount       int    // Retry count (1-10, default 3)
    TimeoutBtwRepeat int    // Timeout between retries in ms (default 300)
    MaxRepetitions   uint16 // Max repetitions for BulkWalk (default 25)
    MaxMsgSize       uint16 // Max SNMP v3 message size
    Community        string // Community string (v2c)
}
```

| Parameter        | Type   | description                                                                                                                                                                                                                                                    |
|------------------|--------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| SNMPversion      | int    | SNMP version, 2 for v2c, 3 for v3                                                                                                                                                                                                                              |
| Username         | string | USM User for SNMP v3                                                                                                                                                                                                                                           |
| AuthKey          | string | Authentication password for v3                                                                                                                                                                                                                                 |
| AuthProtocol     | string | "md5", "sha", "sha224", "sha256", "sha384", "sha512"                                                                                                                                                                                                           |
| PrivKey          | string | Privacy password for v3                                                                                                                                                                                                                                        |
| PrivProtocol     | string | "des", "aes", "aes192", "aes256", "aes192a", "aes256a"                                                                                                                                                                                                         |
| ContextName      | string | Optional SNMP v3 context name. For example, to retrieve a MAC address table for VLAN 10 on a Cisco switch, specify the vlan-10 context                                                                                                                         |
| RetryCount       | int    | Retry count (1-10, default 3)                                                                                                                                                                                                                                  |
| TimeoutBtwRepeat | int    | Timeout between retries in ms (default 300). Uses linear backoff: timeout = base × (attempt + 1)                                                                                                                                                               |
| MaxRepetitions   | uint16 | Max repetitions for BulkWalk (default 25)                                                                                                                                                                                                                      |
| MaxMsgSize       | Uint16 | limits the maximum size of SNMP messages sent to and received from the device. It functions similarly to the MSS (Maximum Segment Size) parameter in TCP, defining the upper limit for the payload to avoid IP fragmentation and improve delivery reliability. |

### SNMPv3Session

Active SNMP session. Created via `SNMP_Init()`.

```
type SNMPv3Session struct {
    IPaddress  string
    Port       int
    Debuglevel uint8
    SNMPparams SNMPParameters
    // ... internal fields
}
```

### SNMP_Packet_V2_Decoded_VarBind

SNMP request result - OID and value pair.

```
type SNMP_Packet_V2_Decoded_VarBind struct {
    RSnmpOID []int   // OID as int array
    RSnmpVar SNMPVar // Variable value
}
```

### SNMPVar

SNMP variable with type and value.

```
type SNMPVar struct {
    ValueType  int    // Value type (ASN.1 tag)
    ValueClass int    // Class (Universal, Application, Context, Private)
    IsCompound bool   // Compound type (SEQUENCE, etc.)
    Value      []byte // Raw value
}
```

### ChanDataWErr

Result for streaming operations via channels.

```
type ChanDataWErr struct {
    Data  SNMP_Packet_V2_Decoded_VarBind // Data
    Error error                          // Error (nil if OK)
    ValidData bool                       // Data is valid
}
```

### SNMPTrapParameters

Parameters for TRAP/INFORM reception.

```
type SNMPTrapParameters struct {
    SNMPversion  int    // 2 or 3
    Username     string // Username (v3)
    AuthKey      string // Authentication password
    AuthProtocol string // Authentication protocol
    PrivKey      string // Privacy password
    PrivProtocol string // Privacy protocol
    Community    string // Community (v2c)
}
```

---

## Public Functions

### Session Initialization and Closing

#### SNMP_Init

Creates and initializes SNMP session. Performs Engine Discovery for SNMPv3.

```
func SNMP_Init(Ndev NetworkDevice) (*SNMPv3Session, error)
```

**Parameters:**
- `Ndev` - device configuration

**Returns:**
- `*SNMPv3Session` - pointer to session
- `error` - initialization error or nil

**Example:**
```
sess, err := snmp.SNMP_Init(device)
if err != nil {
    log.Fatal("Init failed:", err)
}
defer sess.Close()
```

#### Close

Closes UDP connection and releases resources.

```
func (s *SNMPv3Session) Close() error
```

---

### Read Operations

#### SNMP_Get

Performs SNMP GET request for a single OID.

```
func (s *SNMPv3Session) SNMP_Get(Oid []int) ([]SNMP_Packet_V2_Decoded_VarBind, error)
```

**Parameters:**
- `Oid` - OID as int array (use `ParseOID`)

**Returns:**
- `[]SNMP_Packet_V2_Decoded_VarBind` - array with single result
- `error` - fatal error or nil

**Example:**
```
oid, _ := snmp.ParseOID("1.3.6.1.2.1.1.1.0")
result, err := sess.SNMP_Get(oid)
```

#### SNMP_GetMulti

Performs SNMP GET request for multiple OIDs in a single PDU.

```
func (s *SNMPv3Session) SNMP_GetMulti(OidVar []SNMP_Packet_V2_Decoded_VarBind) ([]SNMP_Packet_V2_Decoded_VarBind, error)
```

**Parameters:**
- `OidVar` - VarBind array with filled OIDs (`RSnmpOID` field)

**Returns:**
- `[]SNMP_Packet_V2_Decoded_VarBind` - results
- `error` - can be partial error (`SNMPne_Errors`) or fatal

**Example:**
```
oids := []snmp.SNMP_Packet_V2_Decoded_VarBind{
    {RSnmpOID: oid1},
    {RSnmpOID: oid2},
    {RSnmpOID: oid3},
}
results, err := sess.SNMP_GetMulti(oids)
```

#### SNMP_Walk

Performs complete SNMP Walk of subtree using GETNEXT.

```
func (s *SNMPv3Session) SNMP_Walk(oid []int) ([]SNMP_Packet_V2_Decoded_VarBind, error)
```

**Parameters:**
- `oid` - root OID of subtree

**Returns:**
- `[]SNMP_Packet_V2_Decoded_VarBind` - all values in subtree
- `error` - error or nil

**Example:**
```
// Walk ifDescr (1.3.6.1.2.1.2.2.1.2)
oid, _ := snmp.ParseOID("1.3.6.1.2.1.2.2.1.2")
interfaces, err := sess.SNMP_Walk(oid)
for _, iface := range interfaces {
    fmt.Println(snmp.Convert_Variable_To_String(iface.RSnmpVar))
}
```

#### SNMP_BulkWalk

Performs high-performance SNMP Walk using GETBULK.

```
func (s *SNMPv3Session) SNMP_BulkWalk(oid []int) ([]SNMP_Packet_V2_Decoded_VarBind, error)
```

**Parameters and returns** are similar to `SNMP_Walk`.

Uses `MaxRepetitions` to get multiple values per request.

#### SNMP_Walk_WChan

Streaming Walk via channel. Results are sent as received.

```
func (s *SNMPv3Session) SNMP_Walk_WChan(ctx context.Context,oid []int, CData chan<- ChanDataWErr)
```

**Parameters:**
- `ctx` - context with timeout
- `oid` - root OID
- `CData` - channel for results (closed on completion)

Recommended: buffered channel prevents blocking, context adds timeout

**Example:**
```
ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
defer cancel()
ch := make(chan snmp.ChanDataWErr,30000)
go sess.SNMP_Walk_WChan(ctx,oid, ch)

for result := range ch {
    if result.Error != nil {
        log.Println("Error:", result.Error)
        continue
    }
    fmt.Printf("%s = %s\n",
        snmp.Convert_OID_IntArrayToString_RAW(result.Data.RSnmpOID),
        snmp.Convert_Variable_To_String(result.Data.RSnmpVar))
}
```

#### SNMP_BulkWalk_WChan

Streaming BulkWalk via channel.

```
func (s *SNMPv3Session) SNMP_BulkWalk_WChan(ctx context.Context,oid []int, CData chan<- ChanDataWErr)
```

Similar to `SNMP_Walk_WChan`, but uses GETBULK.

---

### Write Operations

#### SNMP_Set

Performs SNMP SET for a single OID.

```
func (s *SNMPv3Session) SNMP_Set(Oid []int, VBvalue SNMPVar) ([]SNMP_Packet_V2_Decoded_VarBind, error)
```

**Parameters:**
- `Oid` - OID to write
- `VBvalue` - value (create using `SetSNMPVar_*` functions)

**Returns:**
- `[]SNMP_Packet_V2_Decoded_VarBind` - SET result
- `error` - error or nil

**Example:**
```
oid, _ := snmp.ParseOID("1.3.6.1.2.1.1.6.0") // sysLocation
value := snmp.SetSNMPVar_OctetString("Server Room A1")
result, err := sess.SNMP_Set(oid, value)
```

#### SNMP_SetMulti

Performs SNMP SET for multiple OIDs in a single PDU.

```
func (s *SNMPv3Session) SNMP_SetMulti(OidVar []SNMP_Packet_V2_Decoded_VarBind) ([]SNMP_Packet_V2_Decoded_VarBind, error)
```

---

### Value Creation Functions for SET

#### SetSNMPVar_OctetString

Creates SNMP OctetString.

```
func SetSNMPVar_OctetString(str string) SNMPVar
```

#### SetSNMPVar_Int

Creates SNMP Integer.

```
func SetSNMPVar_Int(ival int32) SNMPVar
```

#### SetSNMPVar_IpAddr

Creates SNMP IpAddress.

```
func SetSNMPVar_IpAddr(ipval net.IP) (SNMPVar, error)
```

---

### Conversion Functions

#### Convert_OID_StringToIntArray

Converts OID string to BER-encoded int array.

```
func Convert_OID_StringToIntArray(OIDStr string) ([]int, error)
```

**Example:**
```
oid, err := snmp.Convert_OID_StringToIntArray("1.3.6.1.2.1.1.1.0")
// oid = []int{43, 6, 1, 2, 1, 1, 1, 0} (BER encoded)
```

#### ParseOID

Converts OID string to "raw" int array (without BER encoding).
Use for convert string OID to []int for us in the Get/Set/Walk function

```
func ParseOID(OIDStr string) ([]int, error)
```

**Example:**
```
oid, err := snmp.ParseOID("1.3.6.1.2.1.1.1.0")
// oid = []int{1, 3, 6, 1, 2, 1, 1, 1, 0}
```

#### Convert_OID_IntArrayToString_RAW

Converts int array back to OID string.

```
func Convert_OID_IntArrayToString_RAW(OIDIntArray []int) string
```

**Example:**
```
str := snmp.Convert_OID_IntArrayToString_RAW([]int{1, 3, 6, 1, 2, 1, 1, 1, 0})
// str = "1.3.6.1.2.1.1.1.0"
```

#### Convert_Variable_To_String

Converts SNMPVar to human-readable string.

```
func Convert_Variable_To_String(Var SNMPVar) string
```

Automatically detects type and formats:
- OctetString → string
- Integer → number
- Counter32/64, Gauge32 → number
- TimeTicks → number
- IpAddress → "x.x.x.x"
- OID → "1.3.6.1..."

#### Convert_ClassTag_to_String

Returns ASN.1/SNMP type name.

```
func Convert_ClassTag_to_String(Var SNMPVar) string
```

**Example:**
```
typeStr := snmp.Convert_ClassTag_to_String(varbind.RSnmpVar)
// "Universal OCTET STRING", "Application COUNTER32", etc.
```

---

### TRAP/INFORM Handling
Supports simultaneous reception of SNMP v2c and SNMP v3 TRAPs/INFORMs

#### ParseTrapUsername

Quick extraction of username or community from TRAP packet.

```
func ParseTrapUsername(packet []byte) (version int, username string, v3secdata SNMPv3_SecSeq, err error)
```

**Returns:**
- `version` - SNMP version (1 for v2c, 3 for v3)
- `username` - username (v3) or community (v2c)
- `v3secdata` - v3 security data (EngineID, Boots, Time)
- `err` - parsing error

#### ParseTrapWithCredentials

Full TRAP/INFORM parsing with authentication verification and decryption.

```
func ParseTrapWithCredentials(
    SenderIp string,
    SenderPort int,
    packet []byte,
    UserData SNMPTrapParameters,
    debuglevel uint8,
) (decodedversion int, messagetype int, decryptedData SNMP_Packet_V2_decoded_PDU, err error)
```

**Parameters:**
- `SenderIp`, `SenderPort` - sender address
- `packet` - raw UDP packet
- `UserData` - credentials for decryption
- `debuglevel` - debug level

**Returns:**
- `decodedversion` - SNMP version
- `messagetype` - type (1=REPORT, 2=TRAP, 3=INFORM)
- `decryptedData` - decrypted PDU data
- `err` - error

**Message type constants:**
```
const (
    REPORT_MESSAGE = 1
    TRAP_MESSAGE   = 2
    INFORM_MESSAGE = 3
)
```

**Workflow:**  
After initial packet parsing extracts Username from SNMPv3 header, matching credentials can be looked up in a map by Username for decryption/authentication.

---

### Helper Functions

#### InSubTreeCheck

Checks if OID is within subtree.

```
func InSubTreeCheck(OidMain []int, OidCurrent []int) bool
```

**Example:**
```
main := []int{1, 3, 6, 1, 2, 1}
current := []int{1, 3, 6, 1, 2, 1, 1, 1}
inTree := snmp.InSubTreeCheck(main, current) // true
```

#### SNMPErrorIntToText

Converts SNMP error code to text.

```
func SNMPErrorIntToText(code int) string
```

#### SNMPPDUErrorIntToText

Converts PDU error code to text.

```
func SNMPPDUErrorIntToText(code int) string
```

---

## Error Handling

The library distinguishes between **fatal** and **partial** errors.

### Error Types

#### SNMPfe_Errors - Fatal Errors

Operation completely failed. Results are unavailable.

```
type SNMPfe_Errors struct {
    ErrorStatusRaw int32  // SNMP error code
    ErrorIndexRaw  int32  // Failed OID index
    FailedOID      []int  // OID that caused error
    RequestType    uint32 // Request type
}
```

Examples: network timeout, authentication error, `notWritable`.

#### SNMPne_Errors - Partial Errors

Part of request completed successfully. **Results are available!**

```
type SNMPne_Errors struct {
    Failedoids []PowerSNMPv3_Errors_FailedOids_Error
}

type PowerSNMPv3_Errors_FailedOids_Error struct {
    Failedoid []int // Failed OID
    Error_id  int   // Error code (noSuchInstance, etc.)
}
```

Examples: `noSuchInstance`, `noSuchObject` for some OIDs in GetMulti.

### ParseError - Unified Error Analysis

The `ParseError` function helps determine error type:

```
func ParseError(err error) (SNMPerr SNMPud_Errors, CommonError error)
```

**Returns:**

```
type SNMPud_Errors struct {
    IsFatal bool             // true = fatal, false = partial
    Oids    []SNMPud_OidError // List of failed OIDs
}

type SNMPud_OidError struct {
    Failedoid        []int  // Failed OID
    Error_id         int32  // Error code
    ErrorDescription string // Error description
}
```

**Usage example:**

```
results, err := sess.SNMP_GetMulti(oids)
if err != nil {
    snmpErr, commonErr := snmp.ParseError(err)

    if commonErr != nil {
        // Network error, cryptography, etc.
        log.Fatal("Network/system error:", commonErr)
    }

    if snmpErr.IsFatal {
        // Fatal SNMP error
        log.Fatal("Fatal SNMP error:", snmpErr.Oids[0].ErrorDescription)
    }

    // Partial error - results are available!
    log.Printf("Partial error, %d OIDs failed:", len(snmpErr.Oids))
    for _, oidErr := range snmpErr.Oids {
        log.Printf("  - %s: %s",
            snmp.Convert_OID_IntArrayToString_RAW(oidErr.Failedoid),
            oidErr.ErrorDescription)
    }
}

// Process successful results
for _, vb := range results {
    // ...
}
```

---

## Examples

### SNMP Walk CLI (examples/SNMPWalk.go)

Command-line utility for SNMP Walk.

```bash
# SNMPv3 Walk
go run cmd/SNMPWalk.go -h 192.168.1.1 -v 3 \
    -u snmpuser -a sha -A authpass -x aes -X privpass \
    -o 1.3.6.1.2.1.2.2.1.2

# SNMPv3 BulkWalk
go run cmd/SNMPWalk.go -h 192.168.1.1 -v 3 \
    -u snmpuser -a sha -A authpass -x aes -X privpass \
    -o 1.3.6.1.2.1.2.2.1.2 -bulk

# SNMPv2c Walk
go run cmd/SNMPWalk.go -h 192.168.1.1 -v 2 -c public \
    -o 1.3.6.1.2.1.2.2.1.2
```

### TRAP/INFORM Receiver (examples/TrapInformReceiver.go)

TRAP and INFORM message receiver with SNMPv3 support.

```
// Configure credentials
Userv3Map := make(map[string]*snmp.SNMPTrapParameters)
Userv3Map["snmpuser"] = &snmp.SNMPTrapParameters{
    Username:     "snmpuser",
    AuthProtocol: "sha",
    AuthKey:      "authpass123",
    PrivProtocol: "aes",
    PrivKey:      "privpass123",
}

// Receive packet
conn, _ := net.ListenPacket("udp", ":162")
n, addr, _ := conn.ReadFrom(buff)

// Parse
version, msgtype, data, err := snmp.ParseTrapWithCredentials(
    addr.IP.String(), addr.Port, buff[:n], credentials, 0)
```

Testing with net-snmp:
```bash
# SNMPv3 INFORM
snmpinform -v 3 -u snmpuser -a sha -A authpass123 \
    -l authPriv -x aes -X privpass123 \
    -e 0x80001f8880f7996d5a41965d69 192.168.1.100 42 coldStart.0

# SNMPv2c INFORM
snmpinform -v 2c -c public 192.168.1.100 42 coldStart.0
```

---

## Testing

### Requirements

Full testing requires a **real SNMP device** (switch, router).

### Running Tests

```bash
go test -v -args \
    -h <DEVICE_IP> \
    -u <SNMP_USER> \
    -a <AUTH_PROTO> \
    -A <AUTH_PASS> \
    -x <PRIV_PROTO> \
    -X <PRIV_PASS> \
    -c <COMMUNITY>
```

**Example:**
```bash
go test -v -args -h 192.168.1.252 -u SNMPv3-U -a sha -A test123 -x aes -X test321 -c private123
```

### What is Tested

1. **Unit tests** (no device required):
   - `TestConvert_Variable_To_String` - value conversion
   - `TestConvert_ClassTag_to_String` - type detection
   - `TestConvert_bytearray_to_int` - number conversion
   - `TestConvert_bytearray_to_uint` - unsigned conversion
   - `TestCovert_OID_IntArrayToString` - OID conversion
   - `TestCovert_OID_IntArrayToString_RAW` - RAW OID conversion
   - `TestConvert_bytearray_to_intarray_with_multibyte_data` - multibyte OID
   - `TestConvert_snmpint_to_int32` - SNMP int32
   - `TestConvert_snmpint_to_uint32` - SNMP uint32
   - `TestConvert_Covert_OID_StringToIntArray` - string to OID
   - `Test_PKCS5Padding` - PKCS5 padding/unpadding

2. **Integration tests** (device required):
   - `TestSNMPv3Session_SNMP_Get_Set_Walk`:
     - SNMPv2c GET (read sysLocation)
     - SNMPv2c SET (write sysLocation)
     - SNMPv3 initialization with Engine Discovery
     - SNMPv3 GET (read sysLocation)
     - SNMPv3 SET (write sysLocation)
     - V2→V3 verification (check that v2 SET is visible from v3)
     - SNMPv3 Walk (ifDescr)
     - SNMPv3 BulkWalk (ifDescr)

### Expected Output

```
=== RUN   TestConvert_Variable_To_String
--- PASS: TestConvert_Variable_To_String (0.00s)
...
=== RUN   TestSNMPv3Session_SNMP_Get_Set_Walk
1.3.6.1.2.1.1.6.0 = Test location : Universal OCTET STRING
    snmpfunc_test.go:55: 59 <nil>
1.3.6.1.2.1.1.6.0 = Test location from V2 : Universal OCTET STRING
    snmpfunc_test.go:88: 67 <nil>
    snmpfunc_test.go:93: V2→V3 VERIFICATION PASS! 'Test location from V2'
1.3.6.1.2.1.2.2.1.2.1 = Vlan1 : Universal OCTET STRING
...
--- PASS: TestSNMPv3Session_SNMP_Get_Set_Walk (0.75s)
PASS
ok      github.com/OlegPowerC/powersnmpv3       2.273s
```

---

## Constants

### Authentication Protocols

| Constant | Value | String |
|----------|-------|--------|
| AUTH_PROTOCOL_NONE | 0 | - |
| AUTH_PROTOCOL_MD5 | 1 | "md5" |
| AUTH_PROTOCOL_SHA | 2 | "sha" |
| AUTH_PROTOCOL_SHA224 | 3 | "sha224" |
| AUTH_PROTOCOL_SHA256 | 4 | "sha256" |
| AUTH_PROTOCOL_SHA384 | 5 | "sha384" |
| AUTH_PROTOCOL_SHA512 | 6 | "sha512" |

### Privacy Protocols

| Constant | Value | String |
|----------|-------|--------|
| PRIV_PROTOCOL_NONE | 0 | - |
| PRIV_PROTOCOL_DES | 2 | "des" |
| PRIV_PROTOCOL_AES128 | 1 | "aes" |
| PRIV_PROTOCOL_AES192 | 3 | "aes192" |
| PRIV_PROTOCOL_AES256 | 4 | "aes256" |
| PRIV_PROTOCOL_AES192A | 5 | "aes192a" (AGENT++) |
| PRIV_PROTOCOL_AES256A | 6 | "aes256a" (AGENT++) |

### Limits

| Constant | Value | Description |
|----------|-------|-------------|
| SNMP_MAXIMUMWALK | 1000000 | Max Walk entries |
| SNMP_BUFFERSIZE | 2048 | UDP buffer size |
| SNMP_MAXTIMEOUT_MS | 1000 | Max timeout |
| SNMP_DEFAULTTIMEOUT_MS | 300 | Default timeout |
| SNMP_MAXIMUM_RETRY | 10 | Max retries |
| SNMP_DEFAULTRETRY | 3 | Default retries |
| SNMP_MAXREPETITION | 80 | Max repetitions |
| SNMP_DEFAULTREPETITION | 25 | Default repetitions |

---

## Dependencies

- `github.com/OlegPowerC/asn1modsnmp` - fork of standard `encoding/asn1` with SNMP optimizations:
  - `ShortLengthAllow` - support for short-length encoding (some switches, e.g., Moxa) and indefinite length (include nested)
  - `FindSNMPv3AuthParamsOffset()` - find AuthParams position for USM verification
  - `ExtractDataWOTagAndLen()` - extract data without TLV wrapper for cryptography

---

## Performance

Benchmarked on 15,381 OIDs (SNMPv3 AES128+SHA, 1Gbps network, Cisco S8000v target):

| Implementation                 | Time        | Throughput      | Memory     |
|--------------------------------|-------------|-----------------|------------|
| **PowerSNMPv3 (Channel)** ⭐   | **4.02s**   | **3,827 OID/s** | 12.4 MB    |
| PowerSNMPv3 (Callback)         | 4.46s       | 3,449 OID/s     | **8.8 MB** |
| gosnmp                         | 4.43s       | 3,472 OID/s     | 10.0 MB    |
| net-snmp (C)                   | 6.43s       | 2,393 OID/s     | 8.8 MB     |
| snmp4j (Java)                  | 8.27s       | 1,860 OID/s     | 145.6 MB   |

**PowerSNMP is 37% faster than net-snmp and uses 12x less memory than snmp4j.**

### When to use each mode:

- **Channel** (`SNMP_BulkWalk_WChan`): Maximum speed for large tables (5000+ OIDs)
- **Callback** (`SNMP_BulkWalk_WCallback`): Memory-efficient for scripts (100-5000 OIDs)
- **Sync** (`SNMP_Walk`): Debugging and small queries (<100 OIDs)


## License

MIT License

Commercial version with extended support available.

**Contact:** oleg@powerc.ru

### v1.2.6 – Improved Buffer Management and MaxMsgSize Discovery
##### What’s new  

    SNMPv2 buffers:
    The RX buffer size is now fixed at 65535 bytes, while the TX buffer defaults to 1500 bytes (can be modified via a constant).

    SNMPv3 buffers:
    The RX buffer size now dynamically matches the MaxMsgSize value negotiated with the agent.

    Dynamic discovery:
    During the initial exchange, the library automatically discovers the agent’s MaxMsgSize and adjusts the session configuration. Subsequent messages are validated to ensure they do not exceed this limit.

##### Why this matters

These changes make message exchange more robust across different devices and agents, especially those with non‑standard or limited buffer sizes.
They also reduce the risk of transmission errors and improve performance when communicating with high‑capacity agents.
Impact

    Better interoperability with diverse SNMP implementations.
    Automatic buffer sizing for SNMPv3.
    Configurable TX buffer for SNMPv2 to match specific deployment needs.

### v.2.9 January 27, 2026

Key Improvement
- Discovery Agent EngineID: Now performed in main get/set functions when proper REPORT is received
- Automatic EngineID update without additional calls

### Security Level Mismatch Handling

PowerSNMPv3 provides RFC 3414-compliant handling of security level mismatches with optimal network efficiency and zero unnecessary retries.

#### Testing Methodology

The behavior comparison was conducted using simple SNMP Walk operations against the same SNMP agent with identical misconfigurations. Test scenario: client configured with authentication (authNoPriv or authPriv), agent has the same username configured with noAuthNoPriv (no authentication). This represents a common misconfiguration in production environments.

All three libraries (PowerSNMPv3, SNMP4J, gosnmp) were tested with identical parameters, and network traffic was captured via PCAP for analysis.

#### The Problem

Security level mismatches occur when the client is configured with authentication/encryption (authNoPriv or authPriv) but the agent has the same username configured with a different security level (e.g., noAuthNoPriv). According to RFC 3414 §3.2, the agent responds with a REPORT PDU containing `usmStatsUnsupportedSecLevels` (OID 1.3.6.1.6.3.15.1.1.1.0). Critically, **the REPORT is sent without authentication or encryption**, even if the request was authenticated/encrypted.

#### How PowerSNMPv3 Handles It

##### Discovery Phase
```
Client → Agent: GetRequest (EngineID discovery, noAuthNoPriv)
Agent → Client: Report (usmStatsUnknownEngineIDs)
  Returns: EngineID, Boots, Time
```

##### Request Phase (Security Level Mismatch)
```
Client → Agent: GetRequest/GetBulk
  Flags: 0x05 (Auth, Reportable) or 0x07 (Auth, Priv, Reportable)
  Auth Params: HMAC digest present
  Priv Params: AES/DES IV (if authPriv)

Agent → Client: Report
  Flags: 0x00 (None) ← NO authentication!
  Report OID: 1.3.6.1.6.3.15.1.1.1.0 (usmStatsUnsupportedSecLevels)
  Counter: Increments on each mismatch

PowerSNMPv3 Response:
  ✓ Accepts REPORT (checks packet flags, not client config)
  ✓ Parses report OID
  ✓ Returns error: "unsupported security levels"
  ✓ NO RETRY - immediate error return
```

#### RFC 3414 Compliance

PowerSNMPv3 correctly implements RFC 3414 requirements:

- **Accepts REPORT PDUs without authentication** - Even when client expects authenticated responses, REPORT PDUs with msgFlags=0x00 are accepted as valid error indications
- **No retry on configuration errors** - UnsupportedSecLevels is a non-recoverable configuration error; retrying with the same credentials won't help
- **Checks packet flags, not client config** - Authentication verification is based on actual packet flags, not expected client configuration

#### Intelligent Error Classification

PowerSNMPv3 distinguishes between **recoverable** and **non-recoverable** errors:

**Recoverable** (auto-retry with recovery):
- `usmStatsNotInTimeWindows` - Syncs time, then retries
- `usmStatsUnknownEngineIDs` - Performs discovery with key re-localization, then retries

**Non-recoverable** (immediate error return):
- `usmStatsUnsupportedSecLevels` - Configuration mismatch
- `usmStatsUnknownUserNames` - Unknown user
- `usmStatsWrongDigests` - Wrong password
- `usmStatsDecryptionErrors` - Wrong encryption key

#### Comparison with Other Libraries

| Library      | Total Packets | Retry Count | RFC 3414 Compliant | Automatic REPORT Handling |
|--------------|---------------|-------------|--------------------|---------------------------|
| **PowerSNMPv3** | **4**      | **0**       | **✅**             | **✅ Yes**                |
| SNMP4J       | 6             | 1           | ✅                 | ❌ Manual                 |
| gosnmp       | 10            | 3           | ❌                 | ⚠️ Partial                |

**Network efficiency**: PowerSNMPv3 typically uses **60% fewer packets** than gosnmp and **33% fewer** than SNMP4J when handling misconfigurations.

#### User Experience

**PowerSNMPv3:**
```
Error: unsupported security levels
```
✅ Clear, actionable error message  
✅ Immediate feedback  
✅ Obvious what to fix (check security level configuration)

**gosnmp:**
```
Walk Error: incoming packet is not authentic, discarding
```
❌ Confusing error message - suggests authentication problem, not configuration mismatch  
❌ Multiple retries before error  
❌ Unclear root cause - could be wrong password, wrong protocol, or security level mismatch

**SNMP4J** (without manual PDU type check):
```
1.3.6.1.6.3.15.1.1.1.0 = 17
1.3.6.1.6.3.15.1.1.1.0 = 18
```
❌ Returns REPORT OID and counter as data  
❌ Requires manual PDU type checking: `if (response.getType() == PDU.REPORT)`  
❌ User must interpret OID meaning and handle appropriately