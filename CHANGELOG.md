## v1.4.2

### Bug Fixes
- Fixed SHA-2 USM HMAC for SHA-384 and SHA-512 (RFC 7860 / RFC 6234 `crypto/hmac` instead of a 64-byte RFC 3414 pad)
- Fixed AES-192/AES-256 key expansion for MD5/SHA-1 to use the Blumenthal algorithm (`Kul || H(Kul)`)
  - Breaking: `aes192`/`aes256` with MD5/SHA-1 now derive different privacy keys than older versions; callers that need the previous behavior should use `aes192c`/`aes256c`.

### Features
- Added Cisco/Reeder privacy protocols `"aes192c"` and `"aes256c"`
- Added Triple-DES EDE-CBC privacy protocol `"3des"` (draft-reeder-snmpv3-usm-3desede; Cisco/SNMP4J)

## v1.2.2

- Added field **MaxMsgSize** in `NetworkDevice` for controlling SNMP message size.  
  - Prevent IP fragmentation when properly configured with MaxRepetitions 
  - Default: 1360 bytes (suitable for typical LAN and VPN environments)
  - Configurable range: 500-65535 bytes
  - Not applicable for SNMP v2c
## v1.2.3
- Fixed DES key error

## v1.2.4
- Fix ASN.1 truncated error: remove fPKCS5UnPadding for SNMPv3
  asn1.Unmarshal handles PKCS5 padding automatically (RFC3414)

## v1.2.6
- Set SNMPv2 RX buffer size to 65535 bytes
- Set SNMPv3 RX buffer size equal to MaxMsgSize
- Discover MaxMsgSize from the agent and avoid sending data exceeding this limit

## v1.2.7
- Fix error message when received report with 1.3.6.1.6.3.15.1.1.1 (usmStatsUnsupportedSecLevels) 

## v1.2.9 January 27, 2026
✨ Key Improvement  
- Discovery Agent EngineID: Now performed in main get/set functions when proper REPORT is received
- Automatic EngineID update without additional calls
- 

## v1.3.1 January 30, 2026
- Change partial error behavior when all OIDs fail in GetMulti
Mark partial error as fatal when all OIDs in GetMulti request fail.
This provides better error semantics: complete failure = fatal error.
- Change error handling in examples

## v1.4.1 Feb 03, 2026

### Bug Fixes
- Fixed Context-Specific tag handling using `UnmarshalWithParams`
- Fixed critical MaxMsgSize bug (was 0, now 1360 per RFC 3412)

### Improvements
- Removed byte manipulation hack for PDU parsing
- Clean ASN.1 parsing using standard mechanisms
### hide Discovery function
