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
