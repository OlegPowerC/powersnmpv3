## v1.2.2

- Added field **MaxMsgSize** in `NetworkDevice` for controlling SNMP message size.  
  - Prevent IP fragmentation when properly configured with MaxRepetitions 
  - Default: 1360 bytes (suitable for typical LAN and VPN environments)
  - Configurable range: 500-65535 bytes
  - Not applicable for SNMP v2c
## v1.2.3
- Fixed DES key error
