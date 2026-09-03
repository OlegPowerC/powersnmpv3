## Test description

Key expansion is required when the authentication protocol gives a digest that is too short.  

|Auth protocol  |Digest butes       |
|---------------|-------------------|
|MD5            |16                 |
|SHA1           |20                 |
|SHA224         |28                 |
|SHA256         |32                 |
|SHA384         |48                 |
|SHA512         |64                 |

Authentication: SHA512, encryption: AES256 no key expanshion needed.

### Terminology Mismatches

Key expansion methods do not have a standardized naming convention. In practice, there are only two primary methods:

| Attribute                     | Method 1: Cisco/Reeder                                             | Method 2: Blumenthal-Wiener             |
|-------------------------------|--------------------------------------------------------------------|-----------------------------------------|
| **Library Identifier**        | `aes192`, `aes256`                                                 | `aes192a`, `aes256a`  (*a* = AGENT++)   |
| **Wireshark Name**            | `draft-reeder-snmpv3-usm-3desede-00`                               | `AGENT++`                               |
| **Common Names**              | Cisco, Reeder, Draft-Reeder                                        | Blumenthal, Blumenthal-Wiener           |
| **Other Library Identifiers** | `aes192c`, `aes256c` (*c* = Cisco)                                 | `aes192`, `aes256`                      |
| **IETF Draft Names**          | `draft-reeder-snmpv3-usm-3desede-00`, 3DES-EDE Extension           | `draft-blumenthal-aes-usm-04`           |
| **Vendor / Software Names**   | Cisco Style, Cisco Extension, Standard                             | AGENT++, AgentPlusPlus, Alternative AES |
| **Notes**                     | Default variant in this library (no suffix)                        | Use for Huawei switches                 |

## Cisco

*Some data is masked (Engine ID, IP addresses, passwords)

### Switch

NAME: "Switch 1", DESCR: "WS-C3850-24XS-S"
PID: WS-C3850-24XS-S   , VID: V02  , SN: FOC22XXXXXX

USM Users:

    User name: md5des
    Engine ID: 80000009030000XXXXXXXXXX
    storage-type: nonvolatile        active
    Authentication Protocol: MD5
    Privacy Protocol: DES
    Group-name: testgroup

    User name: md5aes128
    Engine ID: 80000009030000XXXXXXXXXX
    storage-type: nonvolatile        active
    Authentication Protocol: MD5
    Privacy Protocol: AES128
    Group-name: testgroup

    User name: md5aes192
    Engine ID: 80000009030000XXXXXXXXXX
    storage-type: nonvolatile        active
    Authentication Protocol: MD5
    Privacy Protocol: AES192
    Group-name: testgroup

    User name: md5aes256
    Engine ID: 80000009030000XXXXXXXXXX
    storage-type: nonvolatile        active
    Authentication Protocol: MD5
    Privacy Protocol: AES256
    Group-name: testgroup

    User name: sha1aes128
    Engine ID: 80000009030000XXXXXXXXXX
    storage-type: nonvolatile        active
    Authentication Protocol: SHA
    Privacy Protocol: AES128
    Group-name: testgroup

    User name: sha1aes192
    Engine ID: 80000009030000XXXXXXXXXX
    storage-type: nonvolatile        active
    Authentication Protocol: SHA
    Privacy Protocol: AES192
    Group-name: testgroup

    User name: sha1aes256
    Engine ID: 80000009030000XXXXXXXXXX
    storage-type: nonvolatile        active
    Authentication Protocol: SHA
    Privacy Protocol: AES256
    Group-name: testgroup


command:

    go test -run TestSNMPv3Session_SNMP_WalkChain -v -tags=integration -args -u md5des -a md5 -A XXXXXXXXXX -x des -X XXXXXXXXXX -h 192.168.XX.XXX

result:

    === RUN   TestSNMPv3Session_SNMP_WalkChain
        integration_test.go:476: -------- WalkChain from OID 1.3.6.1.2.1.2.2.1.2 V3 --------
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.1 = GigabitEthernet0/0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.2 = Null0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.3 = unrouted VLAN 1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.4 = unrouted VLAN 1002 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.5 = unrouted VLAN 1004 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.6 = unrouted VLAN 1005 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.7 = unrouted VLAN 1003 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.8 = TenGigabitEthernet1/0/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.9 = TenGigabitEthernet1/0/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.10 = TenGigabitEthernet1/0/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.11 = TenGigabitEthernet1/0/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.12 = TenGigabitEthernet1/0/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.13 = TenGigabitEthernet1/0/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.14 = TenGigabitEthernet1/0/7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.15 = TenGigabitEthernet1/0/8 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.16 = TenGigabitEthernet1/0/9 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.17 = TenGigabitEthernet1/0/10 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.18 = TenGigabitEthernet1/0/11 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.19 = TenGigabitEthernet1/0/12 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.20 = TenGigabitEthernet1/0/13 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.21 = TenGigabitEthernet1/0/14 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.22 = TenGigabitEthernet1/0/15 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.23 = TenGigabitEthernet1/0/16 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.24 = TenGigabitEthernet1/0/17 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.25 = TenGigabitEthernet1/0/18 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.26 = TenGigabitEthernet1/0/19 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.27 = TenGigabitEthernet1/0/20 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.28 = TenGigabitEthernet1/0/21 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.29 = TenGigabitEthernet1/0/22 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.30 = TenGigabitEthernet1/0/23 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.31 = TenGigabitEthernet1/0/24 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.32 = TenGigabitEthernet1/1/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.33 = TenGigabitEthernet1/1/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.34 = TenGigabitEthernet1/1/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.35 = TenGigabitEthernet1/1/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.36 = TenGigabitEthernet1/1/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.37 = TenGigabitEthernet1/1/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.38 = TenGigabitEthernet1/1/7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.39 = TenGigabitEthernet1/1/8 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.40 = FortyGigabitEthernet1/1/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.41 = FortyGigabitEthernet1/1/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.42 = StackPort1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.43 = StackSub-St1-1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.44 = StackSub-St1-2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.45 = Vlan1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.46 = Port-channel1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.47 = Vlan130 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.48 = unrouted VLAN 130 : Universal OCTET STRING
        integration_test.go:495: Results:  48
    --- PASS: TestSNMPv3Session_SNMP_WalkChain (0.04s)
    PASS
    ok      github.com/OlegPowerC/powersnmpv3       0.600s

command:

    go test -run TestSNMPv3Session_SNMP_WalkChain -v -tags=integration -args -u md5aes128 -a md5 -A XXXXXXXXXX -x aes -X XXXXXXXXXX -h 192.168.XX.XXX

result:

    === RUN   TestSNMPv3Session_SNMP_WalkChain
        integration_test.go:476: -------- WalkChain from OID 1.3.6.1.2.1.2.2.1.2 V3 --------
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.1 = GigabitEthernet0/0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.2 = Null0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.3 = unrouted VLAN 1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.4 = unrouted VLAN 1002 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.5 = unrouted VLAN 1004 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.6 = unrouted VLAN 1005 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.7 = unrouted VLAN 1003 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.8 = TenGigabitEthernet1/0/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.9 = TenGigabitEthernet1/0/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.10 = TenGigabitEthernet1/0/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.11 = TenGigabitEthernet1/0/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.12 = TenGigabitEthernet1/0/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.13 = TenGigabitEthernet1/0/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.14 = TenGigabitEthernet1/0/7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.15 = TenGigabitEthernet1/0/8 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.16 = TenGigabitEthernet1/0/9 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.17 = TenGigabitEthernet1/0/10 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.18 = TenGigabitEthernet1/0/11 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.19 = TenGigabitEthernet1/0/12 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.20 = TenGigabitEthernet1/0/13 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.21 = TenGigabitEthernet1/0/14 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.22 = TenGigabitEthernet1/0/15 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.23 = TenGigabitEthernet1/0/16 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.24 = TenGigabitEthernet1/0/17 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.25 = TenGigabitEthernet1/0/18 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.26 = TenGigabitEthernet1/0/19 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.27 = TenGigabitEthernet1/0/20 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.28 = TenGigabitEthernet1/0/21 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.29 = TenGigabitEthernet1/0/22 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.30 = TenGigabitEthernet1/0/23 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.31 = TenGigabitEthernet1/0/24 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.32 = TenGigabitEthernet1/1/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.33 = TenGigabitEthernet1/1/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.34 = TenGigabitEthernet1/1/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.35 = TenGigabitEthernet1/1/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.36 = TenGigabitEthernet1/1/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.37 = TenGigabitEthernet1/1/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.38 = TenGigabitEthernet1/1/7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.39 = TenGigabitEthernet1/1/8 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.40 = FortyGigabitEthernet1/1/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.41 = FortyGigabitEthernet1/1/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.42 = StackPort1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.43 = StackSub-St1-1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.44 = StackSub-St1-2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.45 = Vlan1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.46 = Port-channel1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.47 = Vlan130 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.48 = unrouted VLAN 130 : Universal OCTET STRING
        integration_test.go:495: Results:  48
    --- PASS: TestSNMPv3Session_SNMP_WalkChain (0.04s)
    PASS
    ok      github.com/OlegPowerC/powersnmpv3       0.611s

command:

    go test -run TestSNMPv3Session_SNMP_WalkChain -v -tags=integration -args -u md5aes192 -a md5 -A XXXXXXXXXX -x aes192 -X XXXXXXXXXX -h 192.168.XX.XXX

result:

    === RUN   TestSNMPv3Session_SNMP_WalkChain
        integration_test.go:476: -------- WalkChain from OID 1.3.6.1.2.1.2.2.1.2 V3 --------
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.1 = GigabitEthernet0/0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.2 = Null0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.3 = unrouted VLAN 1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.4 = unrouted VLAN 1002 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.5 = unrouted VLAN 1004 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.6 = unrouted VLAN 1005 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.7 = unrouted VLAN 1003 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.8 = TenGigabitEthernet1/0/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.9 = TenGigabitEthernet1/0/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.10 = TenGigabitEthernet1/0/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.11 = TenGigabitEthernet1/0/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.12 = TenGigabitEthernet1/0/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.13 = TenGigabitEthernet1/0/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.14 = TenGigabitEthernet1/0/7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.15 = TenGigabitEthernet1/0/8 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.16 = TenGigabitEthernet1/0/9 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.17 = TenGigabitEthernet1/0/10 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.18 = TenGigabitEthernet1/0/11 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.19 = TenGigabitEthernet1/0/12 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.20 = TenGigabitEthernet1/0/13 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.21 = TenGigabitEthernet1/0/14 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.22 = TenGigabitEthernet1/0/15 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.23 = TenGigabitEthernet1/0/16 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.24 = TenGigabitEthernet1/0/17 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.25 = TenGigabitEthernet1/0/18 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.26 = TenGigabitEthernet1/0/19 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.27 = TenGigabitEthernet1/0/20 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.28 = TenGigabitEthernet1/0/21 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.29 = TenGigabitEthernet1/0/22 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.30 = TenGigabitEthernet1/0/23 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.31 = TenGigabitEthernet1/0/24 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.32 = TenGigabitEthernet1/1/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.33 = TenGigabitEthernet1/1/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.34 = TenGigabitEthernet1/1/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.35 = TenGigabitEthernet1/1/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.36 = TenGigabitEthernet1/1/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.37 = TenGigabitEthernet1/1/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.38 = TenGigabitEthernet1/1/7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.39 = TenGigabitEthernet1/1/8 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.40 = FortyGigabitEthernet1/1/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.41 = FortyGigabitEthernet1/1/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.42 = StackPort1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.43 = StackSub-St1-1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.44 = StackSub-St1-2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.45 = Vlan1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.46 = Port-channel1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.47 = Vlan130 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.48 = unrouted VLAN 130 : Universal OCTET STRING
        integration_test.go:495: Results:  48
    --- PASS: TestSNMPv3Session_SNMP_WalkChain (0.05s)
    PASS
    ok      github.com/OlegPowerC/powersnmpv3       0.611s

command:

    go test -run TestSNMPv3Session_SNMP_WalkChain -v -tags=integration -args -u md5aes256 -a md5 -A XXXXXXXXXX -x aes256 -X XXXXXXXXXX -h 192.168.XX.XXX

result:

    === RUN   TestSNMPv3Session_SNMP_WalkChain
        integration_test.go:476: -------- WalkChain from OID 1.3.6.1.2.1.2.2.1.2 V3 --------
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.1 = GigabitEthernet0/0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.2 = Null0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.3 = unrouted VLAN 1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.4 = unrouted VLAN 1002 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.5 = unrouted VLAN 1004 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.6 = unrouted VLAN 1005 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.7 = unrouted VLAN 1003 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.8 = TenGigabitEthernet1/0/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.9 = TenGigabitEthernet1/0/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.10 = TenGigabitEthernet1/0/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.11 = TenGigabitEthernet1/0/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.12 = TenGigabitEthernet1/0/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.13 = TenGigabitEthernet1/0/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.14 = TenGigabitEthernet1/0/7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.15 = TenGigabitEthernet1/0/8 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.16 = TenGigabitEthernet1/0/9 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.17 = TenGigabitEthernet1/0/10 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.18 = TenGigabitEthernet1/0/11 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.19 = TenGigabitEthernet1/0/12 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.20 = TenGigabitEthernet1/0/13 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.21 = TenGigabitEthernet1/0/14 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.22 = TenGigabitEthernet1/0/15 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.23 = TenGigabitEthernet1/0/16 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.24 = TenGigabitEthernet1/0/17 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.25 = TenGigabitEthernet1/0/18 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.26 = TenGigabitEthernet1/0/19 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.27 = TenGigabitEthernet1/0/20 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.28 = TenGigabitEthernet1/0/21 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.29 = TenGigabitEthernet1/0/22 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.30 = TenGigabitEthernet1/0/23 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.31 = TenGigabitEthernet1/0/24 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.32 = TenGigabitEthernet1/1/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.33 = TenGigabitEthernet1/1/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.34 = TenGigabitEthernet1/1/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.35 = TenGigabitEthernet1/1/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.36 = TenGigabitEthernet1/1/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.37 = TenGigabitEthernet1/1/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.38 = TenGigabitEthernet1/1/7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.39 = TenGigabitEthernet1/1/8 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.40 = FortyGigabitEthernet1/1/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.41 = FortyGigabitEthernet1/1/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.42 = StackPort1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.43 = StackSub-St1-1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.44 = StackSub-St1-2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.45 = Vlan1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.46 = Port-channel1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.47 = Vlan130 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.48 = unrouted VLAN 130 : Universal OCTET STRING
        integration_test.go:495: Results:  48
    --- PASS: TestSNMPv3Session_SNMP_WalkChain (0.05s)
    PASS
    ok      github.com/OlegPowerC/powersnmpv3       0.606s

command:

    go test -run TestSNMPv3Session_SNMP_WalkChain -v -tags=integration -args -u sha1aes128 -a sha -A XXXXXXXXXX -x aes -X XXXXXXXXXX -h 192.168.XX.XXX

result:

    === RUN   TestSNMPv3Session_SNMP_WalkChain
        integration_test.go:476: -------- WalkChain from OID 1.3.6.1.2.1.2.2.1.2 V3 --------
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.1 = GigabitEthernet0/0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.2 = Null0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.3 = unrouted VLAN 1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.4 = unrouted VLAN 1002 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.5 = unrouted VLAN 1004 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.6 = unrouted VLAN 1005 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.7 = unrouted VLAN 1003 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.8 = TenGigabitEthernet1/0/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.9 = TenGigabitEthernet1/0/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.10 = TenGigabitEthernet1/0/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.11 = TenGigabitEthernet1/0/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.12 = TenGigabitEthernet1/0/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.13 = TenGigabitEthernet1/0/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.14 = TenGigabitEthernet1/0/7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.15 = TenGigabitEthernet1/0/8 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.16 = TenGigabitEthernet1/0/9 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.17 = TenGigabitEthernet1/0/10 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.18 = TenGigabitEthernet1/0/11 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.19 = TenGigabitEthernet1/0/12 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.20 = TenGigabitEthernet1/0/13 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.21 = TenGigabitEthernet1/0/14 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.22 = TenGigabitEthernet1/0/15 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.23 = TenGigabitEthernet1/0/16 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.24 = TenGigabitEthernet1/0/17 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.25 = TenGigabitEthernet1/0/18 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.26 = TenGigabitEthernet1/0/19 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.27 = TenGigabitEthernet1/0/20 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.28 = TenGigabitEthernet1/0/21 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.29 = TenGigabitEthernet1/0/22 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.30 = TenGigabitEthernet1/0/23 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.31 = TenGigabitEthernet1/0/24 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.32 = TenGigabitEthernet1/1/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.33 = TenGigabitEthernet1/1/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.34 = TenGigabitEthernet1/1/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.35 = TenGigabitEthernet1/1/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.36 = TenGigabitEthernet1/1/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.37 = TenGigabitEthernet1/1/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.38 = TenGigabitEthernet1/1/7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.39 = TenGigabitEthernet1/1/8 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.40 = FortyGigabitEthernet1/1/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.41 = FortyGigabitEthernet1/1/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.42 = StackPort1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.43 = StackSub-St1-1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.44 = StackSub-St1-2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.45 = Vlan1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.46 = Port-channel1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.47 = Vlan130 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.48 = unrouted VLAN 130 : Universal OCTET STRING
        integration_test.go:495: Results:  48
    --- PASS: TestSNMPv3Session_SNMP_WalkChain (0.04s)
    PASS
    ok      github.com/OlegPowerC/powersnmpv3       0.598s

command:

    go test -run TestSNMPv3Session_SNMP_WalkChain -v -tags=integration -args -u sha1aes192 -a sha -A XXXXXXXXXX -x aes192 -X XXXXXXXXXX -h 192.168.XX.XXX

result:

    === RUN   TestSNMPv3Session_SNMP_WalkChain
        integration_test.go:476: -------- WalkChain from OID 1.3.6.1.2.1.2.2.1.2 V3 --------
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.1 = GigabitEthernet0/0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.2 = Null0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.3 = unrouted VLAN 1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.4 = unrouted VLAN 1002 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.5 = unrouted VLAN 1004 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.6 = unrouted VLAN 1005 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.7 = unrouted VLAN 1003 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.8 = TenGigabitEthernet1/0/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.9 = TenGigabitEthernet1/0/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.10 = TenGigabitEthernet1/0/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.11 = TenGigabitEthernet1/0/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.12 = TenGigabitEthernet1/0/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.13 = TenGigabitEthernet1/0/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.14 = TenGigabitEthernet1/0/7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.15 = TenGigabitEthernet1/0/8 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.16 = TenGigabitEthernet1/0/9 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.17 = TenGigabitEthernet1/0/10 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.18 = TenGigabitEthernet1/0/11 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.19 = TenGigabitEthernet1/0/12 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.20 = TenGigabitEthernet1/0/13 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.21 = TenGigabitEthernet1/0/14 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.22 = TenGigabitEthernet1/0/15 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.23 = TenGigabitEthernet1/0/16 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.24 = TenGigabitEthernet1/0/17 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.25 = TenGigabitEthernet1/0/18 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.26 = TenGigabitEthernet1/0/19 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.27 = TenGigabitEthernet1/0/20 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.28 = TenGigabitEthernet1/0/21 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.29 = TenGigabitEthernet1/0/22 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.30 = TenGigabitEthernet1/0/23 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.31 = TenGigabitEthernet1/0/24 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.32 = TenGigabitEthernet1/1/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.33 = TenGigabitEthernet1/1/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.34 = TenGigabitEthernet1/1/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.35 = TenGigabitEthernet1/1/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.36 = TenGigabitEthernet1/1/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.37 = TenGigabitEthernet1/1/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.38 = TenGigabitEthernet1/1/7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.39 = TenGigabitEthernet1/1/8 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.40 = FortyGigabitEthernet1/1/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.41 = FortyGigabitEthernet1/1/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.42 = StackPort1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.43 = StackSub-St1-1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.44 = StackSub-St1-2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.45 = Vlan1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.46 = Port-channel1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.47 = Vlan130 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.48 = unrouted VLAN 130 : Universal OCTET STRING
        integration_test.go:495: Results:  48
    --- PASS: TestSNMPv3Session_SNMP_WalkChain (0.06s)
    PASS
    ok      github.com/OlegPowerC/powersnmpv3       0.646s

command:

    go test -run TestSNMPv3Session_SNMP_WalkChain -v -tags=integration -args -u sha1aes256 -a sha -A XXXXXXXXXX -x aes256 -X XXXXXXXXXX -h 192.168.XX.XXX

result:

    === RUN   TestSNMPv3Session_SNMP_WalkChain
        integration_test.go:476: -------- WalkChain from OID 1.3.6.1.2.1.2.2.1.2 V3 --------
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.1 = GigabitEthernet0/0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.2 = Null0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.3 = unrouted VLAN 1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.4 = unrouted VLAN 1002 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.5 = unrouted VLAN 1004 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.6 = unrouted VLAN 1005 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.7 = unrouted VLAN 1003 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.8 = TenGigabitEthernet1/0/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.9 = TenGigabitEthernet1/0/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.10 = TenGigabitEthernet1/0/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.11 = TenGigabitEthernet1/0/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.12 = TenGigabitEthernet1/0/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.13 = TenGigabitEthernet1/0/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.14 = TenGigabitEthernet1/0/7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.15 = TenGigabitEthernet1/0/8 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.16 = TenGigabitEthernet1/0/9 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.17 = TenGigabitEthernet1/0/10 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.18 = TenGigabitEthernet1/0/11 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.19 = TenGigabitEthernet1/0/12 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.20 = TenGigabitEthernet1/0/13 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.21 = TenGigabitEthernet1/0/14 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.22 = TenGigabitEthernet1/0/15 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.23 = TenGigabitEthernet1/0/16 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.24 = TenGigabitEthernet1/0/17 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.25 = TenGigabitEthernet1/0/18 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.26 = TenGigabitEthernet1/0/19 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.27 = TenGigabitEthernet1/0/20 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.28 = TenGigabitEthernet1/0/21 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.29 = TenGigabitEthernet1/0/22 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.30 = TenGigabitEthernet1/0/23 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.31 = TenGigabitEthernet1/0/24 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.32 = TenGigabitEthernet1/1/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.33 = TenGigabitEthernet1/1/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.34 = TenGigabitEthernet1/1/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.35 = TenGigabitEthernet1/1/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.36 = TenGigabitEthernet1/1/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.37 = TenGigabitEthernet1/1/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.38 = TenGigabitEthernet1/1/7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.39 = TenGigabitEthernet1/1/8 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.40 = FortyGigabitEthernet1/1/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.41 = FortyGigabitEthernet1/1/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.42 = StackPort1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.43 = StackSub-St1-1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.44 = StackSub-St1-2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.45 = Vlan1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.46 = Port-channel1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.47 = Vlan130 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.48 = unrouted VLAN 130 : Universal OCTET STRING
        integration_test.go:495: Results:  48
    --- PASS: TestSNMPv3Session_SNMP_WalkChain (0.05s)
    PASS
    ok      github.com/OlegPowerC/powersnmpv3       0.605s

### ASA

Name: "Chassis", DESCR: "ASA 5508-X with FirePOWER services, 8GE, AC, DES"
PID: ASA5508           , VID: V01     , SN: JMX19XXXXXX

USM Users:

    User name: sha224aes128
    Engine ID: 80000009feXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    storage-type: nonvolatile        active
    Authentication Protocol: SHA224
    Privacy Protocol:AES128
    Group-name: testgroup

    User name: sha384aes128
    Engine ID: 80000009feXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    storage-type: nonvolatile        active
    Authentication Protocol: SHA384
    Privacy Protocol:AES128
    Group-name: testgroup

    User name: sha384aes192
    Engine ID: 80000009feXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    storage-type: nonvolatile        active
    Authentication Protocol: SHA384
    Privacy Protocol:AES192
    Group-name: testgroup

    User name: sha384aes256
    Engine ID: 80000009feXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    storage-type: nonvolatile        active
    Authentication Protocol: SHA384
    Privacy Protocol:AES256
    Group-name: testgroup

command:

    go test -run TestSNMPv3Session_SNMP_WalkChain -v -tags=integration -args -u sha224aes128 -a sha224 -A XXXXXXXXXX -x aes -X XXXXXXXXXX -h 192.168.XX.XXX

result:

    === RUN   TestSNMPv3Session_SNMP_WalkChain
        integration_test.go:476: -------- WalkChain from OID 1.3.6.1.2.1.2.2.1.2 V3 --------
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.2 = Adaptive Security Appliance 'outside' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.3 = Adaptive Security Appliance 'inside' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.4 = Adaptive Security Appliance 'GigabitEthernet1/3' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.5 = Adaptive Security Appliance 'GigabitEthernet1/4' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.6 = Adaptive Security Appliance 'GigabitEthernet1/5' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.7 = Adaptive Security Appliance 'GigabitEthernet1/6' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.8 = Adaptive Security Appliance 'GigabitEthernet1/7' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.9 = Adaptive Security Appliance 'GigabitEthernet1/8' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.10 = Adaptive Security Appliance 'asa_mgmt_plane' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.11 = Adaptive Security Appliance 'Internal-Data1/2' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.12 = Adaptive Security Appliance 'cplane' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.13 = Adaptive Security Appliance 'mgmt_plane_int_tap' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.14 = Adaptive Security Appliance 'Management1/1' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.15 = Adaptive Security Appliance 'nlp_int_tap' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.16 = Adaptive Security Appliance '_internal_loopback' interface : Universal OCTET STRING
        integration_test.go:495: Results:  15
    --- PASS: TestSNMPv3Session_SNMP_WalkChain (0.43s)
    PASS
    ok      github.com/OlegPowerC/powersnmpv3       0.992


command:

    go test -run TestSNMPv3Session_SNMP_WalkChain -v -tags=integration -args -u sha384aes128 -a sha384 -A XXXXXXXXXX -x aes -X XXXXXXXXXX -h 192.168.XX.XXX        

result:

    === RUN   TestSNMPv3Session_SNMP_WalkChain
        integration_test.go:476: -------- WalkChain from OID 1.3.6.1.2.1.2.2.1.2 V3 --------
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.2 = Adaptive Security Appliance 'outside' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.3 = Adaptive Security Appliance 'inside' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.4 = Adaptive Security Appliance 'GigabitEthernet1/3' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.5 = Adaptive Security Appliance 'GigabitEthernet1/4' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.6 = Adaptive Security Appliance 'GigabitEthernet1/5' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.7 = Adaptive Security Appliance 'GigabitEthernet1/6' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.8 = Adaptive Security Appliance 'GigabitEthernet1/7' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.9 = Adaptive Security Appliance 'GigabitEthernet1/8' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.10 = Adaptive Security Appliance 'asa_mgmt_plane' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.11 = Adaptive Security Appliance 'Internal-Data1/2' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.12 = Adaptive Security Appliance 'cplane' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.13 = Adaptive Security Appliance 'mgmt_plane_int_tap' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.14 = Adaptive Security Appliance 'Management1/1' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.15 = Adaptive Security Appliance 'nlp_int_tap' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.16 = Adaptive Security Appliance '_internal_loopback' interface : Universal OCTET STRING
        integration_test.go:495: Results:  15
    --- PASS: TestSNMPv3Session_SNMP_WalkChain (0.43s)
    PASS
    ok      github.com/OlegPowerC/powersnmpv3       0.993s

command:

    go test -run TestSNMPv3Session_SNMP_WalkChain -v -tags=integration -args -u sha384aes192 -a sha384 -A XXXXXXXXXX -x aes192 -X XXXXXXXXXX -h 192.168.XX.XXX

result:

    === RUN   TestSNMPv3Session_SNMP_WalkChain
        integration_test.go:476: -------- WalkChain from OID 1.3.6.1.2.1.2.2.1.2 V3 --------
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.2 = Adaptive Security Appliance 'outside' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.3 = Adaptive Security Appliance 'inside' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.4 = Adaptive Security Appliance 'GigabitEthernet1/3' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.5 = Adaptive Security Appliance 'GigabitEthernet1/4' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.6 = Adaptive Security Appliance 'GigabitEthernet1/5' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.7 = Adaptive Security Appliance 'GigabitEthernet1/6' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.8 = Adaptive Security Appliance 'GigabitEthernet1/7' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.9 = Adaptive Security Appliance 'GigabitEthernet1/8' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.10 = Adaptive Security Appliance 'asa_mgmt_plane' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.11 = Adaptive Security Appliance 'Internal-Data1/2' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.12 = Adaptive Security Appliance 'cplane' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.13 = Adaptive Security Appliance 'mgmt_plane_int_tap' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.14 = Adaptive Security Appliance 'Management1/1' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.15 = Adaptive Security Appliance 'nlp_int_tap' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.16 = Adaptive Security Appliance '_internal_loopback' interface : Universal OCTET STRING
        integration_test.go:495: Results:  15
    --- PASS: TestSNMPv3Session_SNMP_WalkChain (0.43s)
    PASS
    ok      github.com/OlegPowerC/powersnmpv3       1.043s

Command:

    go test -run TestSNMPv3Session_SNMP_WalkChain -v -tags=integration -args -u sha384aes256 -a sha384 -A XXXXXXXXXX -x aes256 -X XXXXXXXXXX -h 192.168.XX.XXX

Result:

    === RUN   TestSNMPv3Session_SNMP_WalkChain
        integration_test.go:476: -------- WalkChain from OID 1.3.6.1.2.1.2.2.1.2 V3 --------
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.2 = Adaptive Security Appliance 'outside' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.3 = Adaptive Security Appliance 'inside' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.4 = Adaptive Security Appliance 'GigabitEthernet1/3' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.5 = Adaptive Security Appliance 'GigabitEthernet1/4' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.6 = Adaptive Security Appliance 'GigabitEthernet1/5' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.7 = Adaptive Security Appliance 'GigabitEthernet1/6' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.8 = Adaptive Security Appliance 'GigabitEthernet1/7' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.9 = Adaptive Security Appliance 'GigabitEthernet1/8' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.10 = Adaptive Security Appliance 'asa_mgmt_plane' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.11 = Adaptive Security Appliance 'Internal-Data1/2' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.12 = Adaptive Security Appliance 'cplane' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.13 = Adaptive Security Appliance 'mgmt_plane_int_tap' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.14 = Adaptive Security Appliance 'Management1/1' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.15 = Adaptive Security Appliance 'nlp_int_tap' interface : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.16 = Adaptive Security Appliance '_internal_loopback' interface : Universal OCTET STRING
        integration_test.go:495: Results:  15
    --- PASS: TestSNMPv3Session_SNMP_WalkChain (0.42s)
    PASS
    ok      github.com/OlegPowerC/powersnmpv3       0.999s


## Huawei

*Some data is masked (Engine ID, IP addresses, passwords)
Test do throught VPN

### Switch

    --------------------------------------------------------------------------------
    MemberID Role     MAC              Priority   DeviceType         Description
    --------------------------------------------------------------------------------
    1        Master   3037-XXXX-XXXX   200        S5735-S24P4XE-V2
    2        Standby  3037-XXXX-XXXX   100        S5735-S24P4XE-V2
    --------------------------------------------------------------------------------

USM Users:

    User name: md5aes192
    Engine ID: 800007XXXXXXXXXXXXXXXX active
    Authentication Protocol: md5
    Privacy Protocol: aes192
    Group name: SNMPv3-G
    State: Active
    
    User name: md5aes256
    Engine ID: 800007XXXXXXXXXXXXXXXX active
    Authentication Protocol: md5
    Privacy Protocol: aes256
    Group name: SNMPv3-G
    State: Active
    
    User name: sha224aes256
    Engine ID: 800007XXXXXXXXXXXXXXXX active
    Authentication Protocol: sha2-224
    Privacy Protocol: aes256
    Group name: SNMPv3-G
    State: Active
    
    User name: sha256aes256
    Engine ID: 800007XXXXXXXXXXXXXXXX active
    Authentication Protocol: sha2-256
    Privacy Protocol: aes256
    Group name: SNMPv3-G
    State: Active
    
    User name: sha384aes128
    Engine ID: 800007XXXXXXXXXXXXXXXX active
    Authentication Protocol: sha2-384
    Privacy Protocol: aes128
    Group name: SNMPv3-G
    State: Active
    
    User name: sha384aes192
    Engine ID: 800007XXXXXXXXXXXXXXXX active
    Authentication Protocol: sha2-384
    Privacy Protocol: aes192
    Group name: SNMPv3-G
    State: Active
    
    User name: sha384aes256
    Engine ID: 800007XXXXXXXXXXXXXXXX active
    Authentication Protocol: sha2-384
    Privacy Protocol: aes256
    Group name: SNMPv3-G
    State: Active
    
    User name: sha512aes128
    Engine ID: 800007XXXXXXXXXXXXXXXX active
    Authentication Protocol: sha2-512
    Privacy Protocol: aes128
    Group name: SNMPv3-G
    State: Active
    
    User name: sha512aes192
    Engine ID: 800007XXXXXXXXXXXXXXXX active
    Authentication Protocol: sha2-512
    Privacy Protocol: aes192
    Group name: SNMPv3-G
    State: Active
    
    User name: sha512aes256
    Engine ID: 800007XXXXXXXXXXXXXXXX active
    Authentication Protocol: sha2-512
    Privacy Protocol: aes256
    Group name: SNMPv3-G
    State: Active

Command:

    go test -run TestSNMPv3Session_SNMP_WalkChain -v -tags=integration -args -u sha512aes256 -a sha512 -A XXXXXXXXXX -x aes256a -X XXXXXXXXXX -h 192.168.XX.XXX

Result:

    === RUN   TestSNMPv3Session_SNMP_WalkChain
        integration_test.go:476: -------- WalkChain from OID 1.3.6.1.2.1.2.2.1.2 V3 --------
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.1 = GE1/0/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.2 = GE1/0/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.3 = GE1/0/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.4 = GE1/0/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.5 = GE1/0/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.6 = GE1/0/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.7 = GE1/0/7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.8 = GE1/0/8 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.9 = GE1/0/9 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.10 = GE1/0/10 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.11 = GE1/0/11 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.12 = GE1/0/12 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.13 = GE1/0/13 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.14 = GE1/0/14 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.15 = GE1/0/15 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.16 = GE1/0/16 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.17 = GE1/0/17 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.18 = GE1/0/18 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.19 = GE1/0/19 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.20 = GE1/0/20 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.21 = GE1/0/21 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.22 = GE1/0/22 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.23 = GE1/0/23 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.24 = GE1/0/24 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.25 = 10GE1/0/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.26 = 10GE1/0/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.27 = 10GE1/0/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.28 = 10GE1/0/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.29 = 10GE1/0/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.30 = 10GE1/0/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.31 = NULL0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.32 = InLoopBack0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.33 = Stack-Port1/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.34 = Stack-Port1/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.35 = GE2/0/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.36 = GE2/0/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.37 = GE2/0/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.38 = GE2/0/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.39 = GE2/0/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.40 = GE2/0/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.41 = GE2/0/7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.42 = GE2/0/8 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.43 = GE2/0/9 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.44 = GE2/0/10 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.45 = GE2/0/11 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.46 = GE2/0/12 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.47 = GE2/0/13 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.48 = GE2/0/14 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.49 = GE2/0/15 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.50 = GE2/0/16 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.51 = GE2/0/17 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.52 = GE2/0/18 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.53 = GE2/0/19 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.54 = GE2/0/20 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.55 = GE2/0/21 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.56 = GE2/0/22 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.57 = GE2/0/23 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.58 = GE2/0/24 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.59 = 10GE2/0/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.60 = 10GE2/0/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.61 = 10GE2/0/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.62 = 10GE2/0/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.63 = 10GE2/0/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.64 = 10GE2/0/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.65 = Stack-Port2/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.66 = Stack-Port2/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.67 = Vlanif2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.68 = Eth-Trunk100 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.69 = Vlanif1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.70 = Vlanif3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.71 = Vlanif4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.72 = Vlanif5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.73 = Vlanif6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.74 = Vlanif7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.75 = Vlanif9 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.76 = Vlanif10 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.77 = Vlanif11 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.78 = Vlanif16 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.79 = Vlanif17 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.80 = Vlanif20 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.81 = Vlanif21 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.82 = Vlanif100 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.83 = Vlanif103 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.84 = Vlanif140 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.85 = Vlanif146 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.86 = Vlanif147 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.87 = Eth-Trunk20 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.88 = Eth-Trunk21 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.89 = Eth-Trunk22 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.90 = Eth-Trunk23 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.91 = Eth-Trunk24 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.92 = Vlanif98 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.93 = Eth-Trunk109 : Universal OCTET STRING
        integration_test.go:495: Results:  93
    --- PASS: TestSNMPv3Session_SNMP_WalkChain (0.66s)
    PASS
    ok      github.com/OlegPowerC/powersnmpv3       1.239s


Command:

    go test -run TestSNMPv3Session_SNMP_WalkChain -v -tags=integration -args -u sha512aes128 -a sha512 -A XXXXXXXXXX -x aes -X XXXXXXXXXX -h 192.168.XX.XXX

Result:

    === RUN   TestSNMPv3Session_SNMP_WalkChain
        integration_test.go:476: -------- WalkChain from OID 1.3.6.1.2.1.2.2.1.2 V3 --------
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.1 = GE1/0/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.2 = GE1/0/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.3 = GE1/0/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.4 = GE1/0/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.5 = GE1/0/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.6 = GE1/0/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.7 = GE1/0/7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.8 = GE1/0/8 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.9 = GE1/0/9 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.10 = GE1/0/10 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.11 = GE1/0/11 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.12 = GE1/0/12 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.13 = GE1/0/13 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.14 = GE1/0/14 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.15 = GE1/0/15 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.16 = GE1/0/16 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.17 = GE1/0/17 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.18 = GE1/0/18 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.19 = GE1/0/19 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.20 = GE1/0/20 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.21 = GE1/0/21 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.22 = GE1/0/22 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.23 = GE1/0/23 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.24 = GE1/0/24 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.25 = 10GE1/0/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.26 = 10GE1/0/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.27 = 10GE1/0/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.28 = 10GE1/0/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.29 = 10GE1/0/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.30 = 10GE1/0/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.31 = NULL0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.32 = InLoopBack0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.33 = Stack-Port1/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.34 = Stack-Port1/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.35 = GE2/0/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.36 = GE2/0/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.37 = GE2/0/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.38 = GE2/0/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.39 = GE2/0/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.40 = GE2/0/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.41 = GE2/0/7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.42 = GE2/0/8 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.43 = GE2/0/9 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.44 = GE2/0/10 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.45 = GE2/0/11 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.46 = GE2/0/12 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.47 = GE2/0/13 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.48 = GE2/0/14 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.49 = GE2/0/15 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.50 = GE2/0/16 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.51 = GE2/0/17 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.52 = GE2/0/18 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.53 = GE2/0/19 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.54 = GE2/0/20 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.55 = GE2/0/21 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.56 = GE2/0/22 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.57 = GE2/0/23 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.58 = GE2/0/24 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.59 = 10GE2/0/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.60 = 10GE2/0/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.61 = 10GE2/0/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.62 = 10GE2/0/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.63 = 10GE2/0/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.64 = 10GE2/0/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.65 = Stack-Port2/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.66 = Stack-Port2/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.67 = Vlanif2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.68 = Eth-Trunk100 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.69 = Vlanif1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.70 = Vlanif3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.71 = Vlanif4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.72 = Vlanif5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.73 = Vlanif6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.74 = Vlanif7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.75 = Vlanif9 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.76 = Vlanif10 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.77 = Vlanif11 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.78 = Vlanif16 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.79 = Vlanif17 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.80 = Vlanif20 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.81 = Vlanif21 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.82 = Vlanif100 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.83 = Vlanif103 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.84 = Vlanif140 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.85 = Vlanif146 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.86 = Vlanif147 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.87 = Eth-Trunk20 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.88 = Eth-Trunk21 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.89 = Eth-Trunk22 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.90 = Eth-Trunk23 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.91 = Eth-Trunk24 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.92 = Vlanif98 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.93 = Eth-Trunk109 : Universal OCTET STRING
        integration_test.go:495: Results:  93
    --- PASS: TestSNMPv3Session_SNMP_WalkChain (0.75s)
    PASS
    ok      github.com/OlegPowerC/powersnmpv3       1.416s

Command:

    go test -run TestSNMPv3Session_SNMP_WalkChain -v -tags=integration -args -u sha512aes192 -a sha512 -A XXXXXXXXXX -x aes192a -X XXXXXXXXXX -h 192.168.XX.XXX

Result:

    === RUN   TestSNMPv3Session_SNMP_WalkChain
    integration_test.go:476: -------- WalkChain from OID 1.3.6.1.2.1.2.2.1.2 V3 --------
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.1 = GE1/0/1 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.2 = GE1/0/2 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.3 = GE1/0/3 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.4 = GE1/0/4 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.5 = GE1/0/5 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.6 = GE1/0/6 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.7 = GE1/0/7 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.8 = GE1/0/8 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.9 = GE1/0/9 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.10 = GE1/0/10 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.11 = GE1/0/11 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.12 = GE1/0/12 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.13 = GE1/0/13 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.14 = GE1/0/14 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.15 = GE1/0/15 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.16 = GE1/0/16 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.17 = GE1/0/17 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.18 = GE1/0/18 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.19 = GE1/0/19 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.20 = GE1/0/20 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.21 = GE1/0/21 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.22 = GE1/0/22 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.23 = GE1/0/23 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.24 = GE1/0/24 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.25 = 10GE1/0/1 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.26 = 10GE1/0/2 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.27 = 10GE1/0/3 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.28 = 10GE1/0/4 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.29 = 10GE1/0/5 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.30 = 10GE1/0/6 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.31 = NULL0 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.32 = InLoopBack0 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.33 = Stack-Port1/1 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.34 = Stack-Port1/2 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.35 = GE2/0/1 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.36 = GE2/0/2 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.37 = GE2/0/3 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.38 = GE2/0/4 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.39 = GE2/0/5 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.40 = GE2/0/6 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.41 = GE2/0/7 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.42 = GE2/0/8 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.43 = GE2/0/9 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.44 = GE2/0/10 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.45 = GE2/0/11 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.46 = GE2/0/12 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.47 = GE2/0/13 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.48 = GE2/0/14 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.49 = GE2/0/15 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.50 = GE2/0/16 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.51 = GE2/0/17 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.52 = GE2/0/18 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.53 = GE2/0/19 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.54 = GE2/0/20 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.55 = GE2/0/21 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.56 = GE2/0/22 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.57 = GE2/0/23 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.58 = GE2/0/24 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.59 = 10GE2/0/1 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.60 = 10GE2/0/2 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.61 = 10GE2/0/3 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.62 = 10GE2/0/4 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.63 = 10GE2/0/5 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.64 = 10GE2/0/6 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.65 = Stack-Port2/1 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.66 = Stack-Port2/2 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.67 = Vlanif2 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.68 = Eth-Trunk100 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.69 = Vlanif1 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.70 = Vlanif3 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.71 = Vlanif4 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.72 = Vlanif5 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.73 = Vlanif6 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.74 = Vlanif7 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.75 = Vlanif9 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.76 = Vlanif10 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.77 = Vlanif11 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.78 = Vlanif16 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.79 = Vlanif17 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.80 = Vlanif20 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.81 = Vlanif21 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.82 = Vlanif100 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.83 = Vlanif103 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.84 = Vlanif140 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.85 = Vlanif146 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.86 = Vlanif147 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.87 = Eth-Trunk20 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.88 = Eth-Trunk21 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.89 = Eth-Trunk22 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.90 = Eth-Trunk23 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.91 = Eth-Trunk24 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.92 = Vlanif98 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.93 = Eth-Trunk109 : Universal OCTET STRING
    integration_test.go:495: Results:  93
    --- PASS: TestSNMPv3Session_SNMP_WalkChain (0.71s)
    PASS
    ok      github.com/OlegPowerC/powersnmpv3       1.277s

Command:

    go test -run TestSNMPv3Session_SNMP_WalkChain -v -tags=integration -args -u md5aes192 -a md5 -A XXXXXXXXXX -x aes192a -X XXXXXXXXXX -h 192.168.XX.XXX 

Result:

    === RUN   TestSNMPv3Session_SNMP_WalkChain
        integration_test.go:476: -------- WalkChain from OID 1.3.6.1.2.1.2.2.1.2 V3 --------
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.1 = GE1/0/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.2 = GE1/0/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.3 = GE1/0/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.4 = GE1/0/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.5 = GE1/0/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.6 = GE1/0/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.7 = GE1/0/7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.8 = GE1/0/8 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.9 = GE1/0/9 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.10 = GE1/0/10 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.11 = GE1/0/11 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.12 = GE1/0/12 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.13 = GE1/0/13 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.14 = GE1/0/14 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.15 = GE1/0/15 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.16 = GE1/0/16 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.17 = GE1/0/17 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.18 = GE1/0/18 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.19 = GE1/0/19 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.20 = GE1/0/20 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.21 = GE1/0/21 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.22 = GE1/0/22 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.23 = GE1/0/23 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.24 = GE1/0/24 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.25 = 10GE1/0/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.26 = 10GE1/0/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.27 = 10GE1/0/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.28 = 10GE1/0/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.29 = 10GE1/0/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.30 = 10GE1/0/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.31 = NULL0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.32 = InLoopBack0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.33 = Stack-Port1/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.34 = Stack-Port1/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.35 = GE2/0/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.36 = GE2/0/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.37 = GE2/0/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.38 = GE2/0/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.39 = GE2/0/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.40 = GE2/0/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.41 = GE2/0/7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.42 = GE2/0/8 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.43 = GE2/0/9 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.44 = GE2/0/10 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.45 = GE2/0/11 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.46 = GE2/0/12 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.47 = GE2/0/13 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.48 = GE2/0/14 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.49 = GE2/0/15 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.50 = GE2/0/16 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.51 = GE2/0/17 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.52 = GE2/0/18 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.53 = GE2/0/19 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.54 = GE2/0/20 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.55 = GE2/0/21 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.56 = GE2/0/22 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.57 = GE2/0/23 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.58 = GE2/0/24 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.59 = 10GE2/0/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.60 = 10GE2/0/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.61 = 10GE2/0/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.62 = 10GE2/0/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.63 = 10GE2/0/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.64 = 10GE2/0/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.65 = Stack-Port2/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.66 = Stack-Port2/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.67 = Vlanif2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.68 = Eth-Trunk100 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.69 = Vlanif1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.70 = Vlanif3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.71 = Vlanif4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.72 = Vlanif5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.73 = Vlanif6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.74 = Vlanif7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.75 = Vlanif9 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.76 = Vlanif10 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.77 = Vlanif11 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.78 = Vlanif16 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.79 = Vlanif17 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.80 = Vlanif20 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.81 = Vlanif21 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.82 = Vlanif100 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.83 = Vlanif103 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.84 = Vlanif140 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.85 = Vlanif146 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.86 = Vlanif147 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.87 = Eth-Trunk20 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.88 = Eth-Trunk21 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.89 = Eth-Trunk22 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.90 = Eth-Trunk23 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.91 = Eth-Trunk24 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.92 = Vlanif98 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.93 = Eth-Trunk109 : Universal OCTET STRING
        integration_test.go:495: Results:  93
    --- PASS: TestSNMPv3Session_SNMP_WalkChain (0.69s)
    PASS
    ok      github.com/OlegPowerC/powersnmpv3       1.266s

Command:

    go test -run TestSNMPv3Session_SNMP_WalkChain -v -tags=integration -args -u md5aes256 -a md5 -A XXXXXXXXXX -x aes256a -X XXXXXXXXXX -h 192.168.XX.XXX

Result:

    === RUN   TestSNMPv3Session_SNMP_WalkChain
        integration_test.go:476: -------- WalkChain from OID 1.3.6.1.2.1.2.2.1.2 V3 --------
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.1 = GE1/0/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.2 = GE1/0/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.3 = GE1/0/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.4 = GE1/0/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.5 = GE1/0/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.6 = GE1/0/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.7 = GE1/0/7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.8 = GE1/0/8 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.9 = GE1/0/9 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.10 = GE1/0/10 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.11 = GE1/0/11 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.12 = GE1/0/12 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.13 = GE1/0/13 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.14 = GE1/0/14 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.15 = GE1/0/15 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.16 = GE1/0/16 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.17 = GE1/0/17 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.18 = GE1/0/18 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.19 = GE1/0/19 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.20 = GE1/0/20 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.21 = GE1/0/21 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.22 = GE1/0/22 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.23 = GE1/0/23 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.24 = GE1/0/24 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.25 = 10GE1/0/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.26 = 10GE1/0/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.27 = 10GE1/0/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.28 = 10GE1/0/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.29 = 10GE1/0/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.30 = 10GE1/0/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.31 = NULL0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.32 = InLoopBack0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.33 = Stack-Port1/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.34 = Stack-Port1/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.35 = GE2/0/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.36 = GE2/0/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.37 = GE2/0/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.38 = GE2/0/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.39 = GE2/0/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.40 = GE2/0/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.41 = GE2/0/7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.42 = GE2/0/8 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.43 = GE2/0/9 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.44 = GE2/0/10 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.45 = GE2/0/11 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.46 = GE2/0/12 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.47 = GE2/0/13 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.48 = GE2/0/14 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.49 = GE2/0/15 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.50 = GE2/0/16 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.51 = GE2/0/17 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.52 = GE2/0/18 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.53 = GE2/0/19 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.54 = GE2/0/20 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.55 = GE2/0/21 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.56 = GE2/0/22 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.57 = GE2/0/23 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.58 = GE2/0/24 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.59 = 10GE2/0/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.60 = 10GE2/0/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.61 = 10GE2/0/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.62 = 10GE2/0/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.63 = 10GE2/0/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.64 = 10GE2/0/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.65 = Stack-Port2/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.66 = Stack-Port2/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.67 = Vlanif2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.68 = Eth-Trunk100 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.69 = Vlanif1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.70 = Vlanif3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.71 = Vlanif4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.72 = Vlanif5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.73 = Vlanif6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.74 = Vlanif7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.75 = Vlanif9 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.76 = Vlanif10 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.77 = Vlanif11 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.78 = Vlanif16 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.79 = Vlanif17 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.80 = Vlanif20 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.81 = Vlanif21 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.82 = Vlanif100 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.83 = Vlanif103 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.84 = Vlanif140 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.85 = Vlanif146 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.86 = Vlanif147 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.87 = Eth-Trunk20 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.88 = Eth-Trunk21 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.89 = Eth-Trunk22 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.90 = Eth-Trunk23 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.91 = Eth-Trunk24 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.92 = Vlanif98 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.93 = Eth-Trunk109 : Universal OCTET STRING
        integration_test.go:495: Results:  93
    --- PASS: TestSNMPv3Session_SNMP_WalkChain (0.67s)
    PASS
    ok      github.com/OlegPowerC/powersnmpv3       1.227s

Command:

    go test -run TestSNMPv3Session_SNMP_WalkChain -v -tags=integration -args -u sha384aes192 -a sha384 -A XXXXXXXXXX -x aes192a -X XXXXXXXXXX -h 192.168.XX.XXX

Result:

    === RUN   TestSNMPv3Session_SNMP_WalkChain
        integration_test.go:476: -------- WalkChain from OID 1.3.6.1.2.1.2.2.1.2 V3 --------
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.1 = GE1/0/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.2 = GE1/0/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.3 = GE1/0/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.4 = GE1/0/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.5 = GE1/0/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.6 = GE1/0/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.7 = GE1/0/7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.8 = GE1/0/8 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.9 = GE1/0/9 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.10 = GE1/0/10 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.11 = GE1/0/11 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.12 = GE1/0/12 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.13 = GE1/0/13 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.14 = GE1/0/14 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.15 = GE1/0/15 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.16 = GE1/0/16 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.17 = GE1/0/17 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.18 = GE1/0/18 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.19 = GE1/0/19 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.20 = GE1/0/20 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.21 = GE1/0/21 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.22 = GE1/0/22 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.23 = GE1/0/23 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.24 = GE1/0/24 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.25 = 10GE1/0/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.26 = 10GE1/0/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.27 = 10GE1/0/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.28 = 10GE1/0/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.29 = 10GE1/0/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.30 = 10GE1/0/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.31 = NULL0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.32 = InLoopBack0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.33 = Stack-Port1/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.34 = Stack-Port1/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.35 = GE2/0/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.36 = GE2/0/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.37 = GE2/0/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.38 = GE2/0/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.39 = GE2/0/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.40 = GE2/0/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.41 = GE2/0/7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.42 = GE2/0/8 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.43 = GE2/0/9 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.44 = GE2/0/10 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.45 = GE2/0/11 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.46 = GE2/0/12 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.47 = GE2/0/13 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.48 = GE2/0/14 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.49 = GE2/0/15 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.50 = GE2/0/16 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.51 = GE2/0/17 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.52 = GE2/0/18 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.53 = GE2/0/19 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.54 = GE2/0/20 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.55 = GE2/0/21 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.56 = GE2/0/22 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.57 = GE2/0/23 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.58 = GE2/0/24 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.59 = 10GE2/0/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.60 = 10GE2/0/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.61 = 10GE2/0/3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.62 = 10GE2/0/4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.63 = 10GE2/0/5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.64 = 10GE2/0/6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.65 = Stack-Port2/1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.66 = Stack-Port2/2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.67 = Vlanif2 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.68 = Eth-Trunk100 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.69 = Vlanif1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.70 = Vlanif3 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.71 = Vlanif4 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.72 = Vlanif5 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.73 = Vlanif6 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.74 = Vlanif7 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.75 = Vlanif9 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.76 = Vlanif10 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.77 = Vlanif11 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.78 = Vlanif16 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.79 = Vlanif17 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.80 = Vlanif20 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.81 = Vlanif21 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.82 = Vlanif100 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.83 = Vlanif103 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.84 = Vlanif140 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.85 = Vlanif146 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.86 = Vlanif147 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.87 = Eth-Trunk20 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.88 = Eth-Trunk21 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.89 = Eth-Trunk22 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.90 = Eth-Trunk23 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.91 = Eth-Trunk24 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.92 = Vlanif98 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.93 = Eth-Trunk109 : Universal OCTET STRING
        integration_test.go:495: Results:  93
    --- PASS: TestSNMPv3Session_SNMP_WalkChain (0.68s)
    PASS
    ok      github.com/OlegPowerC/powersnmpv3       1.243s

## Net-SNMP 5.9

**snmpd.conf**

    createUser sha512aes256 SHA-512 "XXXXXXXXXX" AES-256 "XXXXXXXXXX"
    createUser sha1aes192   SHA     "XXXXXXXXXX" AES-192 "XXXXXXXXXX"
    createUser sha1aes192c   SHA     "XXXXXXXXXX" AES-192-C "XXXXXXXXXX"

    rouser sha512aes256 priv
    rouser sha1aes192 priv
    rouser sha1aes192c priv


Command:

    go test -run TestSNMPv3Session_SNMP_WalkChain -v -tags=integration -args -u sha512aes256 -a sha512 -A XXXXXXXXXX -x aes256a -X XXXXXXXXXX -h 192.168.XX.XXX

Result:

    === RUN   TestSNMPv3Session_SNMP_WalkChain
        integration_test.go:476: -------- WalkChain from OID 1.3.6.1.2.1.2.2.1.2 V3 --------
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.1 = lo : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.2 = eno1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.3 = enp4s0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.4 = enp1s0f0np0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.5 = enp1s0f1np1 : Universal OCTET STRING
        integration_test.go:495: Results:  5
    --- PASS: TestSNMPv3Session_SNMP_WalkChain (0.03s)
    PASS
    ok      github.com/OlegPowerC/powersnmpv3       0.606s

Command:

    go test -run TestSNMPv3Session_SNMP_WalkChain -v -tags=integration -args -u sha1aes192 -a sha -A XXXXXXXXXX -x aes192a -X XXXXXXXXXX -h 192.168.XX.XXX        

Result:

    === RUN   TestSNMPv3Session_SNMP_WalkChain
        integration_test.go:476: -------- WalkChain from OID 1.3.6.1.2.1.2.2.1.2 V3 --------
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.1 = lo : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.2 = eno1 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.3 = enp4s0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.4 = enp1s0f0np0 : Universal OCTET STRING
        integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.5 = enp1s0f1np1 : Universal OCTET STRING
        integration_test.go:495: Results:  5
    --- PASS: TestSNMPv3Session_SNMP_WalkChain (0.03s)
    PASS
    ok      github.com/OlegPowerC/powersnmpv3       0.577s

Command:

    go test -run TestSNMPv3Session_SNMP_WalkChain -v -tags=integration -args -u sha1aes192c -a sha -A XXXXXXXXXX -x aes192 -X XXXXXXXXXX -h 192.168.XX.XXX         

Result:

    === RUN   TestSNMPv3Session_SNMP_WalkChain
    integration_test.go:476: -------- WalkChain from OID 1.3.6.1.2.1.2.2.1.2 V3 --------
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.1 = lo : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.2 = eno1 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.3 = enp4s0 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.4 = enp1s0f0np0 : Universal OCTET STRING
    integration_test.go:492: 1.3.6.1.2.1.2.2.1.2.5 = enp1s0f1np1 : Universal OCTET STRING
    integration_test.go:495: Results:  5
    --- PASS: TestSNMPv3Session_SNMP_WalkChain (0.04s)
    PASS
    ok      github.com/OlegPowerC/powersnmpv3       0.607s