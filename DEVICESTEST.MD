### Switches
#### PowerSNMPv3 version 1.2.7
##### Telefly TL-7164PGM-8FC
Switch support SNMP v2/v3, v3 auth: none/sha/aes priv: non/des  
**snmp community/users**

         Name            Group Name      Auth Priv
                                         Meth Meth    Remote Engine ID
    ----------------- ------------------ ---- ---- -------------------------
    desu              DefaultRead        SHA  DES  8000113d03c8390d045778
    desao             DefaultRead        SHA       8000113d03c8390d045778
    desua             DefaultRead        MD5  DES  8000113d03c8390d045778
    noanop            DefaultRead                  8000113d03c8390d045778

    
    Community-String     Community-Access View Name        IP Address
    -------------------- ---------------- ---------------- ----------------
    public123            Read Only        Default          All

Walk test for root OID 1.3.6.1.2.1.1.9.1.2:  

    1.3.6.1.2.1.1.9.1.2.1 = 1.3.6.1.6.3.1 : Universal OID  
    1.3.6.1.2.1.1.9.1.2.2 = 1.3.6.1.2.1.16.20.8 : Universal OID  
    1.3.6.1.2.1.1.9.1.2.3 = 1.3.6.1.2.1.16.20.5 : Universal OID  
    1.3.6.1.2.1.1.9.1.2.4 = 1.3.6.1.2.1.16.29 : Universal OID  
    1.3.6.1.2.1.1.9.1.2.5 = 1.3.6.1.2.1.78 : Universal OID  
    1.3.6.1.2.1.1.9.1.2.6 = 1.3.6.1.4.1.4413 : Universal OID  
    1.3.6.1.2.1.1.9.1.2.7 = 1.3.6.1.6.3.18 : Universal OID  
    1.3.6.1.2.1.1.9.1.2.8 = 1.3.6.1.6.3.10 : Universal OID  
    1.3.6.1.2.1.1.9.1.2.9 = 1.3.6.1.6.3.11 : Universal OID  
    1.3.6.1.2.1.1.9.1.2.10 = 1.3.6.1.6.3.13 : Universal OID  
    1.3.6.1.2.1.1.9.1.2.11 = 1.3.6.1.6.3.12 : Universal OID  
    1.3.6.1.2.1.1.9.1.2.12 = 1.3.6.1.6.3.15 : Universal OID  
    1.3.6.1.2.1.1.9.1.2.13 = 1.3.6.1.6.3.16 : Universal OID  
    1.3.6.1.2.1.1.9.1.2.14 = 1.3.6.1.4.1.99.12.46 : Universal OID  
    Completed successfully  
    Results: 14, Errors: 0  
  
Test PASS

#### PowerSNMPv3 version 1.4.6
##### Eltext MES3500I-8P8F
**Integration Test**   
**switch settings**  
    
    snmp-server server
    snmp-server view SNMPv3-V iso included
    snmp-server community rw view Default
    snmp-server view SNMPv3-V iso included
    snmp-server group SNMPv3-G v3 priv read SNMPv3-V write SNMPv3-V
    encrypted snmp-server user aesuser SNMPv3-G v3 auth sha pass12345 priv-protocol aes-128-cfb priv pass54321

**testing**  
**go test -v -tags integration -args -u aesuser  -a sha -A pass12345 -x aes -X pass54321 -h 192.168.1.92 -c private123**

    === RUN   TestSNMPv3Session_SNMP_Get_Set
    integration_test.go:55: -------- Get single oid V2 --------
    integration_test.go:65: 1.3.6.1.2.1.1.6.0 = Test location : Universal OCTET STRING
    integration_test.go:67: -------- End --------
    integration_test.go:68: -------- Set single oids V2 --------
    integration_test.go:77: -------- End --------
    integration_test.go:78: -------- Get multiple oids V2 --------
    integration_test.go:93: 1.3.6.1.2.1.1.6.0 = Test location from V2 : Universal OCTET STRING
    integration_test.go:93: 1.3.6.1.2.1.1.5.0 = TestELTEX : Universal OCTET STRING
    integration_test.go:99: SNMP v2 Error in SNMP_GetMulti: partial, NoSuchObject (status=128): 1.3.6.1.2.1.1.99.0
    integration_test.go:116: -------- End --------
    integration_test.go:125: -------- Sitch to V3 --------
    integration_test.go:133: -------- Set single oids V3 --------
    integration_test.go:144: 1.3.6.1.2.1.1.6.0 = Test location from V2 : Universal OCTET STRING
    integration_test.go:149: V2→V3 VERIFICATION PASS! 'Test location from V2'
    integration_test.go:152: -------- End --------
    integration_test.go:154: -------- Get multiple oids V3 --------
    integration_test.go:158: 1.3.6.1.2.1.1.6.0 = Test location from V2 : Universal OCTET STRING
    integration_test.go:158: 1.3.6.1.2.1.1.5.0 = TestELTEX : Universal OCTET STRING
    integration_test.go:164: SNMP v3 Error in SNMP_GetMulti: partial, NoSuchObject (status=128): 1.3.6.1.2.1.1.99.0
    integration_test.go:181: -------- End --------
    integration_test.go:183: -------- Get multiple oids V3, All oids is invalid --------
    integration_test.go:193: SNMP v3 Error in SNMP_GetMulti: partial, NoSuchObject (status=128): 1.3.6.1.2.1.1.66.0,partial, NoSuchObject (status=128): 1.3.6.1.2.1.1.99.0,partial, NoSuchObject (status=128): 1.3.6.1.2.1.1.55.0   
    integration_test.go:221: -------- End --------
    integration_test.go:223: -------- Set multiple oids V3 (one OID is wrong) --------
    integration_test.go:243: SNMP v3 Error in SNMP_SetMulti: NotWritable (status=17, index=2): 1.3.6.1.2.1.1.99.0
    integration_test.go:266: -------- End --------
    integration_test.go:267: -------- Set location to 'Test location' V3 --------
    integration_test.go:276: -------- End --------
    --- PASS: TestSNMPv3Session_SNMP_Get_Set (0.13s)
    === RUN   TestSNMPv3Session_SNMP_Get_Walk
    integration_test.go:300: -------- Walk from OID 1.3.6.1.2.1.2.2.1.2 V3 --------
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.49 = GigabitEthernet1/0/1 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.50 = GigabitEthernet1/0/2 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.51 = GigabitEthernet1/0/3 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.52 = GigabitEthernet1/0/4 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.53 = GigabitEthernet1/0/5 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.54 = GigabitEthernet1/0/6 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.55 = GigabitEthernet1/0/7 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.56 = GigabitEthernet1/0/8 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.57 = GigabitEthernet1/0/9 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.58 = GigabitEthernet1/0/10 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.59 = GigabitEthernet1/0/11 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.60 = GigabitEthernet1/0/12 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.61 = GigabitEthernet1/0/13 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.62 = GigabitEthernet1/0/14 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.63 = GigabitEthernet1/0/15 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.64 = GigabitEthernet1/0/16 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.105 = TenGigabitEthernet1/0/1 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.106 = TenGigabitEthernet1/0/2 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1000 = Port-Channel1 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1001 = Port-Channel2 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1002 = Port-Channel3 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1003 = Port-Channel4 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1004 = Port-Channel5 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1005 = Port-Channel6 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1006 = Port-Channel7 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1007 = Port-Channel8 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1008 = Port-Channel9 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1009 = Port-Channel10 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1010 = Port-Channel11 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1011 = Port-Channel12 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1012 = Port-Channel13 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1013 = Port-Channel14 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1014 = Port-Channel15 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1015 = Port-Channel16 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1016 = Port-Channel17 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1017 = Port-Channel18 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1018 = Port-Channel19 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1019 = Port-Channel20 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1020 = Port-Channel21 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1021 = Port-Channel22 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1022 = Port-Channel23 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1023 = Port-Channel24 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1024 = Port-Channel25 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1025 = Port-Channel26 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1026 = Port-Channel27 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1027 = Port-Channel28 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1028 = Port-Channel29 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1029 = Port-Channel30 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1030 = Port-Channel31 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.1031 = Port-Channel32 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7000 = loopback1 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7001 = loopback2 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7002 = loopback3 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7003 = loopback4 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7004 = loopback5 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7005 = loopback6 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7006 = loopback7 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7007 = loopback8 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7008 = loopback9 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7009 = loopback10 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7010 = loopback11 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7011 = loopback12 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7012 = loopback13 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7013 = loopback14 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7014 = loopback15 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7015 = loopback16 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7016 = loopback17 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7017 = loopback18 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7018 = loopback19 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7019 = loopback20 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7020 = loopback21 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7021 = loopback22 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7022 = loopback23 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7023 = loopback24 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7024 = loopback25 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7025 = loopback26 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7026 = loopback27 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7027 = loopback28 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7028 = loopback29 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7029 = loopback30 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7030 = loopback31 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7031 = loopback32 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7032 = loopback33 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7033 = loopback34 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7034 = loopback35 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7035 = loopback36 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7036 = loopback37 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7037 = loopback38 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7038 = loopback39 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7039 = loopback40 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7040 = loopback41 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7041 = loopback42 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7042 = loopback43 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7043 = loopback44 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7044 = loopback45 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7045 = loopback46 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7046 = loopback47 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7047 = loopback48 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7048 = loopback49 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7049 = loopback50 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7050 = loopback51 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7051 = loopback52 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7052 = loopback53 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7053 = loopback54 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7054 = loopback55 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7055 = loopback56 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7056 = loopback57 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7057 = loopback58 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7058 = loopback59 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7059 = loopback60 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7060 = loopback61 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7061 = loopback62 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7062 = loopback63 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.7063 = loopback64 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.9000 = stack-port : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.10000 = tunnel1 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.10001 = tunnel2 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.10002 = tunnel3 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.10003 = tunnel4 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.10004 = tunnel5 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.10005 = tunnel6 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.10006 = tunnel7 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.10007 = tunnel8 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.10008 = tunnel9 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.10009 = tunnel10 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.10010 = tunnel11 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.10011 = tunnel12 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.10012 = tunnel13 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.10013 = tunnel14 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.10014 = tunnel15 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.10015 = tunnel16 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.20000 = Logical-int 1 : Universal OCTET STRING
    integration_test.go:318: 1.3.6.1.2.1.2.2.1.2.100000 = 1 : Universal OCTET STRING
    integration_test.go:320: -------- End --------
    integration_test.go:321: -------- Bulk walk from OID 1.3.6.1.2.1.2.2.1.2 V3 --------
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.49 = GigabitEthernet1/0/1 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.50 = GigabitEthernet1/0/2 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.51 = GigabitEthernet1/0/3 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.52 = GigabitEthernet1/0/4 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.53 = GigabitEthernet1/0/5 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.54 = GigabitEthernet1/0/6 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.55 = GigabitEthernet1/0/7 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.56 = GigabitEthernet1/0/8 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.57 = GigabitEthernet1/0/9 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.58 = GigabitEthernet1/0/10 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.59 = GigabitEthernet1/0/11 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.60 = GigabitEthernet1/0/12 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.61 = GigabitEthernet1/0/13 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.62 = GigabitEthernet1/0/14 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.63 = GigabitEthernet1/0/15 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.64 = GigabitEthernet1/0/16 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.105 = TenGigabitEthernet1/0/1 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.106 = TenGigabitEthernet1/0/2 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1000 = Port-Channel1 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1001 = Port-Channel2 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1002 = Port-Channel3 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1003 = Port-Channel4 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1004 = Port-Channel5 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1005 = Port-Channel6 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1006 = Port-Channel7 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1007 = Port-Channel8 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1008 = Port-Channel9 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1009 = Port-Channel10 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1010 = Port-Channel11 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1011 = Port-Channel12 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1012 = Port-Channel13 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1013 = Port-Channel14 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1014 = Port-Channel15 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1015 = Port-Channel16 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1016 = Port-Channel17 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1017 = Port-Channel18 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1018 = Port-Channel19 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1019 = Port-Channel20 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1020 = Port-Channel21 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1021 = Port-Channel22 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1022 = Port-Channel23 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1023 = Port-Channel24 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1024 = Port-Channel25 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1025 = Port-Channel26 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1026 = Port-Channel27 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1027 = Port-Channel28 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1028 = Port-Channel29 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1029 = Port-Channel30 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1030 = Port-Channel31 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.1031 = Port-Channel32 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7000 = loopback1 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7001 = loopback2 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7002 = loopback3 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7003 = loopback4 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7004 = loopback5 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7005 = loopback6 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7006 = loopback7 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7007 = loopback8 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7008 = loopback9 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7009 = loopback10 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7010 = loopback11 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7011 = loopback12 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7012 = loopback13 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7013 = loopback14 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7014 = loopback15 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7015 = loopback16 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7016 = loopback17 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7017 = loopback18 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7018 = loopback19 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7019 = loopback20 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7020 = loopback21 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7021 = loopback22 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7022 = loopback23 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7023 = loopback24 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7024 = loopback25 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7025 = loopback26 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7026 = loopback27 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7027 = loopback28 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7028 = loopback29 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7029 = loopback30 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7030 = loopback31 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7031 = loopback32 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7032 = loopback33 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7033 = loopback34 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7034 = loopback35 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7035 = loopback36 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7036 = loopback37 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7037 = loopback38 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7038 = loopback39 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7039 = loopback40 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7040 = loopback41 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7041 = loopback42 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7042 = loopback43 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7043 = loopback44 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7044 = loopback45 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7045 = loopback46 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7046 = loopback47 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7047 = loopback48 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7048 = loopback49 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7049 = loopback50 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7050 = loopback51 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7051 = loopback52 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7052 = loopback53 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7053 = loopback54 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7054 = loopback55 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7055 = loopback56 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7056 = loopback57 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7057 = loopback58 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7058 = loopback59 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7059 = loopback60 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7060 = loopback61 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7061 = loopback62 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7062 = loopback63 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.7063 = loopback64 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.9000 = stack-port : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.10000 = tunnel1 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.10001 = tunnel2 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.10002 = tunnel3 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.10003 = tunnel4 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.10004 = tunnel5 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.10005 = tunnel6 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.10006 = tunnel7 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.10007 = tunnel8 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.10008 = tunnel9 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.10009 = tunnel10 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.10010 = tunnel11 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.10011 = tunnel12 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.10012 = tunnel13 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.10013 = tunnel14 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.10014 = tunnel15 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.10015 = tunnel16 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.20000 = Logical-int 1 : Universal OCTET STRING
    integration_test.go:336: 1.3.6.1.2.1.2.2.1.2.100000 = 1 : Universal OCTET STRING
    integration_test.go:338: -------- End --------
    integration_test.go:345: -------- Sitch to V2 --------
    integration_test.go:355: -------- Walk from OID 1.3.6.1.2.1.2.2.1.2 V2 --------
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.49 = GigabitEthernet1/0/1 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.50 = GigabitEthernet1/0/2 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.51 = GigabitEthernet1/0/3 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.52 = GigabitEthernet1/0/4 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.53 = GigabitEthernet1/0/5 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.54 = GigabitEthernet1/0/6 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.55 = GigabitEthernet1/0/7 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.56 = GigabitEthernet1/0/8 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.57 = GigabitEthernet1/0/9 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.58 = GigabitEthernet1/0/10 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.59 = GigabitEthernet1/0/11 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.60 = GigabitEthernet1/0/12 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.61 = GigabitEthernet1/0/13 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.62 = GigabitEthernet1/0/14 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.63 = GigabitEthernet1/0/15 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.64 = GigabitEthernet1/0/16 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.105 = TenGigabitEthernet1/0/1 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.106 = TenGigabitEthernet1/0/2 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1000 = Port-Channel1 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1001 = Port-Channel2 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1002 = Port-Channel3 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1003 = Port-Channel4 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1004 = Port-Channel5 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1005 = Port-Channel6 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1006 = Port-Channel7 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1007 = Port-Channel8 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1008 = Port-Channel9 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1009 = Port-Channel10 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1010 = Port-Channel11 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1011 = Port-Channel12 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1012 = Port-Channel13 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1013 = Port-Channel14 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1014 = Port-Channel15 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1015 = Port-Channel16 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1016 = Port-Channel17 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1017 = Port-Channel18 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1018 = Port-Channel19 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1019 = Port-Channel20 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1020 = Port-Channel21 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1021 = Port-Channel22 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1022 = Port-Channel23 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1023 = Port-Channel24 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1024 = Port-Channel25 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1025 = Port-Channel26 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1026 = Port-Channel27 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1027 = Port-Channel28 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1028 = Port-Channel29 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1029 = Port-Channel30 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1030 = Port-Channel31 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.1031 = Port-Channel32 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7000 = loopback1 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7001 = loopback2 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7002 = loopback3 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7003 = loopback4 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7004 = loopback5 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7005 = loopback6 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7006 = loopback7 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7007 = loopback8 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7008 = loopback9 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7009 = loopback10 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7010 = loopback11 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7011 = loopback12 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7012 = loopback13 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7013 = loopback14 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7014 = loopback15 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7015 = loopback16 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7016 = loopback17 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7017 = loopback18 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7018 = loopback19 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7019 = loopback20 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7020 = loopback21 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7021 = loopback22 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7022 = loopback23 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7023 = loopback24 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7024 = loopback25 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7025 = loopback26 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7026 = loopback27 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7027 = loopback28 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7028 = loopback29 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7029 = loopback30 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7030 = loopback31 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7031 = loopback32 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7032 = loopback33 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7033 = loopback34 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7034 = loopback35 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7035 = loopback36 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7036 = loopback37 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7037 = loopback38 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7038 = loopback39 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7039 = loopback40 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7040 = loopback41 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7041 = loopback42 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7042 = loopback43 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7043 = loopback44 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7044 = loopback45 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7045 = loopback46 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7046 = loopback47 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7047 = loopback48 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7048 = loopback49 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7049 = loopback50 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7050 = loopback51 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7051 = loopback52 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7052 = loopback53 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7053 = loopback54 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7054 = loopback55 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7055 = loopback56 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7056 = loopback57 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7057 = loopback58 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7058 = loopback59 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7059 = loopback60 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7060 = loopback61 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7061 = loopback62 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7062 = loopback63 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.7063 = loopback64 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.9000 = stack-port : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.10000 = tunnel1 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.10001 = tunnel2 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.10002 = tunnel3 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.10003 = tunnel4 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.10004 = tunnel5 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.10005 = tunnel6 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.10006 = tunnel7 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.10007 = tunnel8 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.10008 = tunnel9 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.10009 = tunnel10 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.10010 = tunnel11 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.10011 = tunnel12 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.10012 = tunnel13 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.10013 = tunnel14 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.10014 = tunnel15 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.10015 = tunnel16 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.20000 = Logical-int 1 : Universal OCTET STRING
    integration_test.go:370: 1.3.6.1.2.1.2.2.1.2.100000 = 1 : Universal OCTET STRING
    integration_test.go:373: -------- End --------
    integration_test.go:374: -------- Bulk walk from OID 1.3.6.1.2.1.2.2.1.2 V2 --------
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.49 = GigabitEthernet1/0/1 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.50 = GigabitEthernet1/0/2 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.51 = GigabitEthernet1/0/3 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.52 = GigabitEthernet1/0/4 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.53 = GigabitEthernet1/0/5 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.54 = GigabitEthernet1/0/6 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.55 = GigabitEthernet1/0/7 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.56 = GigabitEthernet1/0/8 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.57 = GigabitEthernet1/0/9 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.58 = GigabitEthernet1/0/10 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.59 = GigabitEthernet1/0/11 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.60 = GigabitEthernet1/0/12 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.61 = GigabitEthernet1/0/13 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.62 = GigabitEthernet1/0/14 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.63 = GigabitEthernet1/0/15 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.64 = GigabitEthernet1/0/16 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.105 = TenGigabitEthernet1/0/1 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.106 = TenGigabitEthernet1/0/2 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1000 = Port-Channel1 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1001 = Port-Channel2 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1002 = Port-Channel3 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1003 = Port-Channel4 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1004 = Port-Channel5 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1005 = Port-Channel6 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1006 = Port-Channel7 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1007 = Port-Channel8 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1008 = Port-Channel9 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1009 = Port-Channel10 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1010 = Port-Channel11 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1011 = Port-Channel12 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1012 = Port-Channel13 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1013 = Port-Channel14 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1014 = Port-Channel15 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1015 = Port-Channel16 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1016 = Port-Channel17 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1017 = Port-Channel18 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1018 = Port-Channel19 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1019 = Port-Channel20 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1020 = Port-Channel21 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1021 = Port-Channel22 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1022 = Port-Channel23 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1023 = Port-Channel24 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1024 = Port-Channel25 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1025 = Port-Channel26 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1026 = Port-Channel27 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1027 = Port-Channel28 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1028 = Port-Channel29 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1029 = Port-Channel30 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1030 = Port-Channel31 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.1031 = Port-Channel32 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7000 = loopback1 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7001 = loopback2 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7002 = loopback3 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7003 = loopback4 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7004 = loopback5 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7005 = loopback6 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7006 = loopback7 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7007 = loopback8 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7008 = loopback9 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7009 = loopback10 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7010 = loopback11 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7011 = loopback12 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7012 = loopback13 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7013 = loopback14 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7014 = loopback15 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7015 = loopback16 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7016 = loopback17 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7017 = loopback18 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7018 = loopback19 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7019 = loopback20 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7020 = loopback21 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7021 = loopback22 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7022 = loopback23 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7023 = loopback24 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7024 = loopback25 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7025 = loopback26 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7026 = loopback27 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7027 = loopback28 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7028 = loopback29 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7029 = loopback30 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7030 = loopback31 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7031 = loopback32 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7032 = loopback33 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7033 = loopback34 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7034 = loopback35 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7035 = loopback36 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7036 = loopback37 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7037 = loopback38 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7038 = loopback39 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7039 = loopback40 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7040 = loopback41 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7041 = loopback42 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7042 = loopback43 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7043 = loopback44 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7044 = loopback45 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7045 = loopback46 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7046 = loopback47 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7047 = loopback48 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7048 = loopback49 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7049 = loopback50 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7050 = loopback51 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7051 = loopback52 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7052 = loopback53 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7053 = loopback54 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7054 = loopback55 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7055 = loopback56 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7056 = loopback57 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7057 = loopback58 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7058 = loopback59 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7059 = loopback60 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7060 = loopback61 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7061 = loopback62 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7062 = loopback63 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.7063 = loopback64 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.9000 = stack-port : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.10000 = tunnel1 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.10001 = tunnel2 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.10002 = tunnel3 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.10003 = tunnel4 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.10004 = tunnel5 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.10005 = tunnel6 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.10006 = tunnel7 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.10007 = tunnel8 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.10008 = tunnel9 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.10009 = tunnel10 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.10010 = tunnel11 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.10011 = tunnel12 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.10012 = tunnel13 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.10013 = tunnel14 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.10014 = tunnel15 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.10015 = tunnel16 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.20000 = Logical-int 1 : Universal OCTET STRING
    integration_test.go:389: 1.3.6.1.2.1.2.2.1.2.100000 = 1 : Universal OCTET STRING
    integration_test.go:396: -------- End --------
    --- PASS: TestSNMPv3Session_SNMP_Get_Walk (1.81s)
    PASS