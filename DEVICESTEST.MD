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