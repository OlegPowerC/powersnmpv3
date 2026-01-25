## v1.2.2

- Added field **MaxMsgSize** to **NetworkDevice**

**What is MaxMsgSize:**  
 Maximum size of the SNMP message.  
 If you want to avoid IP fragmentation, you must select **MaxMsgSize** properly with **MaxRepetitions**.  
 Default MaxMsgSize is 1360, which is suitable for typical LAN and VPN.