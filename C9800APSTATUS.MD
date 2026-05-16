#### Simple example, how to use **PowerSNMPv3** library to create multichannel PRTG sensor which can monitoring access point registered on the Cisco C9800 wireless controller.
We need the following OID’s:
- AP name **1.3.6.1.4.1.14179.2.2.1.1.3**  
- AP state **1.3.6.1.4.1.14179.2.2.1.1.6** (1 joined 2 not joined 3 downloading)  

First, we need to get list of the registered access point using Walk OID **1.3.6.1.4.1.14179.2.2.1.1.3** and save suffix after .3 This is access point MAC address.  
We can append this suffix to other OID's and performe GET requests to retrieve data about this AP.  
We can also optimise requests by using GET with multiple OID’s.  
One important detail: 
After AP's have been discovered, we can get state of this AP's but after AP loss registartion, the Walk will no longer return information about this AP.

So, at the first sensor start we check file with AP's data exists, if it does not exist, sensor collect data about all AP's and save it to file.
On subsequent starts, sensor retrieve AP's status, use AP's list from file.
If one of these APs no longer exists, sensor output error for this AP (not registered).
What information we need to store in thist file?
It can be MAC address in the text format but suitable for conversion in the []int format.

Now let's briefly describe, how this sensor work:

Create the struct, which type is NetworkDevice and provide all necessary information (ip, snmp user, aut/priv protocols and keys etc.)
In this example we can use command line flags for provide this information:

    WLCIP := flag.String("ip", "", "C9800 ip address")
    SNMPuser := flag.String("u", "", "SNMP username")
    SNMAuth := flag.String("a", "", "SNMP auth protocol")
    SNMAuthPpass := flag.String("A", "", "SNMP auth password")
    SNMPriv := flag.String("x", "", "SNMP priv protocol")
    SNMPrivPpass := flag.String("X", "", "SNMP priv password")
    APListFilename := flag.String("file", "aplist.xml", "File with APs")
    flag.Parse()

    var devicesipstn Devices

Create the device description:

    var C9800 PowerSNMP.NetworkDevice
    С9800.IPaddress = *WLCIP
    С9800.Port = 161
    С9800.SNMPparameters.Username = *SNMPuser
    С9800.SNMPparameters.SNMPversion = 3
    С9800.SNMPparameters.AuthProtocol = *SNMAuth
    С9800.SNMPparameters.PrivProtocol = *SNMPriv
    С9800.SNMPparameters.AuthKey = *SNMAuthPpass
    С9800.SNMPparameters.PrivKey = *SNMPrivPpass

    //Init SNMP session
    SNMPc9800dev, SNMPc9800Err := PowerSNMP.SNMP_Init(С9800)
    if SNMPc9800Err != nil {
        ErrorInProgram(SNMPc9800Err)
    }
Convert OID from string:  

    APNamesOIDint, cmerr := PowerSNMP.ParseOID(OID_APName)
    if cmerr != nil {
        ErrorInProgram(cmerr)
    }

When we explicitly convert string oid to []int, we can handle the error before do request.
    
    APlist, APListErr := SNMPc9800dev.SNMP_BulkWalk(APNamesOIDint)
    if APListErr != nil {
        ErrorInProgram(APListErr)
    }

Now process the result and save MAC addresses as strings

    for _, cap := range APlist {
        if len(cap.RSnmpOID) == (len(APNamesOIDint) + 6) {
            //We need last 6 butes from retrieved OID
            APMAC := cap.RSnmpOID[len(APNamesOIDint):]

            //Convert MAC to string
            MACst := fmt.Sprintf("%d.%d.%d.%d.%d.%d", APMAC[0], APMAC[1], APMAC[2], APMAC[3], APMAC[4], APMAC[5])

            //Convert AP name to string
            APName := PowerSNMP.Convert_Variable_To_String(cap.RSnmpVar)

            //Add AP to AP's list
            Capn := AP{APName: APName, APMAC: MACst}
            devicesipstn.Devices = append(devicesipstn.Devices, Capn)
        }
    }

Now we can get AP states:  

	//Iterate though all the AP's and build the OID list
	for capindex, cap := range devicesipstn.Devices {
		var MACiData []int
		MACDt := strings.Split(cap.APMAC, ".")
		for _, MBc := range MACDt {
			Id, Ie := strconv.Atoi(MBc)
			if Ie != nil {
				if Ie != nil {
					ErrorInProgram(Ie)
				}
			}
			MACiData = append(MACiData, Id)
		}
		//Convert OID from string
		APStatusOIDint, cmerr := PowerSNMP.ParseOID(OID_AP_OP_Status)
		if cmerr != nil {
			ErrorInProgram(cmerr)
		}
		//Add suffix (MAC address) to OID and save it in the device list
		APStatusOIDint = append(APStatusOIDint, MACiData...)
		devicesipstn.Devices[capindex].ApStateOid = APStatusOIDint

		//Save all OID's for future multi GET request
		APstatoids = append(APstatoids, PowerSNMP.SNMP_Packet_V2_Decoded_VarBind{RSnmpOID: APStatusOIDint, RSnmpVar: PowerSNMP.SNMPvbNullValue})
	}

This line need explanation: 

    APstatoids = append(APstatoids, PowerSNMP.SNMP_Packet_V2_Decoded_VarBind{RSnmpOID: APStatusOIDint, RSnmpVar: PowerSNMP.SNMPvbNullValue})

We make a list of the **SNMP_Packet_V2_Decoded_VarBind** struct, in the OID field we provide the OID for retrieving AP status (which contains the MAC address as a suffix), and the value field must be **PowerSNMP.SNMPvbNullValue**.

Now perform a GET request with all these OID's:

    AllApStat, AllApStatErr := SNMPc9800dev.SNMP_GetMulti(APstatoids)

	//The result must be in OID and value format
	OpStDataOIDs := make([]OpstatusData, 0)

	//Now handle the error to understand which OID failed:
	if AllApStatErr != nil {
		PErr, Cerr := PowerSNMP.ParseError(AllApStatErr)
		if Cerr != nil {
			ErrorInProgram(Cerr)
		}
		if PErr.IsFatal {
			if Cerr != nil {
				ErrorInProgram(Cerr)
			} else {
				ferr := ""
				for _, descr := range PErr.Oids {
					ferr = descr.ErrorDescription
				}
				fatalperr := fmt.Errorf("Fatal SNMP error: %s", ferr)
				ErrorInProgram(fatalperr)
			}
		} else {
			for _, EmptOids := range PErr.Oids {
				OpStDataOIDs = append(OpStDataOIDs, OpstatusData{FullOID: EmptOids.Failedoid, OpStatus: OPSTATUS_OID_NOTFOUND})
			}
		}
	}

We use the **ParseError** function which retrieve data about which OID is failed and fatal or partial error.
If error is fatal, we need to break execution and return error.
If error is partial we can iterate all failed OID's and add it to **OpStDataOIDs** slice with special value: **OPSTATUS_OID_NOTFOUND**.

Now process the result:

	for _, APOpstatusCrnt := range AllApStat {
		if PowerSNMP.IsInteger(APOpstatusCrnt.RSnmpVar) {
			StatusIVal := PowerSNMP.Convert_bytearray_to_int(APOpstatusCrnt.RSnmpVar.Value)
			OpStDataOIDs = append(OpStDataOIDs, OpstatusData{FullOID: APOpstatusCrnt.RSnmpOID, OpStatus: StatusIVal})
		}
	}

Now we have all the information about AP status and failed OID's.
Then aggregate the data and return the result as XML.

Full examle locate in the **cmd/c9800aps**

This sensor work with C9800, but also with the old Cisco WLC.  

Example data from real life:  
Capure before creating the file with AP's:  
![Initialexcange.jpg](.github/images/Initialexcange.jpg)  

This capture contains 8 frames.
First 4 frames is the Discovery procedure (only for SNMP v3)
next two frames is Bulkwalk (getBulkRequest) and response for it (with all AP's names and MAC's)
![walknames.jpg](.github/images/walknames.jpg)  

The next frame is a GET request with multiple OID's
![getmulti.jpg](.github/images/getmulti.jpg)  

and the response (if no error):  
![gettataok.jpg](.github/images/gettataok.jpg)  

If the file already exists, the traffic will be less
![getnormal.jpg](.github/images/getnormal.jpg)

Now let's look at a capture when one AP losses registartion
![gettatasingleerror.jpg](.github/images/gettatasingleerror.jpg)

In the returned XML we see: XXX-AP27, has a value of 4, while the other AP's have a values of 1:

    <prtg>
       <error>0</error>
       <text></text>
       <result>
          <channel>XXX-AP02</channel><value>1</value><unit></unit><CustomUnit></CustomUnit><ValueLookup>C9800AP_OPSTATUS_LOOKUP</ValueLookup>
       </result>
       <result>
          <channel>XXX_AP4</channel><value>1</value><unit></unit><CustomUnit></CustomUnit><ValueLookup>C9800AP_OPSTATUS_LOOKUP</ValueLookup>
       </result>
       <result>
          <channel>XXX-APSC</channel><value>1</value><unit></unit><CustomUnit></CustomUnit><ValueLookup>C9800AP_OPSTATUS_LOOKUP</ValueLookup>
       </result>
       <result>
          <channel>XXX-AP20</channel><value>1</value><unit></unit><CustomUnit></CustomUnit><ValueLookup>C9800AP_OPSTATUS_LOOKUP</ValueLookup>
       </result>
       <result>
          <channel>XXX_AP10</channel><value>1</value><unit></unit><CustomUnit></CustomUnit><ValueLookup>C9800AP_OPSTATUS_LOOKUP</ValueLookup>
       </result>
       <result>
          <channel>XXX_AP13</channel><value>1</value><unit></unit><CustomUnit></CustomUnit><ValueLookup>C9800AP_OPSTATUS_LOOKUP</ValueLookup>
       </result>
       <result>
          <channel>XXX_AP03</channel><value>1</value><unit></unit><CustomUnit></CustomUnit><ValueLookup>C9800AP_OPSTATUS_LOOKUP</ValueLookup>
       </result>
       <result>
          <channel>XXX-AP18</channel><value>1</value><unit></unit><CustomUnit></CustomUnit><ValueLookup>C9800AP_OPSTATUS_LOOKUP</ValueLookup>
       </result>
       <result>
          <channel>XXX-AP01</channel><value>1</value><unit></unit><CustomUnit></CustomUnit><ValueLookup>C9800AP_OPSTATUS_LOOKUP</ValueLookup>
       </result>
       <result>
          <channel>XXX-AP27</channel><value>4</value><unit></unit><CustomUnit></CustomUnit><ValueLookup>C9800AP_OPSTATUS_LOOKUP</ValueLookup>
       </result>
       <result>
          <channel>XXX-AP11</channel><value>1</value><unit></unit><CustomUnit></CustomUnit><ValueLookup>C9800AP_OPSTATUS_LOOKUP</ValueLookup>
       </result>
    </prtg>