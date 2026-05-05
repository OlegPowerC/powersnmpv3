package main

import (
	"flag"
	"fmt"

	PowerSNMP "github.com/OlegPowerC/powersnmpv3"
)

func DemoSingleGET_OIDsynt(Ssess *PowerSNMP.SNMPv3Session) {
	fmt.Println("*************************************************************************************************")
	fmt.Println("=== do GET for single OID (valid 1.3.6.1.2.1.1.a.0) ===")
	swrongoid := "1.3.6.1.2.1.1.a.0"
	fmt.Println("--- Do parse OID from string ---")
	swrongoidiarr, parseerr := PowerSNMP.ParseOID(swrongoid)
	if parseerr != nil {
		fmt.Println(parseerr)
		return
	}
	fmt.Println("--- Do GET with wrong error ---")
	GetsingleRes, GetsingleErr := Ssess.SNMP_Get(swrongoidiarr)
	fmt.Println("--- Check errors ---")
	if GetsingleErr != nil {
		OutError(GetsingleErr)
	} else {
		fmt.Println("- No error -")
		fmt.Println("--- Single OID GET result ---")
		for _, wl := range GetsingleRes {
			fmt.Println(PowerSNMP.Convert_OID_IntArrayToString_RAW(wl.RSnmpOID), "=", PowerSNMP.Convert_Variable_To_String(wl.RSnmpVar), ":", PowerSNMP.Convert_ClassTag_to_String(wl.RSnmpVar))
		}
	}
	fmt.Println("*************************************************************************************************")
}

func DemoSingleGET_Valid(Ssess *PowerSNMP.SNMPv3Session) {
	fmt.Println("*************************************************************************************************")
	fmt.Println("=== do GET for single OID (valid 1.3.6.1.2.1.1.5.0) ===")
	swrongoid := "1.3.6.1.2.1.1.5.0"
	swrongoidiarr, parseerr := PowerSNMP.ParseOID(swrongoid)
	if parseerr != nil {
		fmt.Println(parseerr)
		return
	}
	GetsingleRes, GetsingleErr := Ssess.SNMP_Get(swrongoidiarr)
	fmt.Println("--- Check errors ---")
	if GetsingleErr != nil {
		OutError(GetsingleErr)
	} else {
		fmt.Println("- No error -")
		fmt.Println("--- Single OID GET result ---")
		for _, wl := range GetsingleRes {
			fmt.Println(PowerSNMP.Convert_OID_IntArrayToString_RAW(wl.RSnmpOID), "=", PowerSNMP.Convert_Variable_To_String(wl.RSnmpVar), ":", PowerSNMP.Convert_ClassTag_to_String(wl.RSnmpVar))
		}
	}
	fmt.Println("*************************************************************************************************")
}

func DemoSingleGET_Invalid(Ssess *PowerSNMP.SNMPv3Session) {
	fmt.Println("*************************************************************************************************")
	fmt.Println("=== do GET for single OID (invalid 1.3.6.1.2.1.1.99.0) ===")
	swrongoid := "1.3.6.1.2.1.1.99.0"
	swrongoidiarr, parseerr := PowerSNMP.ParseOID(swrongoid)

	if parseerr != nil {
		fmt.Println(parseerr)
		return
	}

	GetsingleRes, GetsingleErr := Ssess.SNMP_Get(swrongoidiarr)
	fmt.Println("--- Check errors ---")
	if GetsingleErr != nil {
		OutError(GetsingleErr)
	} else {
		fmt.Println("- No error -")
		fmt.Println("--- Single OID GET result ---")
		for _, wl := range GetsingleRes {
			fmt.Println(PowerSNMP.Convert_OID_IntArrayToString_RAW(wl.RSnmpOID), "=", PowerSNMP.Convert_Variable_To_String(wl.RSnmpVar), ":", PowerSNMP.Convert_ClassTag_to_String(wl.RSnmpVar))
		}
	}
	fmt.Println("*************************************************************************************************")
}

func DemoMultiGET_PartInvalid(Ssess *PowerSNMP.SNMPv3Session) {
	fmt.Println("*************************************************************************************************")
	fmt.Println("=== do GET with multiple OID's ===")
	OidsStrings := []string{"1.3.6.1.2.1.1.6.0", "1.3.6.1.2.1.1.99.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.100.0"}
	OidsConverted := []PowerSNMP.SNMP_Packet_V2_Decoded_VarBind{}

	for _, OidSting := range OidsStrings {
		Ioid, IoidErr := PowerSNMP.Convert_OID_StringToIntArray_RAW(OidSting)
		if IoidErr != nil {
			fmt.Println(IoidErr)
			return
		}
		OidsConverted = append(OidsConverted, PowerSNMP.SNMP_Packet_V2_Decoded_VarBind{Ioid, PowerSNMP.SNMPvbNullValue})
	}
	GetRes2, verr2 := Ssess.SNMP_GetMulti(OidsConverted)

	fmt.Println("--- Check errors ---")
	if verr2 != nil {
		OutError(verr2)
	} else {
		fmt.Println("- No error -")
	}

	fmt.Println("--- Result ---")
	if len(GetRes2) > 0 {
		fmt.Println(len(GetRes2), "OID's success")
	}
	for _, wl := range GetRes2 {
		fmt.Println(PowerSNMP.Convert_OID_IntArrayToString_RAW(wl.RSnmpOID), "=", PowerSNMP.Convert_Variable_To_String(wl.RSnmpVar), ":", PowerSNMP.Convert_ClassTag_to_String(wl.RSnmpVar))
	}

	fmt.Println("*************************************************************************************************")
}

func DemoMultSET_Invalid(Ssess *PowerSNMP.SNMPv3Session) {
	fmt.Println("*************************************************************************************************")
	fmt.Println("=== do SET with multiple OID's ===")
	VarData := []PowerSNMP.SNMPVar{PowerSNMP.SetSNMPVar_OctetString("TestZone1"), PowerSNMP.SetSNMPVar_OctetString("Test 99.0"), PowerSNMP.SetSNMPVar_OctetString("Sw01")}
	SetStringOids := []string{"1.3.6.1.2.1.1.6.0", "1.3.6.1.2.1.1.99.0", "1.3.6.1.2.1.1.5.0"}
	SetDataVB := []PowerSNMP.SNMP_Packet_V2_Decoded_VarBind{}
	if len(VarData) == len(SetStringOids) {
		for VdataInd, StoidS := range SetStringOids {
			IoidS, IoidErrS := PowerSNMP.Convert_OID_StringToIntArray_RAW(StoidS)
			if IoidErrS != nil {
				fmt.Println(IoidErrS)
				return
			}
			SetDataVB = append(SetDataVB, PowerSNMP.SNMP_Packet_V2_Decoded_VarBind{IoidS, VarData[VdataInd]})
		}
	} else {
		fmt.Println("oid's and data count not equal")
		return
	}

	sdata, verres3 := Ssess.SNMP_SetMulti(SetDataVB)
	fmt.Println("--- Check errors ---")
	if verres3 != nil {
		OutError(verres3)
	} else {
		fmt.Println("- No error -")
	}

	fmt.Println("--- SET result ---")
	for _, wl := range sdata {
		fmt.Println(PowerSNMP.Convert_OID_IntArrayToString_RAW(wl.RSnmpOID), "=", PowerSNMP.Convert_Variable_To_String(wl.RSnmpVar), ":", PowerSNMP.Convert_ClassTag_to_String(wl.RSnmpVar))
	}
	fmt.Println("*************************************************************************************************")
}

func DemoMultSET_Valid(Ssess *PowerSNMP.SNMPv3Session) {
	fmt.Println("*************************************************************************************************")
	fmt.Println("=== do SET with multiple OID's - all valid ===")
	VarData := []PowerSNMP.SNMPVar{PowerSNMP.SetSNMPVar_OctetString("TestZone1"), PowerSNMP.SetSNMPVar_OctetString("Sw01")}
	SetStringOids := []string{"1.3.6.1.2.1.1.6.0", "1.3.6.1.2.1.1.5.0"}
	SetDataVB := []PowerSNMP.SNMP_Packet_V2_Decoded_VarBind{}
	if len(VarData) == len(SetStringOids) {
		for VdataInd, StoidS := range SetStringOids {
			IoidS, IoidErrS := PowerSNMP.Convert_OID_StringToIntArray_RAW(StoidS)
			if IoidErrS != nil {
				fmt.Println(IoidErrS)
				return
			}
			SetDataVB = append(SetDataVB, PowerSNMP.SNMP_Packet_V2_Decoded_VarBind{IoidS, VarData[VdataInd]})
		}
	} else {
		fmt.Println("oid's and data count not equal")
		return
	}

	sdata, verres3 := Ssess.SNMP_SetMulti(SetDataVB)
	fmt.Println("--- Check errors ---")
	if verres3 != nil {
		OutError(verres3)
	} else {
		fmt.Println("- No error -")
	}

	fmt.Println("--- SET result ---")
	for _, wl := range sdata {
		fmt.Println(PowerSNMP.Convert_OID_IntArrayToString_RAW(wl.RSnmpOID), "=", PowerSNMP.Convert_Variable_To_String(wl.RSnmpVar), ":", PowerSNMP.Convert_ClassTag_to_String(wl.RSnmpVar))
	}
	fmt.Println("*************************************************************************************************")
}

func OutError(err error) {
	if err != nil {
		snmpErr, commonErr := PowerSNMP.ParseError(err)
		if commonErr != nil {
			// Network, System, e.t.c error
			fmt.Println("Network/system error:", commonErr)
		}
		if snmpErr.IsFatal {
			// Fatal error
			fmt.Println("Fatal SNMP error")
			for _, descr := range snmpErr.Oids {
				fmt.Println("Error description:", descr.ErrorDescription)
			}
		} else {
			// Partial error
			fmt.Printf("Partial error, %d OID's with error:", len(snmpErr.Oids))
			for _, oidErr := range snmpErr.Oids {
				fmt.Printf("  | %s", oidErr.ErrorDescription)
			}
		}

	} else {
		fmt.Println("- No error -")
	}
	fmt.Println(" ")
}

func main() {
	//Command line args
	Host := flag.String("h", "", "Switch or routers IP")
	SNMPuser := flag.String("u", "", "SNMP v3 USER")
	SNMPauthProtocol := flag.String("a", "", "SNMP auth protocol")
	SNMPauthPassword := flag.String("A", "", "SNMP auth password")
	SNMPprivProtocol := flag.String("x", "", "SNMP priv protocol")
	SNMPprivPassword := flag.String("X", "", "SNMP priv password")
	flag.Parse()

	//Switch reference
	var dev PowerSNMP.NetworkDevice
	dev.IPaddress = *Host
	dev.SNMPparameters.SNMPversion = 3
	dev.Port = 161
	dev.SNMPparameters.Username = *SNMPuser
	dev.SNMPparameters.AuthProtocol = *SNMPauthProtocol
	dev.SNMPparameters.AuthKey = *SNMPauthPassword
	dev.SNMPparameters.PrivProtocol = *SNMPprivProtocol
	dev.SNMPparameters.PrivKey = *SNMPprivPassword

	//Init SNMP
	Ssess, InitErr := PowerSNMP.SNMP_Init(dev)
	if InitErr != nil {
		fmt.Println(InitErr)
		return
	}

	DemoSingleGET_Valid(Ssess)
	DemoSingleGET_Invalid(Ssess)
	DemoMultiGET_PartInvalid(Ssess)
	DemoMultSET_Valid(Ssess)
	DemoMultSET_Invalid(Ssess)
	DemoSingleGET_OIDsynt(Ssess)

}
