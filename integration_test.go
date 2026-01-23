//go:build integration

// PowerSNMPv3 - SNMP library for Go
// Автор: Волков Олег, ООО "Пауэр Си"
// Author: Volkov Oleg, PowerC LLC
// License: MIT (commercial version with support available)
// Лицензия: MIT (доступна коммерческая версия с поддержкой)
package PowerSNMPv3

import (
	"flag"
	"os"
	"slices"
	"testing"
)

var (
	Host             = flag.String("h", "", "Switch or routers IP")
	SNMPuser         = flag.String("u", "", "SNMP v3 USER")
	SNMPcommunity    = flag.String("c", "", "Mandatory for version 2, SNMP read community name")
	SNMPv3Context    = flag.String("context", "", "SNMP v3 context")
	SNMPauthProtocol = flag.String("a", "", "SNMP auth protocol")
	SNMPauthPassword = flag.String("A", "", "SNMP auth password")
	SNMPprivProtocol = flag.String("x", "", "SNMP priv protocol")
	SNMPprivPassword = flag.String("X", "", "SNMP priv password")
)

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(m.Run())
}

func TestSNMPv3Session_SNMP_Get_Set_Walk(t *testing.T) {
	var Nhost NetworkDevice
	Nhost.IPaddress = *Host
	Nhost.Port = 161
	Nhost.SNMPparameters.SNMPversion = 2
	Nhost.SNMPparameters.Username = *SNMPuser
	Nhost.SNMPparameters.AuthProtocol = *SNMPauthProtocol
	Nhost.SNMPparameters.AuthKey = *SNMPauthPassword
	Nhost.SNMPparameters.PrivProtocol = *SNMPprivProtocol
	Nhost.SNMPparameters.PrivKey = *SNMPprivPassword
	Nhost.SNMPparameters.Community = *SNMPcommunity
	Nhost.SNMPparameters.TimeoutBtwRepeat = 500
	Nhost.SNMPparameters.RetryCount = 3
	Ssess, SsessError := SNMP_Init(Nhost)
	if SsessError != nil {
		t.Errorf("Error in SNMPInit: %v", SsessError.Error())
	}
	if Ssess == nil {
		t.Fatal("Error in SNMPInit")
	}

	t.Log("-------- Get single oid V2 --------")
	StrOid := "1.3.6.1.2.1.1.6.0" //Sys Location
	Ioid, _ := ParseOID(StrOid)

	GetRes2, verr2 := Ssess.SNMP_Get(Ioid)
	if verr2 != nil {
		t.Errorf("SNMP v2 Error in SNMP_Get: %s", verr2.Error())
	}

	for _, wl := range GetRes2 {
		t.Log(Convert_OID_IntArrayToString_RAW(wl.RSnmpOID), "=", Convert_Variable_To_String(wl.RSnmpVar), ":", Convert_ClassTag_to_String(wl.RSnmpVar))
	}
	t.Log("-------- End --------")
	t.Log("-------- Set single oids V2 --------")

	var SNMPsv SNMPVar
	SNMPsv = SetSNMPVar_OctetString("Test location from V2")

	_, verr2 = Ssess.SNMP_Set(Ioid, SNMPsv)
	if verr2 != nil {
		t.Errorf("SNMP v2 Error in SNMP_Set: %s", verr2.Error())
	}
	t.Log("-------- End --------")
	t.Log("-------- Get multiple oids V2 --------")
	StrOidWA1, StrOidWA2, StrOidWA3 := "1.3.6.1.2.1.1.6.0", "1.3.6.1.2.1.1.99.0", "1.3.6.1.2.1.1.5.0"
	IoidWA1, _ := Convert_OID_StringToIntArray_RAW(StrOidWA1)
	IoidWA2, _ := Convert_OID_StringToIntArray_RAW(StrOidWA2)
	IoidWA3, _ := Convert_OID_StringToIntArray_RAW(StrOidWA3)

	GetOids := []SNMP_Packet_V2_Decoded_VarBind{{IoidWA1, SNMPvbNullValue}, {IoidWA2, SNMPvbNullValue}, {IoidWA3, SNMPvbNullValue}}

	Mg, Mgerr := Ssess.SNMP_GetMulti(GetOids)
	for _, Mgv := range Mg {
		t.Log(Convert_OID_IntArrayToString_RAW(Mgv.RSnmpOID), "=", Convert_Variable_To_String(Mgv.RSnmpVar), ":", Convert_ClassTag_to_String(Mgv.RSnmpVar))
	}
	if Mgerr == nil {
		t.Errorf("expected partial error OID 1.3.6.1.2.1.1.99.0 is NoSuchObject")
	}

	t.Logf("SNMP v2 Error in SNMP_GetMulti: %v", Mgerr)
	per, _ := ParseError(Mgerr)
	if per.IsFatal {
		t.Errorf("expected partial error but get fatal")
	} else {
		if per.Oids != nil {
			if len(per.Oids) > 0 {
				if per.Oids[0].Error_id != 128 {
					t.Errorf("Expected error id 128 but got: %d", per.Oids[0].Error_id)
				}
				if !slices.Equal(per.Oids[0].Failedoid, IoidWA2) {

					t.Errorf("Expected error in OID 1.3.6.1.2.1.1.99.0 but got: %s", Convert_OID_IntArrayToString_RAW(per.Oids[0].Failedoid))
				}
			}
		}
	}
	t.Log("-------- End --------")

	CloseErr := Ssess.Close()
	if CloseErr != nil {
		t.Errorf("SNMP v2  Error in Close: %s", CloseErr.Error())
	}

	t.Log("-------- Sitch to V3 --------")
	Nhost.SNMPparameters.SNMPversion = 3

	Ssess, SsessError = SNMP_Init(Nhost)
	if SsessError != nil {
		t.Errorf("SNMP v3 Error in SNMPInit: %s", SsessError.Error())
	}

	t.Log("-------- Set single oids V3 --------")
	GetRes3, verr3 := Ssess.SNMP_Get(Ioid)
	if verr3 != nil {
		t.Errorf("SNMP v3 Error in SNMP_Get: %s", verr3.Error())
	}

	if GetRes3 == nil {
		t.Errorf("SNMP v3 Error in SNMP_Get, reult is nul")
	}

	for _, wl := range GetRes3 {
		t.Log(Convert_OID_IntArrayToString_RAW(wl.RSnmpOID), "=", Convert_Variable_To_String(wl.RSnmpVar), ":", Convert_ClassTag_to_String(wl.RSnmpVar))
		location := Convert_Variable_To_String(wl.RSnmpVar)
		if Convert_Variable_To_String(wl.RSnmpVar) != "Test location from V2" {
			t.Logf("V3 sees: '%s' (V2 SET может иметь разные ACL)", location)
		} else {
			t.Logf("V2→V3 VERIFICATION PASS! '%s'", location)
		}
	}
	t.Log("-------- End --------")

	t.Log("-------- Get multiple oids V3 --------")

	Mgv3, Mgerrv3 := Ssess.SNMP_GetMulti(GetOids)
	for _, Mgvv3 := range Mgv3 {
		t.Log(Convert_OID_IntArrayToString_RAW(Mgvv3.RSnmpOID), "=", Convert_Variable_To_String(Mgvv3.RSnmpVar), ":", Convert_ClassTag_to_String(Mgvv3.RSnmpVar))
	}
	if Mgerrv3 == nil {
		t.Errorf("expected partial error OID 1.3.6.1.2.1.1.99.0 is NoSuchObject)")
	}

	t.Logf("SNMP v3 Error in SNMP_GetMulti: %s", Mgerrv3.Error())
	perv3, _ := ParseError(Mgerrv3)
	if perv3.IsFatal {
		t.Errorf("expected partial error but get fatal")
	} else {
		if perv3.Oids != nil {
			if len(perv3.Oids) > 0 {
				if perv3.Oids[0].Error_id != 128 {
					t.Errorf("Expected error id 128 but got: %d", perv3.Oids[0].Error_id)
				}
				if !slices.Equal(perv3.Oids[0].Failedoid, IoidWA2) {

					t.Errorf("Expected error in OID 1.3.6.1.2.1.1.99.0 but got: %s", Convert_OID_IntArrayToString_RAW(perv3.Oids[0].Failedoid))
				}
			}
		}
	}
	t.Log("-------- End --------")

	t.Log("-------- Set multiple oids V3 (one OID is wrong) --------")
	var SNMPsv3OS SNMPVar
	SNMPsv3OS = SetSNMPVar_OctetString("Test 6.0")

	var SNMPsv3OS2 SNMPVar
	SNMPsv3OS2 = SetSNMPVar_OctetString("Test 5.0")

	StrOidWB1, StrOidWB2, StrOidWB3 := "1.3.6.1.2.1.1.6.0", "1.3.6.1.2.1.1.99.0", "1.3.6.1.2.1.1.5.0"

	IoidWB1, _ := ParseOID(StrOidWB1)
	IoidWB2, _ := ParseOID(StrOidWB2)
	IoidWB3, _ := ParseOID(StrOidWB3)

	smwerr := []SNMP_Packet_V2_Decoded_VarBind{{IoidWB1, SNMPsv3OS}, {IoidWB2, SNMPsv3OS}, {IoidWB3, SNMPsv3OS2}}

	sdata, verres3 := Ssess.SNMP_SetMulti(smwerr)
	if verres3 == nil {
		t.Errorf("expected fatal error")
	}

	t.Logf("SNMP v3 Error in SNMP_SetMulti: %v", verres3)

	mseterr, _ := ParseError(verres3)
	if !mseterr.IsFatal {
		t.Errorf("expected fatal error but got partial")
	} else {
		if mseterr.Oids != nil {
			if len(mseterr.Oids) > 0 {
				if mseterr.Oids[0].Error_id != 11 {
					t.Errorf("Expected error id 11 but got: %d", mseterr.Oids[0].Error_id)
				}
				if !slices.Equal(mseterr.Oids[0].Failedoid, IoidWB2) {

					t.Errorf("Expected error in OID 1.3.6.1.2.1.1.99.0 but got: %s", Convert_OID_IntArrayToString_RAW(mseterr.Oids[0].Failedoid))
				}
			}
		}
	}

	for _, sdadac := range sdata {
		t.Log(Convert_OID_IntArrayToString_RAW(sdadac.RSnmpOID), "=", Convert_Variable_To_String(sdadac.RSnmpVar), ":", Convert_ClassTag_to_String(sdadac.RSnmpVar))
	}

	t.Log("-------- End --------")
	t.Log("-------- Set location to 'Test location' V3 --------")

	var SNMPsv3 SNMPVar
	SNMPsv3 = SetSNMPVar_OctetString("Test location")

	_, verr3 = Ssess.SNMP_Set(Ioid, SNMPsv3)
	if verr3 != nil {
		t.Errorf("SNMP v3  Error in SNMP_Set: %s", verr3.Error())
	}
	t.Log("-------- End --------")

	t.Log("-------- Walk from OID 1.3.6.1.2.1.2.2.1.2 V3 --------")
	StrOidW := "1.3.6.1.2.1.2.2.1.2"
	IoidW, _ := ParseOID(StrOidW)

	WalkRes, verr3w := Ssess.SNMP_Walk(IoidW)
	if verr3w != nil {
		t.Errorf("SNMP v3 Error in SNMP_Walk: %s", verr3w.Error())
	}

	if WalkRes == nil {
		t.Errorf("Error in SNMP_Walk, result is nul")
	}

	if len(WalkRes) == 0 {
		t.Errorf("Error in SNMP_Walk, expected > 0 VarBinds but got %d", len(WalkRes))
	}

	for _, wl := range WalkRes {
		t.Log(Convert_OID_IntArrayToString_RAW(wl.RSnmpOID), "=", Convert_Variable_To_String(wl.RSnmpVar), ":", Convert_ClassTag_to_String(wl.RSnmpVar))
	}
	t.Log("-------- End --------")
	t.Log("-------- Bulk walk from OID 1.3.6.1.2.1.2.2.1.2 V3 --------")
	BWalkRes, verr3bw := Ssess.SNMP_BulkWalk(IoidW)
	if verr3bw != nil {
		t.Errorf("SNMP v3 Error in SNMP_BulkWalk: %s", verr3bw.Error())
	}

	if BWalkRes == nil {
		t.Errorf("Error in SNMP_BulkWalk, result is nul")
	}

	if len(BWalkRes) == 0 {
		t.Errorf("Error in SNMP_BulkWalk, expected > 0 VarBinds but got %d", len(BWalkRes))
	}

	for _, wl := range BWalkRes {
		t.Log(Convert_OID_IntArrayToString_RAW(wl.RSnmpOID), "=", Convert_Variable_To_String(wl.RSnmpVar), ":", Convert_ClassTag_to_String(wl.RSnmpVar))
	}
	t.Log("-------- End --------")

	Close3Err := Ssess.Close()
	if Close3Err != nil {
		t.Errorf("SNMP v3  Error in Close: %s", Close3Err.Error())
	}

	t.Log("-------- Sitch to V2 --------")

	Nhost.SNMPparameters.SNMPversion = 2
	Ssess, SsessError = SNMP_Init(Nhost)
	if SsessError != nil {
		t.Errorf("Error in V2 SNMPInit: %v", SsessError.Error())
	}
	if Ssess == nil {
		t.Fatal("Error in SNMPInit")
	}
	t.Log("-------- Walk from OID 1.3.6.1.2.1.2.2.1.2 V2 --------")
	WalkResv2, verr3wv2 := Ssess.SNMP_Walk(IoidW)
	if verr3wv2 != nil {
		t.Errorf("SNMP v3 Error in SNMP_Walk: %s", verr3wv2.Error())
	}

	if WalkResv2 == nil {
		t.Errorf("Error in SNMP_Walk, result is nul")
	}

	if len(WalkResv2) == 0 {
		t.Errorf("Error in SNMP_Walk, expected > 0 VarBinds but got %d", len(WalkResv2))
	}

	for _, wlv2 := range WalkResv2 {
		t.Log(Convert_OID_IntArrayToString_RAW(wlv2.RSnmpOID), "=", Convert_Variable_To_String(wlv2.RSnmpVar), ":", Convert_ClassTag_to_String(wlv2.RSnmpVar))
	}

	t.Log("-------- End --------")
	t.Log("-------- Bulk walk from OID 1.3.6.1.2.1.2.2.1.2 V2 --------")
	WalkResv2, verr3wv2 = Ssess.SNMP_BulkWalk(IoidW)
	if verr3wv2 != nil {
		t.Errorf("SNMP v3 Error in SNMP_BulkWalk: %s", verr3wv2.Error())
	}

	if WalkResv2 == nil {
		t.Errorf("Error in SNMP_BulkWalk, result is nul")
	}

	if len(WalkResv2) == 0 {
		t.Errorf("Error in SNMP_BulkWalk, expected > 0 VarBinds but got %d", len(WalkResv2))
	}

	for _, wlv2 := range WalkResv2 {
		t.Log(Convert_OID_IntArrayToString_RAW(wlv2.RSnmpOID), "=", Convert_Variable_To_String(wlv2.RSnmpVar), ":", Convert_ClassTag_to_String(wlv2.RSnmpVar))
	}

	Close3Errv2 := Ssess.Close()
	if Close3Errv2 != nil {
		t.Errorf("SNMP v3  Error in Close: %s", Close3Errv2.Error())
	}
	t.Log("-------- End --------")

}
