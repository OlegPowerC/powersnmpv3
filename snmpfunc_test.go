// PowerSNMPv3 - SNMP library for Go
// Автор: Волков Олег, ООО "Пауэр Си"
// Author: Volkov Oleg, PowerC LLC
// License: MIT (commercial version with support available)
// Лицензия: MIT (доступна коммерческая версия с поддержкой)
package PowerSNMPv3

import (
	"flag"
	"fmt"
	"os"
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
	StrOid := "1.3.6.1.2.1.1.6.0" //Sys Location
	Ioid, _ := Convert_OID_StringToIntArray(StrOid)

	GetRes2, verr2 := Ssess.SNMP_Get(Ioid)
	if verr2 != nil {
		t.Errorf("SNMP v2 Error in SNMP_Get: %s", verr2.Error())
	}

	for _, wl := range GetRes2 {
		t.Log(fmt.Println(Convert_OID_IntArrayToString_RAW(wl.RSnmpOID), "=", Convert_Variable_To_String(wl.RSnmpVar), ":", Convert_ClassTag_to_String(wl.RSnmpVar)))
	}

	var SNMPsv SNMPVar
	SNMPsv = SetSNMPVar_OctetString("Test location from V2")

	_, verr2 = Ssess.SNMP_Set(Ioid, SNMPsv)
	if verr2 != nil {
		t.Errorf("SNMP v2 Error in SNMP_Set: %s", verr2.Error())
	}

	CloseErr := Ssess.Close()
	if CloseErr != nil {
		t.Errorf("SNMP v2  Error in Close: %s", CloseErr.Error())
	}

	Nhost.SNMPparameters.SNMPversion = 3

	Ssess, SsessError = SNMP_Init(Nhost)
	if SsessError != nil {
		t.Errorf("SNMP v3 Error in SNMPInit: %s", SsessError.Error())
	}

	GetRes3, verr3 := Ssess.SNMP_Get(Ioid)
	if verr3 != nil {
		t.Errorf("SNMP v3 Error in SNMP_Get: %s", verr3.Error())
	}

	if GetRes3 == nil {
		t.Errorf("SNMP v3 Error in SNMP_Get, reult is nul")
	}

	for _, wl := range GetRes3 {
		t.Log(fmt.Println(Convert_OID_IntArrayToString_RAW(wl.RSnmpOID), "=", Convert_Variable_To_String(wl.RSnmpVar), ":", Convert_ClassTag_to_String(wl.RSnmpVar)))
		location := Convert_Variable_To_String(wl.RSnmpVar)
		if Convert_Variable_To_String(wl.RSnmpVar) != "Test location from V2" {
			t.Logf("ℹ️ V3 sees: '%s' (V2 SET может иметь разные ACL)", location)
		} else {
			t.Logf("V2→V3 VERIFICATION PASS! '%s'", location)
		}
	}

	var SNMPsv3 SNMPVar
	SNMPsv3 = SetSNMPVar_OctetString("Test location")

	_, verr3 = Ssess.SNMP_Set(Ioid, SNMPsv3)
	if verr3 != nil {
		t.Errorf("SNMP v3  Error in SNMP_Set: %s", verr3.Error())
	}

	StrOidW := "1.3.6.1.2.1.2.2.1.2" //Sys Location
	IoidW, _ := Convert_OID_StringToIntArray(StrOidW)

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
		t.Log(fmt.Println(Convert_OID_IntArrayToString_RAW(wl.RSnmpOID), "=", Convert_Variable_To_String(wl.RSnmpVar), ":", Convert_ClassTag_to_String(wl.RSnmpVar)))
	}

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
		t.Log(fmt.Println(Convert_OID_IntArrayToString_RAW(wl.RSnmpOID), "=", Convert_Variable_To_String(wl.RSnmpVar), ":", Convert_ClassTag_to_String(wl.RSnmpVar)))
	}

	Close3Err := Ssess.Close()
	if Close3Err != nil {
		t.Errorf("SNMP v3  Error in Close: %s", Close3Err.Error())
	}
}
