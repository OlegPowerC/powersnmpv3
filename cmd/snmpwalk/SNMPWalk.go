// PowerSNMPv3 - SNMP library for Go
// Автор: Волков Олег, ООО "Пауэр Си"
// Author: Volkov Oleg, PowerC LLC
// License: MIT (commercial version with support available)
// Лицензия: MIT (доступна коммерческая версия с поддержкой)

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	PowerSNMP "github.com/OlegPowerC/powersnmpv3"
)

func main() {
	Host := flag.String("h", "", "Switch or routers IP")
	SNMPVersion := flag.Int("v", 3, "SNMP version, 2 or 3, default is 3")
	SNMPuser := flag.String("u", "", "SNMP v3 USER")
	SNMPcommunity := flag.String("c", "", "Mandatory for version 2, SNMP read community name")
	SNMPv3Context := flag.String("context", "", "SNMP v3 context")
	SNMPauthProtocol := flag.String("a", "", "SNMP auth protocol")
	SNMPauthPassword := flag.String("A", "", "SNMP auth password")
	SNMPprivProtocol := flag.String("x", "", "SNMP priv protocol")
	SNMPprivPassword := flag.String("X", "", "SNMP priv password")
	Bulk := flag.Bool("bulk", false, "SNMP Bukl")
	DebugLevel := flag.Int("debug", 0, "Debug lebel")
	StrOid := flag.String("o", "1.3.6", "SNMP OID")
	RawToo := flag.Bool("r", false, "RAW data")
	flag.Parse()

	var RouterDev PowerSNMP.NetworkDevice

	RouterDev.IPaddress = *Host
	RouterDev.Port = 161
	RouterDev.SNMPparameters.Username = *SNMPuser
	RouterDev.SNMPparameters.Community = *SNMPcommunity
	RouterDev.SNMPparameters.SNMPversion = *SNMPVersion
	RouterDev.SNMPparameters.AuthProtocol = *SNMPauthProtocol
	RouterDev.SNMPparameters.AuthKey = *SNMPauthPassword
	RouterDev.SNMPparameters.PrivProtocol = *SNMPprivProtocol
	RouterDev.SNMPparameters.PrivKey = *SNMPprivPassword
	RouterDev.SNMPparameters.ContextName = *SNMPv3Context
	RouterDev.SNMPparameters.RetryCount = 5
	RouterDev.SNMPparameters.MaxRepetitions = 50
	RouterDev.SNMPparameters.TimeoutBtwRepeat = 800
	RouterDev.DebugLevel = uint8(*DebugLevel)

	Ssess, SsessError := PowerSNMP.SNMP_Init(RouterDev)
	if SsessError != nil {
		fmt.Println(SsessError)
		os.Exit(1)
	}

	if Ssess == nil {
		fmt.Println("Session is nil")
		os.Exit(1)
	}
	defer Ssess.Close()

	iArOID, _ := PowerSNMP.Convert_OID_StringToIntArray_RAW(*StrOid)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	ChIn := make(chan PowerSNMP.ChanDataWErr, 3000)

	if *Bulk {
		go Ssess.SNMP_BulkWalk_WChan(ctx, iArOID, ChIn)
	} else {
		go Ssess.SNMP_Walk_WChan(ctx, iArOID, ChIn)
	}

	ResultNumber := 0
	for gdata := range ChIn {
		if gdata.Error != nil {
			fmt.Println(gdata.Error)
			os.Exit(1)
		}
		ResultNumber++
		if gdata.ValidData {
			if *RawToo {
				fmt.Println(PowerSNMP.Convert_OID_IntArrayToString_RAW(gdata.Data.RSnmpOID), "=", PowerSNMP.Convert_Variable_To_String(gdata.Data.RSnmpVar), ":", PowerSNMP.Convert_ClassTag_to_String(gdata.Data.RSnmpVar), gdata.Data.RSnmpVar.Value)
			} else {
				fmt.Println(PowerSNMP.Convert_OID_IntArrayToString_RAW(gdata.Data.RSnmpOID), "=", PowerSNMP.Convert_Variable_To_String(gdata.Data.RSnmpVar), ":", PowerSNMP.Convert_ClassTag_to_String(gdata.Data.RSnmpVar))
			}
		}
	}
}
