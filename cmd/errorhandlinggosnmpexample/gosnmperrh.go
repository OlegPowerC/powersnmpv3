package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/gosnmp/gosnmp"
)

func connect(host, user, authProto, authPass, privProto, privPass string) *gosnmp.GoSNMP {
	params := &gosnmp.GoSNMP{
		Target:        host,
		Port:          161,
		Version:       gosnmp.Version3,
		Timeout:       time.Duration(2) * time.Second,
		Retries:       1,
		MsgFlags:      gosnmp.AuthPriv,
		SecurityModel: gosnmp.UserSecurityModel,
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName:                 user,
			AuthenticationProtocol:   parseAuth(authProto),
			AuthenticationPassphrase: authPass,
			PrivacyProtocol:          parsePriv(privProto),
			PrivacyPassphrase:        privPass,
		},
	}

	err := params.Connect()
	if err != nil {
		log.Fatalf("Connect error: %v", err)
	}
	return params
}

func parseAuth(p string) gosnmp.SnmpV3AuthProtocol {
	switch p {
	case "sha":
		return gosnmp.SHA
	case "md5":
		return gosnmp.MD5
	default:
		return gosnmp.NoAuth
	}
}

func parsePriv(p string) gosnmp.SnmpV3PrivProtocol {
	switch p {
	case "aes":
		return gosnmp.AES
	case "des":
		return gosnmp.DES
	default:
		return gosnmp.NoPriv
	}
}

func DemoSingleGET_OIDsynt(g *gosnmp.GoSNMP) {
	fmt.Println("*************************************************************************************************")
	fmt.Println("=== gosnmp: GET single, wrong OID format ===")
	oid := "1.3.6.1.2.1.1.a.0"
	fmt.Println("--- Do GET with wrong error ---")
	res, err := g.Get([]string{oid})
	fmt.Println("--- Check errors ---")
	if err != nil {
		fmt.Println("Error:", err)
		return
	} else {
		fmt.Println("--- No error ---")
	}

	if res.Error != gosnmp.NoError {
		fmt.Println("SNMP Error:", res.Error)
	} else {
		fmt.Println("--- res.Error == gosnmp.NoError ---")
	}

	for _, v := range res.Variables {
		fmt.Printf("%s = %v\n", v.Name, v.Value)
	}
	fmt.Println("*************************************************************************************************")
	fmt.Println()
}

func DemoSingleGET_Valid(g *gosnmp.GoSNMP) {
	fmt.Println("*************************************************************************************************")
	fmt.Println("=== gosnmp: GET single valid ===")
	oid := "1.3.6.1.2.1.1.5.0"

	res, err := g.Get([]string{oid})
	fmt.Println("--- Check errors ---")
	if err != nil {
		fmt.Println("Error:", err)
		return
	} else {
		fmt.Println("--- No error ---")
	}

	if res.Error != gosnmp.NoError {
		fmt.Println("SNMP Error:", res.Error)
	} else {
		fmt.Println("--- res.Error == gosnmp.NoError ---")
	}

	for _, v := range res.Variables {
		fmt.Printf("%s = %v\n", v.Name, v.Value)
	}
	fmt.Println("*************************************************************************************************")
	fmt.Println()
}

func DemoSingleGET_Invalid(g *gosnmp.GoSNMP) {
	fmt.Println("*************************************************************************************************")
	fmt.Println("=== gosnmp: GET single invalid ===")
	oid := "1.3.6.1.2.1.1.99.0"

	res, err := g.Get([]string{oid})
	fmt.Println("--- Check errors ---")
	if err != nil {
		fmt.Println("Error:", err)
		return
	} else {
		fmt.Println("--- No error ---")
	}

	if res.Error != gosnmp.NoError {
		fmt.Println("SNMP Error:", res.Error)
	} else {
		fmt.Println("--- res.Error == gosnmp.NoError ---")
	}

	for _, v := range res.Variables {
		fmt.Printf("%s = %v\n", v.Name, v.Value)
	}

	fmt.Println("*************************************************************************************************")
	fmt.Println()
}

func DemoMultiGET_PartInvalid(g *gosnmp.GoSNMP) {
	fmt.Println("*************************************************************************************************")
	fmt.Println("=== gosnmp: GET multi (mixed OIDs) ===")

	oids := []string{
		"1.3.6.1.2.1.1.6.0",
		"1.3.6.1.2.1.1.99.0",
		"1.3.6.1.2.1.1.5.0",
		"1.3.6.1.2.1.1.100.0",
	}

	res, err := g.Get(oids)
	fmt.Println("--- Check errors ---")
	if err != nil {
		fmt.Println("Error:", err)
		return
	} else {
		fmt.Println("--- No error ---")
	}

	if res.Error != gosnmp.NoError {
		fmt.Println("SNMP Error (entire request failed):", res.Error)
	} else {
		fmt.Println("--- res.Error == gosnmp.NoError ---")
	}

	fmt.Println("--- Returned variables ---")
	for _, v := range res.Variables {
		fmt.Printf("%s = %v\n", v.Name, v.Value)
	}
	fmt.Println("*************************************************************************************************")
	fmt.Println()
}

func DemoSET_Valid(g *gosnmp.GoSNMP) {
	fmt.Println("*************************************************************************************************")
	fmt.Println("=== gosnmp: SET valid ===")

	pdus := []gosnmp.SnmpPDU{
		{Name: "1.3.6.1.2.1.1.6.0", Type: gosnmp.OctetString, Value: "TestZone1"},
		{Name: "1.3.6.1.2.1.1.5.0", Type: gosnmp.OctetString, Value: "Sw01"},
	}

	res, err := g.Set(pdus)
	fmt.Println("--- Check errors ---")
	if err != nil {
		fmt.Println("Error:", err)
		return
	} else {
		fmt.Println("--- No error ---")
	}

	if res.Error != gosnmp.NoError {
		fmt.Println("SNMP Error:", res.Error)
	} else {
		fmt.Println("--- res.Error == gosnmp.NoError ---")
	}

	for _, v := range res.Variables {
		fmt.Printf("%s = %v\n", v.Name, v.Value)
	}

	fmt.Println("*************************************************************************************************")
	fmt.Println()
}

func DemoSET_Invalid(g *gosnmp.GoSNMP) {
	fmt.Println("*************************************************************************************************")
	fmt.Println("=== gosnmp: SET invalid ===")

	pdus := []gosnmp.SnmpPDU{
		{Name: "1.3.6.1.2.1.1.6.0", Type: gosnmp.OctetString, Value: "TestZone1"},
		{Name: "1.3.6.1.2.1.1.99.0", Type: gosnmp.OctetString, Value: "FAIL"},
	}

	res, err := g.Set(pdus)
	fmt.Println("--- Check errors ---")
	if err != nil {
		fmt.Println("Error:", err)
		return
	} else {
		fmt.Println("--- No error ---")
	}

	if res.Error != gosnmp.NoError {
		fmt.Println("SNMP Error (SET failed):", res.Error)
	} else {
		fmt.Println("--- res.Error == gosnmp.NoError ---")
	}

	for _, v := range res.Variables {
		fmt.Printf("%s = %v\n", v.Name, v.Value)
	}

	fmt.Println("*************************************************************************************************")
	fmt.Println()
}

func main() {
	host := flag.String("h", "", "Host")
	user := flag.String("u", "", "User")
	auth := flag.String("a", "sha", "Auth proto")
	authPass := flag.String("A", "", "Auth pass")
	priv := flag.String("x", "aes", "Priv proto")
	privPass := flag.String("X", "", "Priv pass")
	flag.Parse()

	g := connect(*host, *user, *auth, *authPass, *priv, *privPass)
	defer g.Conn.Close()

	DemoSingleGET_Valid(g)
	DemoSingleGET_Invalid(g)
	DemoMultiGET_PartInvalid(g)
	DemoSET_Valid(g)
	DemoSET_Invalid(g)
	DemoSingleGET_OIDsynt(g)
}
