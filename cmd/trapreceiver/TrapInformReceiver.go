// PowerSNMPv3 - SNMP library for Go
// Автор: Волков Олег
// Author: Volkov Oleg
// License: MIT (commercial version with support available)
// Лицензия: MIT (доступна коммерческая версия с поддержкой)

package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"sync"

	PowerSNMP "github.com/OlegPowerC/powersnmpv3"
)

// Message types (from RFC 3416)
const (
	MSG_REPORT = 1
	MSG_TRAP   = 2
	MSG_INFORM = 3
)

/*
Тестирование при помощи net-snmp
Протоколы:
sha + aes128
sha + aes192 с типом расширения ключа AGENT++
sha + aes256 с типом расширения ключа AGENT++
sha256 + aes256 с типом расширения ключа AGENT++

snmpinform -v 3 -u snmpuser -a sha -A pass123456 -l authPriv -x aes -X priv123456 -e 0x80001f8880f7996d5a41965d69 192.168.0.143 42 coldStart.0
snmpinform -v 3 -u snmpuser192 -a sha -A pass123456 -l authPriv -x aes-192 -X priv123456 -e 0x80001f8880f7996d5a41965d69 192.168.0.143 42 coldStart.0
snmpinform -v 3 -u snmpuser256 -a sha -A pass123456 -l authPriv -x aes-256 -X priv123456 -e 0x80001f8880f7996d5a41965d69 192.168.0.143 42 coldStart.0
snmpinform -v 3 -u snmpuser256256 -a sha -A pass123456 -l authPriv -x aes-256 -X priv123456 -e 0x80001f8880f7996d5a41965d69 192.168.0.143 42 coldStart.0
snmpinform -v 3 -u snmpuser256256 -a SHA-256 -A pass123456 -l authPriv -x aes-256 -X priv123456 -e 0x80001f8880f7996d5a41965d69 192.168.0.143 42 coldStart.0

Добавление учетных данных в map для быстрого поиска:
	Userv3Map["snmpuser"] = &PowerSNMP.SNMPTrapParameters{Username: "snmpuser", AuthProtocol: "sha", AuthKey: "pass123456", PrivProtocol: "aes", PrivKey: "priv123456"}
	Userv3Map["snmpuser192"] = &PowerSNMP.SNMPTrapParameters{Username: "snmpuser192", AuthProtocol: "sha", AuthKey: "pass123456", PrivProtocol: "aes192a", PrivKey: "priv123456"}
	Userv3Map["snmpuser256"] = &PowerSNMP.SNMPTrapParameters{Username: "snmpuser256", AuthProtocol: "sha", AuthKey: "pass123456", PrivProtocol: "aes256a", PrivKey: "priv123456"}
	Userv3Map["snmpuser256256"] = &PowerSNMP.SNMPTrapParameters{Username: "snmpuser256256", AuthProtocol: "sha256", AuthKey: "pass123456", PrivProtocol: "aes256a", PrivKey: "priv123456"}

Тестирование SNMPv2C
snmpinform -v 2c -c public 192.168.0.143 42 coldStart.0

Тут 192.168.0.143 - ваш IP куда посылать трап

snmpinform можно заменить на snmptrap чтоб протестировать именно прием трапов не требующих подтверждения приема
*/

func PrTrap(addr string, port int, data []byte, Userv3Map map[string]*PowerSNMP.SNMPTrapParameters) {
	//Приняли трап или информ
	SNMPver, SNMPv3User, v3SecData, PuErr := PowerSNMP.ParseTrapUsername(data)
	if PuErr != nil {
		fmt.Println("Ошибка разбора пакета")
	}
	var credentials PowerSNMP.SNMPTrapParameters

	if SNMPver == 3 {
		// SNMPv3: ищем пользователя и параметры аутентификации и шифрования, например в map
		if userCreds, found := Userv3Map[SNMPv3User]; found {
			credentials = *userCreds
		} else {
			fmt.Printf("Неизвестный пользователь SNMPv3: %s\n", SNMPv3User)
			return
		}
	} else if SNMPver == 1 {
		credentials.SNMPversion = 2
	} else {
		fmt.Printf("Неподдерживаемая версия SNMP: %d\n", SNMPver)
		return
	}

	//Конвертации в правильную версию для описания
	SNMPv3UserFoPrint := "3"
	if SNMPver == 1 {
		SNMPv3UserFoPrint = "2c"
	}
	fmt.Println("Принят trap/inform версии", SNMPv3UserFoPrint, "Пользователь/Community", SNMPv3User)

	if SNMPver == 3 {
		fmt.Println("Данные Security:")
		EngineIdHstr := ""
		if len(v3SecData.AuthEng) > 0 {
			EngineIdHstr = hex.EncodeToString(v3SecData.AuthEng)
		}
		fmt.Printf("Boots: %d, Time: %d, EngineID %s\r\n", v3SecData.Boots, v3SecData.Time, EngineIdHstr)
	}

	pversion, pmsgtype, datadec, err := PowerSNMP.ParseTrapWithCredentials(addr, port, data, credentials, 0)

	if err != nil {
		fmt.Printf("Неудалось разобрать пакет: %v\n", err)
		return
	}

	var msgTypeStr string
	var ackStatus string

	switch pmsgtype {
	case MSG_REPORT:
		msgTypeStr = "REPORT"
		ackStatus = ""
	case MSG_TRAP:
		msgTypeStr = "TRAP"
		ackStatus = "(ACK не требуется)"
	case MSG_INFORM:
		msgTypeStr = "INFORM"
		ackStatus = "(отправим ACK)" // ← Key feature!
	default:
		msgTypeStr = fmt.Sprintf("UNKNOWN(%d)", pmsgtype)
		ackStatus = ""
	}

	fmt.Println("─────────────────────────────────────────────────────────")
	fmt.Printf("Source:       %s:%d\n", addr, port)
	fmt.Printf("SNMP Version: v%d\n", pversion)
	fmt.Printf("Message Type: %s %s\n", msgTypeStr, ackStatus)
	fmt.Printf("RequestID:    %d\n", datadec.RequestID)
	fmt.Printf("VarBinds:     %d\n", len(datadec.VarBinds))
	fmt.Println("─────────────────────────────────────────────────────────")
	for _, gdata := range datadec.VarBinds {
		fmt.Println(PowerSNMP.Convert_OID_IntArrayToString_RAW(gdata.RSnmpOID), "=", PowerSNMP.Convert_Variable_To_String(gdata.RSnmpVar), ":", PowerSNMP.Convert_ClassTag_to_String(gdata.RSnmpVar))
	}

}

func RecPacket(conn net.PacketConn, Userv3Map map[string]*PowerSNMP.SNMPTrapParameters, wg *sync.WaitGroup) {
	defer wg.Done()
	buff := make([]byte, 2048)
	for {
		n, addr, err := conn.ReadFrom(buff)
		if err != nil {
			fmt.Println("Read error:", err)
			continue
		}
		data := make([]byte, n)
		copy(data, buff[:n])
		udpAddr := addr.(*net.UDPAddr)
		srcIP := udpAddr.IP.String()
		srcPort := udpAddr.Port
		go PrTrap(srcIP, srcPort, data, Userv3Map)
	}
}

func main() {
	var Userv3Map map[string]*PowerSNMP.SNMPTrapParameters
	var wg sync.WaitGroup

	Userv3Map = make(map[string]*PowerSNMP.SNMPTrapParameters)
	Userv3Map["snmpuser"] = &PowerSNMP.SNMPTrapParameters{Username: "snmpuser", AuthProtocol: "sha", AuthKey: "pass123456", PrivProtocol: "aes", PrivKey: "priv123456"}
	Userv3Map["snmpuser192"] = &PowerSNMP.SNMPTrapParameters{Username: "snmpuser192", AuthProtocol: "sha", AuthKey: "pass123456", PrivProtocol: "aes192a", PrivKey: "priv123456"}
	Userv3Map["snmpuser256"] = &PowerSNMP.SNMPTrapParameters{Username: "snmpuser256", AuthProtocol: "sha", AuthKey: "pass123456", PrivProtocol: "aes256a", PrivKey: "priv123456"}
	Userv3Map["snmpuser256256"] = &PowerSNMP.SNMPTrapParameters{Username: "snmpuser256256", AuthProtocol: "sha256", AuthKey: "pass123456", PrivProtocol: "aes256a", PrivKey: "priv123456"}
	Userv3Map["snmpuserm"] = &PowerSNMP.SNMPTrapParameters{Username: "snmpuserm", AuthProtocol: "md5", AuthKey: "pass123456", PrivProtocol: "aes", PrivKey: "priv123456"}
	Userv3Map["snmpuserm192"] = &PowerSNMP.SNMPTrapParameters{Username: "snmpuserm192", AuthProtocol: "md5", AuthKey: "pass123456", PrivProtocol: "aes192a", PrivKey: "priv123456"}
	Userv3Map["snmpuserm256"] = &PowerSNMP.SNMPTrapParameters{Username: "snmpuserm256", AuthProtocol: "md5", AuthKey: "pass123456", PrivProtocol: "aes256a", PrivKey: "priv123456"}
	conn, err := net.ListenPacket("udp", ":162")
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	wg.Add(1)
	go RecPacket(conn, Userv3Map, &wg)
	fmt.Println("Press Ctrl+C to stop")
	wg.Wait()
}
