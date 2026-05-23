package PowerSNMPv3

import (
	"errors"
	"fmt"
	"net"
	"sync/atomic"

	ASNber "github.com/OlegPowerC/asn1modsnmp"
)

// ParseTrapUsername extracts username/community from TRAP packets (version-blind).
//
// Quick credential extraction for trap filtering/ACL without full decryption.
// Returns SNMPv2c community OR SNMPv3 userName + security parameters.
//
// Arguments:
//
//	packet - Raw TRAP/INFORM bytes
//
// Returns:
//
//	version    - 1(SNMPv2c), 3(SNMPv3)
//	username   - Community string OR userName
//	v3secdata  - Security parameters (SNMPv3 only, zeroed for v2c)
//	err        - ASN.1 decode errors
//
// Production trap filter:
//
//	```go
//	version, user, _, err := ParseTrapUsername(pkt)
//	if err != nil { return }
//
//	switch user {
//	case "public":    dropPublicTraps(pkt)
//	case "admin":     processCriticalTraps(pkt)
//	case "monitor":   queueForGrafana(pkt)
//	}
//	```
//
// Flow:
//   - SNMPv2c → community string extraction
//   - SNMPv3  → userName + USM parameters (secLevel, authP, privP)
//
// Zero-copy for v2c, minimal ASN.1 unmarshaling for v3 header only.
func ParseTrapUsername(packet []byte) (version int, username string, SNMPv3GlobalSecData SNMPv3_DhPacket, err error) {
	var SNMP_UnknownVersionPacket_Data SNMP_UnknownVersionPacket
	var SNMPrecivedPacket SNMPv3_Packet
	var SNMPv3RetGlobalSecData SNMPv3_DhPacket
	var umerr error

	_, umerr = ASNber.Unmarshal(packet, &SNMP_UnknownVersionPacket_Data)
	if umerr != nil {
		return 0, "", SNMPv3RetGlobalSecData, umerr
	}

	if SNMP_UnknownVersionPacket_Data.Version != 1 && SNMP_UnknownVersionPacket_Data.Version != 3 {
		return 0, "", SNMPv3RetGlobalSecData, fmt.Errorf("SNMP protocol version: %d not supported", SNMP_UnknownVersionPacket_Data.Version)
	}

	// Для SNMPv2 извлекаем Community String как "username"
	if SNMP_UnknownVersionPacket_Data.Version == 1 {
		var vs SNMP_Packet_V2
		_, umerr = ASNber.Unmarshal(packet, &vs)
		if umerr != nil {
			return 0, "", SNMPv3RetGlobalSecData, umerr
		}
		//Установим версию 2c в параметрах GlobalData хотя они и для v3
		SNMPv3RetGlobalSecData.Version = 1
		return SNMP_UnknownVersionPacket_Data.Version, string(vs.V2CcommunityString), SNMPv3RetGlobalSecData, nil
	}

	// Для SNMPv3 извлекаем Username и Secutiry Settings
	_, umerr = ASNber.Unmarshal(packet, &SNMPrecivedPacket)
	if umerr != nil {
		return 0, "", SNMPv3RetGlobalSecData, umerr
	}

	//Парсим RAW данные GlobalData из SNMPrecivedPacket
	_, umerr = ASNber.Unmarshal(SNMPrecivedPacket.GlobalData.FullBytes, &SNMPv3RetGlobalSecData.GlobalData)
	if umerr != nil {
		//Ошибка парсинга
		return 0, "", SNMPv3RetGlobalSecData, umerr
	}

	_, umerr = ASNber.Unmarshal(SNMPrecivedPacket.SecuritySettings, &SNMPv3RetGlobalSecData.SecuritySettings)
	if umerr != nil {
		return 0, "", SNMPv3RetGlobalSecData, umerr
	}

	SNMP_UnknownVersionPacket_Data.Version = SNMPrecivedPacket.Version
	SNMPv3RetGlobalSecData.PtData = SNMPrecivedPacket.PtData

	return SNMP_UnknownVersionPacket_Data.Version, string(SNMPv3RetGlobalSecData.SecuritySettings.User), SNMPv3RetGlobalSecData, nil
}

// ParseTrapWithCredentials decodes SNMP TRAP/INFORM packets with credential validation.
//
// Handles SNMPv2c/v3 TRAPs and SNMPv3 INFORMs (with ACK response). Supports authPriv decryption.
// Auto-detects version and sends INFORM ACK per RFC3411 §5 and RFC3826.
//
// Arguments:
//
//	SenderIp    - Source IP (for ACK response)
//	SenderPort  - Source UDP port (for ACK response)
//	packet      - Raw SNMP packet bytes (TRAP/INFORM)
//	UserData    - Credentials (userName/authKey/privKey)
//	debuglevel  - Debug verbosity (0-255)
//
// Returns:
//
//	version     - 1(SNMPv2c), 3(SNMPv3)
//	messagetype - TRAP_MESSAGE(7), INFORM_MESSAGE(8)
//	pdu         - Decoded SNMPv2 PDU (varbinds only)
//	err         - Parse/decrypt/ACK errors
//
// INFORM ACK flow (RFC3411):
//  1. Decode INFORM → RequestID extraction
//  2. Send Response PDU (same RequestID, noError)
//  3. Original INFORM varbinds returned
//
// Production trap receiver:
//
//	```go
//	pkt, _ := readUDPSocket()  // 162 UDP
//	version, msgType, pdu, err := ParseTrapWithCredentials(
//	    senderIP, senderPort, pkt, creds, 1)
//	if err != nil { return }
//
//	if msgType == INFORM_MESSAGE {
//	    log.Printf("INFORM ACK sent for RequestID=%d", pdu.RequestID)
//	}
//
//	for _, vb := range pdu.VarBinds {
//	    fmt.Printf("Trap %s=%s\n", vb.RSnmpOID, vb.RSnmpVar)
//	}
//	```
//
// Error hierarchy:
//   - ASN.1 decode → ASNber.Unmarshal
//   - Auth/Priv   → authNoPriv(17), decryptErr(11)
//   - ACK send    → Network/timeout errors
//
// Supports: Cisco/Huawei/Eltex TRAPs (tested).
func ParseTrapWithCredentials(conn net.PacketConn, addr net.Addr,
	Version int,
	packet []byte,
	SNMPv3PPacket *SNMPv3_DhPacket,
	UserData SNMPTrapParameters,
	LocalEBT *SNMPLocalParams,
	cpboottimeid bool,
	debuglevel uint8) (decodedversion int, messagetype int, decryptedData SNMP_Packet_V2_decoded_PDU, err error) {
	var SNMPparameters SNMPv3Session
	var ReturnSNMPpacket SNMP_Packet_V2_decoded_PDU
	var SNMPpackerv2_FP SNMPv2_DecodePacket
	var MsgType int
	var umerr error

	udpAddr, pok := addr.(*net.UDPAddr)
	if !pok {
		return 0, 0, ReturnSNMPpacket, errors.New("invalid address")
	}
	SenderIp := udpAddr.IP.String()
	SenderPort := udpAddr.Port

	SNMPparameters.Debuglevel = debuglevel
	SNMPparameters.SNMPparams.AuthKey = UserData.AuthKey
	SNMPparameters.SNMPparams.PrivKey = UserData.PrivKey
	SNMPparameters.SNMPparams.Username = UserData.Username
	SNMPparameters.SNMPparams.SNMPversion = UserData.SNMPversion
	SNMPparameters.SNMPparams.Community = UserData.Community
	SNMPparameters.IPaddress = SenderIp
	SNMPparameters.Port = SenderPort
	SNMPparameters.SNMPparams.MaxMsgSize = 1360
	SNMPparameters.SNMPparams.txMaxMsgSize = 1360
	SNMPparameters.IPaddress = SenderIp
	SNMPparameters.SNMPparams.TimeoutBtwRepeat = 300
	SNMPparameters.Port = SenderPort

	if cpboottimeid {
		atomic.StoreInt32(&SNMPparameters.SNMPparams.RBoots, SNMPv3PPacket.SecuritySettings.Boots)
		atomic.StoreInt32(&SNMPparameters.SNMPparams.RTime, SNMPv3PPacket.SecuritySettings.Time)
	}

	if Version != 1 && Version != 3 {
		return 0, 0, ReturnSNMPpacket, errors.New("SNMPv3 trap parser version unsupported")
	}

	if Version == 1 {
		SNMPparameters.SNMPparams.SNMPversion = 2
		SNMPpackerv2_FP, umerr = SNMPparameters.parseSNMPv2Packet(packet)
		if umerr != nil {
			return 0, 0, ReturnSNMPpacket, umerr
		}

		MsgType = SNMPpackerv2_FP.MessageType
		ReturnSNMPpacket = SNMPpackerv2_FP.V2PDU

		if MsgType == INFORM_MESSAGE {
			//Надо отправить ACK
			SNMPparameters.SNMPparams.Community = string(SNMPpackerv2_FP.Community)
			umerr = SNMPparameters.sendV2ACK(conn, addr, ReturnSNMPpacket.RequestID)
		}
		return Version, MsgType, ReturnSNMPpacket, umerr
	}

	seclevel, aproto, pproto, aperr := CheckSNMPv3StringParams(UserData.AuthProtocol, UserData.AuthKey, UserData.PrivProtocol, UserData.PrivKey)
	if aperr != nil {
		return 0, 0, ReturnSNMPpacket, aperr
	}

	SNMPparameters.SNMPparams.SecurityLevel = seclevel
	SNMPparameters.SNMPparams.AuthProtocol = aproto
	SNMPparameters.SNMPparams.PrivProtocol = pproto
	SNMPparameters.SNMPparams.MessageId = SNMPv3PPacket.GlobalData.MsgID

	if !cpboottimeid {
		//Установка локальных Boots и Time а так же EngineID
		SNMPparameters.SNMPparams.EngineID = LocalEBT.LocalEngineID
		SNMPparameters.SNMPparams.RBoots = LocalEBT.RBoots.Load()
		SNMPparameters.SNMPparams.RTime = LocalEBT.RTime.Load()
	}

	MsgPr, MsgPrErr := SNMPparameters.receiverV3Bparser(packet, SNMPv3PPacket, false, true, 0)
	if MsgPrErr != nil {
		return 0, 0, ReturnSNMPpacket, MsgPrErr
	}

	MsgType = MsgPr.MessageType
	ReturnSNMPpacket = MsgPr.V3PDU.V2VarBind
	//SNMPparameters.SNMPparams.MessageId = MsgPr.SecuritySettings.
	//SNMPparams.MessageId

	if MsgType == INFORM_MESSAGE {
		//Надо отправить ACK
		umerr = SNMPparameters.sendV3ACK(conn, addr, ReturnSNMPpacket.RequestID)
	}

	if MsgType == GETREQUEST_MESSAGE {
		if len(MsgPr.SecuritySettings.AuthEng) == 0 {
			SNMPparameters.SNMPparams.EngineID = LocalEBT.LocalEngineID
			SNMPparameters.SNMPparams.RBoots = LocalEBT.RBoots.Load()
			SNMPparameters.SNMPparams.RTime = LocalEBT.RTime.Load()
			umerr = SNMPparameters.sendV3REPORT(conn, addr, ReturnSNMPpacket.RequestID, OID_UnknownEngineId)
			return Version, MsgType, ReturnSNMPpacket, umerr
		}
	}

	return Version, MsgType, ReturnSNMPpacket, umerr
}
