package PowerSNMPv3

import (
	"fmt"
	"slices"

	ASNber "github.com/OlegPowerC/asn1modsnmp"
)

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
func ParseTrapWithCredentials(SenderIp string, SenderPort int, packet []byte, UserData SNMPTrapParameters, LocalEBT SNMPLocalParams, cpboottimeid bool, debuglevel uint8) (decodedversion int, messagetype int, decryptedData SNMP_Packet_V2_decoded_PDU, err error) {
	var SNMPparameters SNMPv3Session
	var ReturnSNMPpacket SNMP_Packet_V2_decoded_PDU

	seclevel, aproto, pproto, aperr := CheckSNMPv3StringParams(UserData.AuthProtocol, UserData.AuthKey, UserData.PrivProtocol, UserData.PrivKey)
	if aperr != nil {
		return 0, 0, ReturnSNMPpacket, aperr
	}

	SNMPparameters.Debuglevel = debuglevel
	SNMPparameters.SNMPparams.SecurityLevel = seclevel
	SNMPparameters.SNMPparams.AuthProtocol = aproto
	SNMPparameters.SNMPparams.AuthKey = UserData.AuthKey
	SNMPparameters.SNMPparams.PrivProtocol = pproto
	SNMPparameters.SNMPparams.PrivKey = UserData.PrivKey
	SNMPparameters.SNMPparams.Username = UserData.Username
	SNMPparameters.SNMPparams.SNMPversion = UserData.SNMPversion
	SNMPparameters.SNMPparams.Community = UserData.Community
	SNMPparameters.SNMPparams.MaxMsgSize = 1360
	SNMPparameters.SNMPparams.txMaxMsgSize = 1360
	SNMPparameters.IPaddress = SenderIp
	SNMPparameters.SNMPparams.TimeoutBtwRepeat = 300
	SNMPparameters.Port = SenderPort

	if !cpboottimeid {
		//Установка локальных Boots и Time а так же EngineID
		SNMPparameters.SNMPparams.EngineID = LocalEBT.LocalEngineID
		SNMPparameters.SNMPparams.RBoots = LocalEBT.RBoots.Load()
		SNMPparameters.SNMPparams.RTime = LocalEBT.RTime.Load()
	}

	var SNMP_UnknownVersionPacket_Data SNMP_UnknownVersionPacket

	var SNMPpackerv3_FP SNMPv3_DecodePacket
	var SNMPpackerv2_FP SNMPv2_DecodePacket
	var MsgType int
	_, umerr := ASNber.Unmarshal(packet, &SNMP_UnknownVersionPacket_Data)
	if umerr != nil {
		return 0, 0, ReturnSNMPpacket, umerr
	}
	if SNMP_UnknownVersionPacket_Data.Version != 1 && SNMP_UnknownVersionPacket_Data.Version != 3 {
		return 0, 0, ReturnSNMPpacket, fmt.Errorf("SNMP protocol version: %d not supported", SNMP_UnknownVersionPacket_Data.Version)
	}
	if SNMP_UnknownVersionPacket_Data.Version == 3 {
		SNMPpackerv3_FP, umerr = parseSNMPv3Packet(&SNMPparameters, cpboottimeid, packet)
		if umerr == nil {
			ReturnSNMPpacket = SNMPpackerv3_FP.V3PDU.V2VarBind
			MsgType = SNMPpackerv3_FP.MessageType
		}

	} else {

		SNMPpackerv2_FP, umerr = parseSNMPv2Packet(&SNMPparameters, packet)
		if umerr == nil {
			MsgType = SNMPpackerv2_FP.MessageType
			ReturnSNMPpacket = SNMPpackerv2_FP.V2PDU
		}

	}

	if umerr == nil && MsgType == INFORM_MESSAGE {
		//Надо отправить ACK
		if SNMP_UnknownVersionPacket_Data.Version == 3 {
			umerr = SNMPparameters.sendV3ACK(ReturnSNMPpacket.RequestID)
		}
		if SNMP_UnknownVersionPacket_Data.Version != 3 {
			SNMPparameters.SNMPparams.Community = string(SNMPpackerv2_FP.Community)
			umerr = SNMPparameters.sendV2ACK(ReturnSNMPpacket.RequestID)
		}
	}

	return SNMP_UnknownVersionPacket_Data.Version, MsgType, ReturnSNMPpacket, umerr
}

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
func ParseTrapUsername(packet []byte) (version int, username string, v3secdata SNMPv3_SecSeq, v3globaldata SNMPv3_GlobalData, err error) {
	var SNMP_UnknownVersionPacket_Data SNMP_UnknownVersionPacket
	var v3secd SNMPv3_SecSeq
	var v3globald SNMPv3_GlobalData
	var umerr error

	_, umerr = ASNber.Unmarshal(packet, &SNMP_UnknownVersionPacket_Data)
	if umerr != nil {
		return 0, "", v3secd, v3globald, umerr
	}

	if SNMP_UnknownVersionPacket_Data.Version != 1 && SNMP_UnknownVersionPacket_Data.Version != 3 {
		return 0, "", v3secd, v3globald, fmt.Errorf("SNMP protocol version: %d not supported", SNMP_UnknownVersionPacket_Data.Version)
	}

	// Для SNMPv2 извлекаем Community String как "username"
	if SNMP_UnknownVersionPacket_Data.Version == 1 {
		var vs SNMP_Packet_V2
		_, umerr = ASNber.Unmarshal(packet, &vs)
		if umerr != nil {
			return 0, "", v3secd, v3globald, umerr
		}
		return SNMP_UnknownVersionPacket_Data.Version, string(vs.V2CcommunityString), v3secd, v3globald, nil
	}

	// Для SNMPv3 извлекаем Username и Secutiry Settings
	var SNMPrecivedPacket SNMPv3_Packet
	_, umerr = ASNber.Unmarshal(packet, &SNMPrecivedPacket)
	if umerr != nil {
		return 0, "", v3secd, v3globald, umerr
	}

	//Парсим RAW данные GlobalData из SNMPrecivedPacket
	_, umerr = ASNber.Unmarshal(SNMPrecivedPacket.GlobalData.FullBytes, &v3globald)
	if umerr != nil {
		//Ошибка парсинга
		return 0, "", v3secd, v3globald, umerr
	}

	var RecivedSecurity SNMPv3_SecSeq
	_, umerr = ASNber.Unmarshal(SNMPrecivedPacket.SecuritySettings, &RecivedSecurity)
	if umerr != nil {
		return 0, "", v3secd, v3globald, umerr
	}

	v3secd = RecivedSecurity
	return SNMP_UnknownVersionPacket_Data.Version, string(RecivedSecurity.User), v3secd, v3globald, nil
}

func ParceInformInvalidData(SenderIp string, SenderPort int, packet []byte, UserData SNMPTrapParameters, LocalEBT SNMPLocalParams, debuglevel uint8) (err error) {
	//Оптравитель перед посылкой Inform, может сначала попробовать определить EngineID/Boots/Time
	var SNMPparameters SNMPv3Session
	var ReturnSNMPpacket SNMP_Packet_V2_decoded_PDU

	SNMPparameters.Debuglevel = debuglevel
	SNMPparameters.SNMPparams.SecurityLevel = SECLEVEL_NOAUTH_NOPRIV
	SNMPparameters.SNMPparams.AuthProtocol = AUTH_PROTOCOL_NONE
	SNMPparameters.SNMPparams.AuthKey = ""
	SNMPparameters.SNMPparams.PrivProtocol = PRIV_PROTOCOL_NONE
	SNMPparameters.SNMPparams.PrivKey = ""
	SNMPparameters.SNMPparams.Username = UserData.Username
	SNMPparameters.SNMPparams.SNMPversion = 3
	SNMPparameters.SNMPparams.Community = ""
	SNMPparameters.SNMPparams.MaxMsgSize = 1360
	SNMPparameters.SNMPparams.txMaxMsgSize = 1360
	SNMPparameters.IPaddress = SenderIp
	SNMPparameters.SNMPparams.TimeoutBtwRepeat = 300
	SNMPparameters.Port = SenderPort

	SNMPparameters.SNMPparams.EngineID = LocalEBT.LocalEngineID
	SNMPparameters.SNMPparams.RBoots = LocalEBT.RBoots.Load()
	SNMPparameters.SNMPparams.RTime = LocalEBT.RTime.Load()

	var SNMP_UnknownVersionPacket_Data SNMP_UnknownVersionPacket

	var SNMPpackerv3_FP SNMPv3_DecodePacket
	var MsgType int
	_, umerr := ASNber.Unmarshal(packet, &SNMP_UnknownVersionPacket_Data)
	if umerr != nil {
		return umerr
	}
	if SNMP_UnknownVersionPacket_Data.Version != 3 {
		return fmt.Errorf("SNMP protocol version: %d not supported", SNMP_UnknownVersionPacket_Data.Version)
	}
	if SNMP_UnknownVersionPacket_Data.Version == 3 {
		SNMPpackerv3_FP, umerr = parseSNMPv3Packet(&SNMPparameters, false, packet)
		if umerr == nil {
			ReturnSNMPpacket = SNMPpackerv3_FP.V3PDU.V2VarBind
			MsgType = SNMPpackerv3_FP.MessageType
		}

	}

	if umerr == nil && MsgType == GETREQUEST_MESSAGE {
		//Надо отправить REPORT
		var ReportToSend []int
		if !slices.Equal(SNMPpackerv3_FP.SecuritySettings.AuthEng, LocalEBT.LocalEngineID) {
			ReportToSend = OID_UnknownEngineId
		} else {
			if SNMPpackerv3_FP.SecuritySettings.Time != LocalEBT.RTime.Load() || SNMPpackerv3_FP.SecuritySettings.Boots != LocalEBT.RBoots.Load() {
				ReportToSend = OID_NoInTime
			}
		}

		if len(ReportToSend) > 0 {
			SNMPparameters.SNMPparams.DataFlag = 0
			umerr = SNMPparameters.sendV3REPORT(ReturnSNMPpacket.RequestID, ReportToSend)
		}

	}

	return umerr
}
