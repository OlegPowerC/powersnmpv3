// PowerSNMPv3 - SNMP library for Go
// Автор: Волков Олег
// Author: Volkov Oleg
// License: MIT (commercial version with support available)
// Лицензия: MIT (доступна коммерческая версия с поддержкой)
package PowerSNMPv3

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"sync/atomic"

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
func ParseTrapWithCredentials(SenderIp string, SenderPort int, packet []byte, UserData SNMPTrapParameters, debuglevel uint8) (decodedversion int, messagetype int, decryptedData SNMP_Packet_V2_decoded_PDU, err error) {
	var SNMPparameters SNMPv3Session
	var ReturnSNMPpacket SNMP_Packet_V2_decoded_PDU

	seclevel, aproto, pproto, aperr := setAuthPrivParamsStToInt(UserData.AuthProtocol, UserData.AuthKey, UserData.PrivProtocol, UserData.PrivKey)
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
	SNMPparameters.IPaddress = SenderIp
	SNMPparameters.SNMPparams.TimeoutBtwRepeat = 300
	SNMPparameters.Port = SenderPort

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
		SNMPpackerv3_FP, umerr = parseSNMPv3Packet(&SNMPparameters, packet)
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

func parseSNMPv3Packet(SNMPparameters *SNMPv3Session, packet []byte) (decryptedData SNMPv3_DecodePacket, err error) {
	var RetPacket SNMPv3_DecodePacket
	var SNMPDataErr error
	RetPacket, SNMPDataErr = receiverV3parser(SNMPparameters, packet, false, 0)
	return RetPacket, SNMPDataErr
}

func parseSNMPv2Packet(SNMPparameters *SNMPv3Session, packet []byte) (decryptedData SNMPv2_DecodePacket, err error) {
	var RetPacket SNMPv2_DecodePacket
	var SNMPDataErr error
	RetPacket, SNMPDataErr = receiverV2parser(SNMPparameters, packet, false, 0)
	return RetPacket, SNMPDataErr
}

func receiverV2parser(SNMPparameters *SNMPv3Session, packet []byte, checkmsg_req_id bool, reqid int32) (decodedDatav2 SNMPv2_DecodePacket, errorv2 error) {
	var vs SNMP_Packet_V2
	var RetVar SNMPv2_DecodePacket
	var pdu1 SNMP_Packet_V2_PDU
	var umerr error
	var partialerr SNMPne_Errors
	partialerr.Failedoids = make([]PowerSNMPv3_Errors_FailedOids_Error, 0)
	defer func() {
		if umerr == nil && len(partialerr.Failedoids) > 0 {
			errorv2 = partialerr
		}
	}()

	_, umerr = ASNber.Unmarshal(packet, &vs)
	if umerr != nil {
		return RetVar, umerr
	}
	if len(vs.V2VarBind.FullBytes) == 0 {
		umerr = errors.New("empty V2VarBind")
		return RetVar, umerr
	}

	RetVar.Community = vs.V2CcommunityString
	//Проверяем тип пакета
	if vs.V2VarBind.Class == 0x02 {
		switch vs.V2VarBind.Tag {
		case 0x07:
			if SNMPparameters.Debuglevel > 199 {
				fmt.Println("Received Trap MSG!")
			}
			RetVar.MessageType = TRAP_MESSAGE

		case 0x6:
			if SNMPparameters.Debuglevel > 199 {
				fmt.Println("Received Inform MSG!")
			}
			RetVar.MessageType = INFORM_MESSAGE
		}

	}

	vs.V2VarBind.FullBytes[0] = 0x30
	_, umerr = ASNber.Unmarshal(vs.V2VarBind.FullBytes, &pdu1)
	if umerr != nil {
		return RetVar, umerr
	}

	if checkmsg_req_id && pdu1.RequestID != reqid {
		umerr = SNMPwrongReqID_MsgId_Errors{PARCE_ERR_WRONGREQID}
		return RetVar, umerr //return ReturnSNMPpacker, errors.New("invalid request id")
	}

	RetVar.V2PDU.RequestID = pdu1.RequestID
	RetVar.V2PDU.ErrorIndexRaw = pdu1.ErrorIndexRaw
	RetVar.V2PDU.ErrorStatusRaw = pdu1.ErrorStatusRaw

	if pdu1.ErrorStatusRaw != sNMP_ErrNoError {
		failedOID := []int{}
		//Скопируем проблемный OID
		if pdu1.ErrorIndexRaw > 0 {
			if int(pdu1.ErrorIndexRaw-1) < len(pdu1.VarBinds) {
				failedOID = pdu1.VarBinds[pdu1.ErrorIndexRaw-1].RSnmpOID
			}
		}
		switch pdu1.ErrorStatusRaw {
		case sNMP_ErrResponseTooLarge:
			partialerr.Failedoids = append(partialerr.Failedoids, PowerSNMPv3_Errors_FailedOids_Error{failedOID, int(pdu1.ErrorStatusRaw)})
		case sNMP_ErrGeneralError, sNMP_ErrNoAccess, sNMP_ErrResourcesUnavailable:
			partialerr.Failedoids = append(partialerr.Failedoids, PowerSNMPv3_Errors_FailedOids_Error{failedOID, int(pdu1.ErrorStatusRaw)})
		default:
			umerr = SNMPfe_Errors{ErrorStatusRaw: pdu1.ErrorStatusRaw, ErrorIndexRaw: pdu1.ErrorIndexRaw, FailedOID: failedOID}
			return RetVar, umerr
		}
	}

	for _, datain := range pdu1.VarBinds {
		if datain.RSnmpVar.Class == ASNber.ClassContextSpecific && len(datain.RSnmpVar.FullBytes) == 2 && datain.RSnmpVar.IsCompound == false {
			switch datain.RSnmpVar.Tag {
			case tagERR_noSuchObject:
				partialerr.Failedoids = append(partialerr.Failedoids, PowerSNMPv3_Errors_FailedOids_Error{datain.RSnmpOID, tagandclassERR_noSuchObject})
				continue
			case tagERR_noSuchInstance:
				partialerr.Failedoids = append(partialerr.Failedoids, PowerSNMPv3_Errors_FailedOids_Error{datain.RSnmpOID, tagandclassERR_noSuchInstance})
				continue
			case tagERR_EndOfMib:
				partialerr.Failedoids = append(partialerr.Failedoids, PowerSNMPv3_Errors_FailedOids_Error{datain.RSnmpOID, tagandclassERR_EndOfMib})
				continue
			default:
				umerr = fmt.Errorf("no such... tag is: %d", (0x80 | datain.RSnmpVar.Tag))
			}
			return RetVar, umerr
		}
		RetVar.V2PDU.VarBinds = append(RetVar.V2PDU.VarBinds, SNMP_Packet_V2_Decoded_VarBind{datain.RSnmpOID, SNMPVar{datain.RSnmpVar.Tag, datain.RSnmpVar.Class, datain.RSnmpVar.IsCompound, datain.RSnmpVar.Bytes}})
	}

	return RetVar, nil
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
func ParseTrapUsername(packet []byte) (version int, username string, v3secdata SNMPv3_SecSeq, err error) {
	var SNMP_UnknownVersionPacket_Data SNMP_UnknownVersionPacket
	var v3secd SNMPv3_SecSeq
	var umerr error
	_, umerr = ASNber.Unmarshal(packet, &SNMP_UnknownVersionPacket_Data)
	if umerr != nil {
		return 0, "", v3secd, umerr
	}

	if SNMP_UnknownVersionPacket_Data.Version != 1 && SNMP_UnknownVersionPacket_Data.Version != 3 {
		return 0, "", v3secd, fmt.Errorf("SNMP protocol version: %d not supported", SNMP_UnknownVersionPacket_Data.Version)
	}

	// Для SNMPv2 извлекаем Community String как "username"
	if SNMP_UnknownVersionPacket_Data.Version == 1 {
		var vs SNMP_Packet_V2
		_, umerr = ASNber.Unmarshal(packet, &vs)
		if umerr != nil {
			return 0, "", v3secd, umerr
		}
		return SNMP_UnknownVersionPacket_Data.Version, string(vs.V2CcommunityString), v3secd, nil
	}

	// Для SNMPv3 извлекаем Username и Secutiry Settings
	var SNMPrecivedPacket SNMPv3_Packet
	_, umerr = ASNber.Unmarshal(packet, &SNMPrecivedPacket)
	if umerr != nil {
		return 0, "", v3secd, umerr
	}

	var RecivedSecurity SNMPv3_SecSeq
	_, umerr = ASNber.Unmarshal(SNMPrecivedPacket.SecuritySettings, &RecivedSecurity)
	if umerr != nil {
		return 0, "", v3secd, umerr
	}

	v3secd = RecivedSecurity
	return SNMP_UnknownVersionPacket_Data.Version, string(RecivedSecurity.User), v3secd, nil
}

func receiverV3parser(SNMPparameters *SNMPv3Session, udppayload []byte, checkmsg_req_id bool, reqid int32) (SNMPretPacket SNMPv3_DecodePacket, err error) {
	var pdudecoded SNMP_Packet_V2_decoded_PDU
	var ReturnSNMPpacker SNMPv3_DecodePacket
	var SNMPrecivedPacket SNMPv3_Packet
	var pdu1 SNMP_Packet_V2_PDU
	var umerr error
	var partialerr SNMPne_Errors
	partialerr.Failedoids = make([]PowerSNMPv3_Errors_FailedOids_Error, 0)

	defer func() {
		if umerr == nil && len(partialerr.Failedoids) > 0 {
			err = partialerr
		}
	}()

	//Прасим payload в структуку
	_, umerr = ASNber.Unmarshal(udppayload, &SNMPrecivedPacket)
	if umerr != nil {
		//Ошибка парсинга
		return ReturnSNMPpacker, umerr
	}

	var RecivedGlobalParameters SNMPv3_GlobalData
	var RecivedSecurity SNMPv3_SecSeq
	var Recivedv3_PDU SNMPv3_PDU

	//Парсим RAW данные GlobalData из SNMPrecivedPacket
	_, umerr = ASNber.Unmarshal(SNMPrecivedPacket.GlobalData.FullBytes, &RecivedGlobalParameters)
	if umerr != nil {
		//Ошибка парсинга
		return ReturnSNMPpacker, umerr
	} else {
		//Если парсер испоользуется не для приема трапов, то нужно проверить MessageID
		if checkmsg_req_id {
			if RecivedGlobalParameters.MsgID != atomic.LoadInt32(&SNMPparameters.SNMPparams.MessageId) {
				umerr = SNMPwrongReqID_MsgId_Errors{PARCE_ERR_WRONGMSGID}
				return ReturnSNMPpacker, umerr //errors.New("message ID not valid")
			}
		} else {
			//Если это inform или trap то сохраним MsgID
			atomic.StoreInt32(&SNMPparameters.SNMPparams.MessageId, RecivedGlobalParameters.MsgID)
		}
	}
	//Парсим Security Settings
	_, umerr = ASNber.Unmarshal(SNMPrecivedPacket.SecuritySettings, &RecivedSecurity)
	if umerr != nil {
		return ReturnSNMPpacker, umerr
	}

	if !checkmsg_req_id {
		atomic.StoreInt32(&SNMPparameters.SNMPparams.RBoots, RecivedSecurity.Boots)
		atomic.StoreInt32(&SNMPparameters.SNMPparams.RTime, RecivedSecurity.Time)
	}

	if RecivedGlobalParameters.MsgFlag[0]&(1<<msgFlag_Authenticated_Bit) != 0 {
		if !checkmsg_req_id {
			//Берем EngineID из принятых данных а так же Boots и Time
			SNMPparameters.SNMPparams.EngineID = RecivedSecurity.AuthEng

			if SNMPparameters.SNMPparams.SecurityLevel > SECLEVEL_NOAUTH_NOPRIV {
				Lkey := makeLocalizedKey(SNMPparameters.SNMPparams.AuthKey, SNMPparameters.SNMPparams.EngineID, SNMPparameters.SNMPparams.AuthProtocol)
				SNMPparameters.SNMPparams.LocalizedKeyAuth = Lkey
				atomic.OrUint32(&SNMPparameters.SNMPparams.DataFlag, 1<<msgFlag_Authenticated_Bit)
			}
		}

		digver := false
		digver, umerr = verifyDigestRAW(udppayload, RecivedSecurity.AuthParams, SNMPparameters.SNMPparams.LocalizedKeyAuth, SNMPparameters.SNMPparams.AuthProtocol)
		if umerr != nil {
			return ReturnSNMPpacker, umerr
		}
		if !digver {
			umerr = errors.New("authentication Error")
			return ReturnSNMPpacker, umerr
		}
	}

	if RecivedGlobalParameters.MsgFlag[0]&(1<<msgFlag_Encrypted_Bit) != 0 {
		//Нужно расшифровать
		if SNMPparameters.Debuglevel > 199 {
			fmt.Println("Encrypted PDU")
		}
		if !checkmsg_req_id {
			//Для дешифровки трапа нужно создать localized keys
			if SNMPparameters.SNMPparams.SecurityLevel == SECLEVEL_AUTHPRIV {
				Lkey := makeLocalizedKey(SNMPparameters.SNMPparams.PrivKey, SNMPparameters.SNMPparams.EngineID, SNMPparameters.SNMPparams.AuthProtocol)
				switch SNMPparameters.SNMPparams.PrivProtocol {
				case PRIV_PROTOCOL_AES128:
					if len(Lkey) > 16 {
						Lkey = Lkey[:16]
					} // Только AES128!
				case PRIV_PROTOCOL_AES192, PRIV_PROTOCOL_AES256, PRIV_PROTOCOL_AES192A, PRIV_PROTOCOL_AES256A:
					Lkey = expandPrivKey(Lkey, SNMPparameters.SNMPparams.PrivProtocol, SNMPparameters.SNMPparams.AuthProtocol, SNMPparameters.SNMPparams.EngineID)
				}
				SNMPparameters.SNMPparams.LocalizedKeyPriv = Lkey
				SNMPparameters.SNMPparams.PrivParameter = rand.Uint64()
				SNMPparameters.SNMPparams.PrivParameterDes = rand.Uint32()
				atomic.OrUint32(&SNMPparameters.SNMPparams.DataFlag, 1<<msgFlag_Encrypted_Bit)
			}
		}
		//Выделяем буфер для расшифрованных данных
		var DecryptedPDU []byte
		SecParamByteArray := RecivedSecurity.PrivParams
		//Копируем принятые Boots, Time
		TBoots := make([]byte, 4)
		TTime := make([]byte, 4)
		binary.BigEndian.PutUint32(TBoots, uint32(RecivedSecurity.Boots))
		binary.BigEndian.PutUint32(TTime, uint32(RecivedSecurity.Time))

		switch SNMPparameters.SNMPparams.PrivProtocol {
		case PRIV_PROTOCOL_AES128, PRIV_PROTOCOL_AES192, PRIV_PROTOCOL_AES256, PRIV_PROTOCOL_AES192A, PRIV_PROTOCOL_AES256A:
			if len(SecParamByteArray) != 8 {
				umerr = errors.New("security Parameter length != 8 - must be 8 for AES")
				return ReturnSNMPpacker, umerr
			}
			//Считаем вектор инициализаци AES128 TBoots+TTime+SecParamByteArray (взято из RecivedSecurity.PrivParams)
			IV := make([]byte, 0)
			IV = append(IV, TBoots...)
			IV = append(IV, TTime...)
			IV = append(IV, SecParamByteArray...)
			DecryptedPDU, umerr = decryptAESCFB(SNMPrecivedPacket.PtData.Bytes, SNMPparameters.SNMPparams.LocalizedKeyPriv, IV)
			if umerr != nil {
				return ReturnSNMPpacker, umerr
			}
		case PRIV_PROTOCOL_DES:
			if len(SecParamByteArray) != 8 {
				umerr = errors.New("security Parameter - length != 8 - need for DES")
				return ReturnSNMPpacker, umerr
			}
			if len(SNMPparameters.SNMPparams.LocalizedKeyPriv) < 16 {
				umerr = errors.New("Localized key for DES, must be 16 or more bytes")
				return ReturnSNMPpacker, umerr
			}
			//Считаем вектор инициализаци DES, Pre IV это последние 8 байт из LocalizedKey
			//Соль берем целиком из RecivedSecurity.PrivParams
			//затем делаем побайтный XOR Pre IV с солью
			Pre_IV := make([]byte, 8)
			copy(Pre_IV, SNMPparameters.SNMPparams.LocalizedKeyPriv[8:])
			Salt := make([]byte, 0)
			IV := make([]byte, 8)
			Salt = append(Salt, SecParamByteArray...)
			for i := 0; i < 8; i++ {
				IV[i] = Pre_IV[i] ^ Salt[i]
			}

			DecryptedPDU, umerr = decryptDES(SNMPrecivedPacket.PtData.Bytes, SNMPparameters.SNMPparams.LocalizedKeyPriv[:8], IV)
			if umerr != nil {
				return ReturnSNMPpacker, umerr
			}
		}

		_, umerr = ASNber.Unmarshal(DecryptedPDU, &Recivedv3_PDU)
	} else {
		//Данные не зашифрованы
		_, umerr = ASNber.Unmarshal(SNMPrecivedPacket.PtData.FullBytes, &Recivedv3_PDU)
	}

	if !checkmsg_req_id {
		SNMPparameters.SNMPparams.ContextEngineId = Recivedv3_PDU.ContextEngineId
		SNMPparameters.SNMPparams.ContextName = string(Recivedv3_PDU.ContextName)
	}

	if umerr != nil {
		//ошибка парсинга расшифрованных данных
		return ReturnSNMPpacker, umerr
	}

	//Проверяем не Report ли это
	if Recivedv3_PDU.V2VarBind.Class == 0x02 {
		switch Recivedv3_PDU.V2VarBind.Tag {
		case 0x08:
			if SNMPparameters.Debuglevel > 199 {
				fmt.Println("Received Report MSG!")
			}
			ReturnSNMPpacker.MessageType = REPORT_MESSAGE

		case 0x07:
			if SNMPparameters.Debuglevel > 199 {
				fmt.Println("Received Trap MSG!")
			}
			ReturnSNMPpacker.MessageType = TRAP_MESSAGE

		case 0x6:
			if SNMPparameters.Debuglevel > 199 {
				fmt.Println("Received Inform MSG!")
			}
			ReturnSNMPpacker.MessageType = INFORM_MESSAGE
		}

	}

	if len(Recivedv3_PDU.V2VarBind.FullBytes) == 0 {
		//длина данных нулевая
		umerr = errors.New("Received PDU Not Found")
		return ReturnSNMPpacker, umerr
	}

	//Это хак для того чтоб работал Unmarshal ASN.1 правильно
	//дело в том что нам приходит PDU т первый байт в нем - тип и он будет Context-Specific
	//Его не поймет Unmarshal, но это просто Sequence (0x30) вот тут мы его и меняем на Sequence
	//А чтоб избежать ошибок проверим что длина не равна нулю (выше проверяется длина FullBytes и если 0 то выход
	Recivedv3_PDU.V2VarBind.FullBytes[0] = 0x30
	_, umerr = ASNber.Unmarshal(Recivedv3_PDU.V2VarBind.FullBytes, &pdu1)
	if umerr != nil {
		return ReturnSNMPpacker, umerr
	} else {
		if checkmsg_req_id && pdu1.RequestID != reqid {
			if ReturnSNMPpacker.MessageType != REPORT_MESSAGE {
				umerr = SNMPwrongReqID_MsgId_Errors{PARCE_ERR_WRONGREQID}
				return ReturnSNMPpacker, umerr //return ReturnSNMPpacker, errors.New("invalid request id")
			}
		}
		if pdu1.ErrorStatusRaw != sNMP_ErrNoError {
			var failedOID []int
			//Скопируем проблемный OID
			if pdu1.ErrorIndexRaw > 0 {
				if int(pdu1.ErrorIndexRaw-1) < len(pdu1.VarBinds) {
					failedOID = pdu1.VarBinds[pdu1.ErrorIndexRaw-1].RSnmpOID
				}
			}
			switch pdu1.ErrorStatusRaw {
			case sNMP_ErrResponseTooLarge:
				partialerr.Failedoids = append(partialerr.Failedoids, PowerSNMPv3_Errors_FailedOids_Error{failedOID, int(pdu1.ErrorStatusRaw)})
			case sNMP_ErrGeneralError, sNMP_ErrNoAccess, sNMP_ErrResourcesUnavailable:
				partialerr.Failedoids = append(partialerr.Failedoids, PowerSNMPv3_Errors_FailedOids_Error{failedOID, int(pdu1.ErrorStatusRaw)})
			default:
				umerr = SNMPfe_Errors{ErrorStatusRaw: pdu1.ErrorStatusRaw, ErrorIndexRaw: pdu1.ErrorIndexRaw, FailedOID: failedOID}
				return ReturnSNMPpacker, umerr
			}
		}
		//OID с ошибкой в VarBind в результат не добавляем, а добавляем в ошибочные
		for _, oidv := range pdu1.VarBinds {
			if oidv.RSnmpVar.Class == ASNber.ClassContextSpecific && len(oidv.RSnmpVar.FullBytes) == 2 && oidv.RSnmpVar.IsCompound == false {
				switch oidv.RSnmpVar.Tag {
				case tagERR_noSuchObject:
					partialerr.Failedoids = append(partialerr.Failedoids, PowerSNMPv3_Errors_FailedOids_Error{oidv.RSnmpOID, tagandclassERR_noSuchObject})
					continue
				case tagERR_noSuchInstance:
					partialerr.Failedoids = append(partialerr.Failedoids, PowerSNMPv3_Errors_FailedOids_Error{oidv.RSnmpOID, tagandclassERR_noSuchInstance})
					continue
				case tagERR_EndOfMib:
					partialerr.Failedoids = append(partialerr.Failedoids, PowerSNMPv3_Errors_FailedOids_Error{oidv.RSnmpOID, tagandclassERR_EndOfMib})
					continue
				default:
					umerr = fmt.Errorf("no such... tag is: %d", oidv.RSnmpVar.Tag)
				}
				return ReturnSNMPpacker, umerr
			} else {

				pdudecoded.VarBinds = append(pdudecoded.VarBinds, SNMP_Packet_V2_Decoded_VarBind{oidv.RSnmpOID, SNMPVar{oidv.RSnmpVar.Tag, oidv.RSnmpVar.Class, oidv.RSnmpVar.IsCompound, oidv.RSnmpVar.Bytes}})

			}
		}
	}
	ReturnSNMPpacker.GlobalData = RecivedGlobalParameters
	ReturnSNMPpacker.SecuritySettings = RecivedSecurity
	ReturnSNMPpacker.V3PDU.ContextName = Recivedv3_PDU.ContextName
	ReturnSNMPpacker.V3PDU.ContextEngineId = Recivedv3_PDU.ContextEngineId
	ReturnSNMPpacker.V3PDU.V2VarBind.RequestID = pdu1.RequestID
	ReturnSNMPpacker.V3PDU.V2VarBind.ErrorIndexRaw = pdu1.ErrorIndexRaw
	ReturnSNMPpacker.V3PDU.V2VarBind.ErrorStatusRaw = pdu1.ErrorStatusRaw
	ReturnSNMPpacker.V3PDU.V2VarBind.VarBinds = pdudecoded.VarBinds
	return ReturnSNMPpacker, nil
}
