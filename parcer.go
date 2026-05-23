// Package PowerSNMPv3 - SNMP library for Go
// Автор: Волков Олег
// Author: Volkov Oleg
// License: MIT
// Лицензия: MIT
// Commercial support and custom development available.
package PowerSNMPv3

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"sync/atomic"

	ASNber "github.com/OlegPowerC/asn1modsnmp"
)

func (SNMPparameters *SNMPv3Session) parseSNMPv3Packet(cpboottimeid bool, packet []byte) (decryptedData SNMPv3_DecodePacket, err error) {
	var RetPacket SNMPv3_DecodePacket
	var SNMPDataErr error
	RetPacket, SNMPDataErr = SNMPparameters.receiverV3parser(packet, false, cpboottimeid, 0)
	return RetPacket, SNMPDataErr
}

func (SNMPparameters *SNMPv3Session) parseSNMPv2Packet(packet []byte) (decryptedData SNMPv2_DecodePacket, err error) {
	var RetPacket SNMPv2_DecodePacket
	var SNMPDataErr error
	RetPacket, SNMPDataErr = SNMPparameters.receiverV2parser(packet, false, 0)
	return RetPacket, SNMPDataErr
}

func (SNMPparameters *SNMPv3Session) receiverV2parser(packet []byte, checkmsg_req_id bool, reqid int32) (decodedDatav2 SNMPv2_DecodePacket, errorv2 error) {
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

	params := fmt.Sprintf("tag:%d", vs.V2VarBind.Tag)
	_, umerr = ASNber.UnmarshalWithParams(vs.V2VarBind.FullBytes, &pdu1, params)
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
	if len(partialerr.Failedoids) == len(pdu1.VarBinds) {
		partialerr.AllOIDsFail = true
	}

	return RetVar, nil
}

func (SNMPparameters *SNMPv3Session) receiverV3parser(udppayload []byte, checkmsg_req_id bool, cpboottimeeid bool, reqid int32) (SNMPretPacket SNMPv3_DecodePacket, err error) {
	var ReturnSNMPpacker SNMPv3_DecodePacket
	var SNMPrecivedPacket SNMPv3_DhPacket
	SNMPrecivedPacket, pheadererr := SNMPparameters.receiverV3Hparser(udppayload, checkmsg_req_id)
	if pheadererr != nil {
		return ReturnSNMPpacker, pheadererr
	}

	return SNMPparameters.receiverV3Bparser(udppayload, &SNMPrecivedPacket, checkmsg_req_id, cpboottimeeid, reqid)
}

func (SNMPparameters *SNMPv3Session) receiverV3Hparser(udppayload []byte, checkmsg_req_id bool) (SNMPretPacket SNMPv3_DhPacket, err error) {
	var SNMPrecivedPacket SNMPv3_Packet
	var SNMPDhRetPacket SNMPv3_DhPacket
	var umerr error

	//Прасим payload в структуку
	_, umerr = ASNber.Unmarshal(udppayload, &SNMPrecivedPacket)
	if umerr != nil {
		//Ошибка парсинга
		return SNMPDhRetPacket, umerr
	}

	//Парсим RAW данные GlobalData из SNMPrecivedPacket
	_, umerr = ASNber.Unmarshal(SNMPrecivedPacket.GlobalData.FullBytes, &SNMPDhRetPacket.GlobalData)
	if umerr != nil {
		//Ошибка парсинга
		return SNMPDhRetPacket, umerr
	} else {
		//Если парсер испоользуется не для приема трапов, то нужно проверить MessageID
		if checkmsg_req_id {
			if SNMPDhRetPacket.GlobalData.MsgID != atomic.LoadInt32(&SNMPparameters.SNMPparams.MessageId) {
				umerr = SNMPwrongReqID_MsgId_Errors{PARCE_ERR_WRONGMSGID}
				return SNMPDhRetPacket, umerr //errors.New("message ID not valid")
			}
		} else {
			//Если это inform или trap то сохраним MsgID
			atomic.StoreInt32(&SNMPparameters.SNMPparams.MessageId, SNMPDhRetPacket.GlobalData.MsgID)
		}
	}
	//Парсим Security Settings
	_, umerr = ASNber.Unmarshal(SNMPrecivedPacket.SecuritySettings, &SNMPDhRetPacket.SecuritySettings)
	if umerr != nil {
		return SNMPDhRetPacket, umerr
	}

	SNMPDhRetPacket.PtData = SNMPrecivedPacket.PtData
	SNMPDhRetPacket.Version = SNMPrecivedPacket.Version
	return SNMPDhRetPacket, nil
}

// Передать указатель на слайс с сырыми данными придется для аутентификации
func (SNMPparameters *SNMPv3Session) receiverV3Bparser(udppayload []byte, SNMPv3Ppacker *SNMPv3_DhPacket, checkmsg_req_id bool, cpboottimeeid bool, reqid int32) (SNMPretPacket SNMPv3_DecodePacket, err error) {
	var ReturnSNMPpacker SNMPv3_DecodePacket
	var Recivedv3_PDU SNMPv3_PDU
	var pdu1 SNMP_Packet_V2_PDU
	var partialerr SNMPne_Errors
	var pdudecoded SNMP_Packet_V2_decoded_PDU
	var umerr error

	defer func() {
		if umerr == nil && len(partialerr.Failedoids) > 0 {
			err = partialerr
		}
	}()

	if len(SNMPv3Ppacker.GlobalData.MsgFlag) > 0 {
		if cpboottimeeid {
			//Берем EngineID из принятых данных, а так же Boots и Time
			SNMPparameters.SNMPparams.EngineID = SNMPv3Ppacker.SecuritySettings.AuthEng
		}

		//Если сообщение аутентифицировано
		if SNMPv3Ppacker.GlobalData.MsgFlag[0]&(1<<msgFlag_Authenticated_Bit) != 0 {
			if !checkmsg_req_id {
				//если это прием TRAP/INFORM то локализуем ключ
				if SNMPparameters.SNMPparams.SecurityLevel > SECLEVEL_NOAUTH_NOPRIV {
					Lkey := makeLocalizedKey(SNMPparameters.SNMPparams.AuthKey, SNMPparameters.SNMPparams.EngineID, SNMPparameters.SNMPparams.AuthProtocol)
					SNMPparameters.SNMPparams.LocalizedKeyAuth = Lkey
					atomic.OrUint32(&SNMPparameters.SNMPparams.DataFlag, 1<<msgFlag_Authenticated_Bit)
				}
			}

			digver := false
			digver, umerr = verifyDigestRAW(udppayload, SNMPv3Ppacker.SecuritySettings.AuthParams, SNMPparameters.SNMPparams.LocalizedKeyAuth, SNMPparameters.SNMPparams.AuthProtocol)
			if umerr != nil {
				return ReturnSNMPpacker, umerr
			}
			if !digver {
				umerr = errors.New("authentication Error")
				return ReturnSNMPpacker, umerr
			}
		}
	}

	if len(SNMPv3Ppacker.GlobalData.MsgFlag) > 0 && (SNMPv3Ppacker.GlobalData.MsgFlag[0]&(1<<msgFlag_Encrypted_Bit) != 0) {
		//Нужно расшифровать потому что задан режим Priv
		//Флаг в принятой датаграмме, поэтому если в параметрах пользователя задан режим AuthPriv
		//А принятые данные не зашифрованы, они все равно корректно разберутся
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
		SecParamByteArray := SNMPv3Ppacker.SecuritySettings.PrivParams
		//Копируем принятые Boots, Time
		TBoots := make([]byte, 4)
		TTime := make([]byte, 4)
		binary.BigEndian.PutUint32(TBoots, uint32(SNMPv3Ppacker.SecuritySettings.Boots))
		binary.BigEndian.PutUint32(TTime, uint32(SNMPv3Ppacker.SecuritySettings.Time))

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
			DecryptedPDU, umerr = decryptAESCFB(SNMPv3Ppacker.PtData.Bytes, SNMPparameters.SNMPparams.LocalizedKeyPriv, IV)
			if umerr != nil {
				return ReturnSNMPpacker, umerr
			}
		case PRIV_PROTOCOL_DES:
			if len(SecParamByteArray) != 8 {
				umerr = errors.New("security Parameter - length != 8 - need for DES")
				return ReturnSNMPpacker, umerr
			}
			if len(SNMPparameters.SNMPparams.LocalizedKeyPriv) < 16 {
				umerr = errors.New("localized key for DES, must be 16 or more bytes")
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

			DecryptedPDU, umerr = decryptDES(SNMPv3Ppacker.PtData.Bytes, SNMPparameters.SNMPparams.LocalizedKeyPriv[:8], IV)
			if umerr != nil {
				return ReturnSNMPpacker, umerr
			}
		}

		_, umerr = ASNber.Unmarshal(DecryptedPDU, &Recivedv3_PDU)
	} else {
		//Данные не зашифрованы
		_, umerr = ASNber.Unmarshal(SNMPv3Ppacker.PtData.FullBytes, &Recivedv3_PDU)
	}

	if !checkmsg_req_id && cpboottimeeid {
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

	if len(Recivedv3_PDU.V2VarBind.FullBytes) < 2 {
		//длина данных нулевая
		umerr = errors.New("received PDU too short")
		return ReturnSNMPpacker, umerr
	}

	params := fmt.Sprintf("tag:%d", Recivedv3_PDU.V2VarBind.Tag)
	_, umerr = ASNber.UnmarshalWithParams(Recivedv3_PDU.V2VarBind.FullBytes, &pdu1, params)
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
		if len(partialerr.Failedoids) == len(pdu1.VarBinds) {
			partialerr.AllOIDsFail = true
		}
	}
	ReturnSNMPpacker.GlobalData = SNMPv3Ppacker.GlobalData
	ReturnSNMPpacker.SecuritySettings = SNMPv3Ppacker.SecuritySettings
	ReturnSNMPpacker.V3PDU.ContextName = Recivedv3_PDU.ContextName
	ReturnSNMPpacker.V3PDU.ContextEngineId = Recivedv3_PDU.ContextEngineId
	ReturnSNMPpacker.V3PDU.V2VarBind.RequestID = pdu1.RequestID
	ReturnSNMPpacker.V3PDU.V2VarBind.ErrorIndexRaw = pdu1.ErrorIndexRaw
	ReturnSNMPpacker.V3PDU.V2VarBind.ErrorStatusRaw = pdu1.ErrorStatusRaw
	ReturnSNMPpacker.V3PDU.V2VarBind.VarBinds = pdudecoded.VarBinds
	return ReturnSNMPpacker, nil
}
