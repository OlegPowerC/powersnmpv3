// PowerSNMPv3 - SNMP library for Go
// Автор: Волков Олег, ООО "Пауэр Си"
// Author: Volkov Oleg, PowerC LLC
// License: MIT (commercial version with support available)
// Лицензия: MIT (доступна коммерческая версия с поддержкой)
package PowerSNMPv3

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"slices"
	"sync/atomic"
	"time"

	ASNber "github.com/OlegPowerC/asn1modsnmp"
)

// SNMPv3_Discovery initializes SNMPv3 session with automatic EngineID discovery.
//
// Sends discovery GET request to `1.3.6.1.2.1.1.1.0` expecting "unknownEngineID" error.
// Extracts EngineID, Boots, Time from REPORT response and localizes Auth/Priv keys.
//
// Example:
//
//	device := PowerSNMP.NetworkDevice{
//	    IPaddress: "192.168.5.252",
//	    SNMPparameters: PowerSNMP.SNMPparameters{Username: "SNMPv3User", AuthProtocol: "SHA", ...},
//	}
//	session, err := PowerSNMP.SNMPv3_Discovery(device)
//
// Automatically handles:
//   - EngineID discovery from REPORT (1.3.6.1.6.3.15.1.1.4.0)
//   - Key localization (makeLocalizedKey/expandPrivKey)
//   - AES128/192/256C protocols
//   - Parameter validation (defaults: Retry=3, Timeout=300ms, MaxRep=25)
func SNMPv3_Discovery(Ndev NetworkDevice) (SNMPsession *SNMPv3Session, err error) {
	var ReturnError error
	Session := &SNMPv3Session{}
	Session.Debuglevel = Ndev.DebugLevel
	Session.IPaddress = Ndev.IPaddress
	Session.Port = Ndev.Port
	Session.SNMPparams.ContextName = Ndev.SNMPparameters.ContextName
	Session.SNMPparams.SNMPversion = Ndev.SNMPparameters.SNMPversion
	if Ndev.SNMPparameters.RetryCount <= 0 || Ndev.SNMPparameters.RetryCount > SNMP_MAXIMUM_RETRY {
		Session.SNMPparams.RetryCount = SNMP_DEFAULTRETRY
	} else {
		Session.SNMPparams.RetryCount = Ndev.SNMPparameters.RetryCount
	}
	if Ndev.SNMPparameters.TimeoutBtwRepeat <= 0 || Ndev.SNMPparameters.TimeoutBtwRepeat > SNMP_MAXTIMEOUT_MS {
		Session.SNMPparams.TimeoutBtwRepeat = SNMP_DEFAULTTIMEOUT_MS
	} else {
		Session.SNMPparams.TimeoutBtwRepeat = Ndev.SNMPparameters.TimeoutBtwRepeat
	}

	if Ndev.SNMPparameters.MaxRepetitions <= 0 || Ndev.SNMPparameters.MaxRepetitions > SNMP_MAXREPETITION {
		Session.SNMPparams.MaxRepetitions = int32(SNMP_DEFAULTREPETITION)
	} else {
		Session.SNMPparams.MaxRepetitions = int32(Ndev.SNMPparameters.MaxRepetitions)
	}

	Session.SNMPparams.AuthKey = Ndev.SNMPparameters.AuthKey
	Session.SNMPparams.PrivKey = Ndev.SNMPparameters.PrivKey
	Session.SNMPparams.MessageIDv2 = rand.Int31()
	Session.SNMPparams.MessageId = rand.Int31()
	atomic.OrUint32(&Session.SNMPparams.DataFlag, 1<<msgFlag_Reportable_Bit)

	Session.SNMPparams.Username = Ndev.SNMPparameters.Username

	//Таймаут на случай долгого разрешения имени
	tmms := time.Duration(10) * time.Second
	Ds := net.Dialer{Timeout: tmms}
	DialAddress := net.JoinHostPort(Session.IPaddress, fmt.Sprintf("%d", Session.Port))
	var conn net.Conn
	conn, ReturnError = Ds.Dial("udp", DialAddress)
	if ReturnError != nil {
		return nil, ReturnError
	}
	defer func() {
		cerrc := conn.Close()
		Session.conn = nil
		if cerrc != nil && ReturnError == nil {
			err = cerrc
		}
	}()

	Session.conn = conn
	seclevel, aproto, pproto, ReturnError := setAuthPrivParamsStToInt(Ndev.SNMPparameters.AuthProtocol, Ndev.SNMPparameters.AuthKey, Ndev.SNMPparameters.PrivProtocol, Ndev.SNMPparameters.PrivKey)
	if ReturnError != nil {
		return Session, ReturnError
	}

	Session.SNMPparams.SecurityLevel = seclevel
	Session.SNMPparams.AuthProtocol = aproto
	Session.SNMPparams.AuthKey = Ndev.SNMPparameters.AuthKey
	Session.SNMPparams.PrivProtocol = pproto
	Session.SNMPparams.PrivKey = Ndev.SNMPparameters.PrivKey

	//oid := make([]int, 0)
	Oid := []int{1, 3, 6, 1, 2, 1, 1, 1, 0}

	OidVarConverted := []SNMP_Packet_V2_VarBind{{Oid, ASNber.NullRawValue}}

	rts, complexerr := Session.sendSnmpv3GetRequestPrototype(OidVarConverted, SNMPv2_REQUEST_GET, 0, 0)
	if complexerr != nil {
		ReturnError = complexerr
		return Session, ReturnError

	}

	OID_UnknownEngineID := ASNber.ObjectIdentifier([]int{1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0})
	// Поскольку нам не известен еще Engine ID, как и Boots и Time то мы ожидаем ошибку - Unknown Engine ID
	// OID 1.3.6.1.6.3.15.1.1.4.0
	// и из этого же пакеты мы его и извлекаем как и Boots и Time (но они могут быть равны нулю)
	// если так то их мы переинициализируем после первого Get и получения ошибки NoInTime 1.3.6.1.6.3.15.1.1.2.0
	if len(rts.V3PDU.V2VarBind.VarBinds) == 0 {
		ReturnError = errors.New("discovery failed: empty VarBinds in response")
		return Session, ReturnError
	}
	if rts.V3PDU.V2VarBind.VarBinds[0].RSnmpOID.Equal(OID_UnknownEngineID) {
		if Session.Debuglevel > 199 {
			fmt.Println("Unknown Engine ID!")
			fmt.Println("Discovered Engine ID:", hex.EncodeToString(rts.SecuritySettings.AuthEng), "Discovered boots:", rts.SecuritySettings.Boots, "Discovered times:", rts.SecuritySettings.Time)
		}

		Session.SNMPparams.EngineID = rts.SecuritySettings.AuthEng
		Session.SNMPparams.ContextEngineId = rts.SecuritySettings.AuthEng
		if len(Session.SNMPparams.EngineID) > 0 {
			Session.SNMPparams.DiscoveredEngineId.Store(true)
			Session.SNMPparams.Username = Ndev.SNMPparameters.Username

			if Session.SNMPparams.SecurityLevel > SECLEVEL_NOAUTH_NOPRIV {
				Lkey := makeLocalizedKey(Session.SNMPparams.AuthKey, Session.SNMPparams.EngineID, Session.SNMPparams.AuthProtocol)
				Session.SNMPparams.LocalizedKeyAuth = Lkey
				atomic.OrUint32(&Session.SNMPparams.DataFlag, 1<<msgFlag_Authenticated_Bit)
			}
			if Session.SNMPparams.SecurityLevel == SECLEVEL_AUTHPRIV {
				Lkey := makeLocalizedKey(Session.SNMPparams.PrivKey, Session.SNMPparams.EngineID, Session.SNMPparams.AuthProtocol)

				switch Session.SNMPparams.PrivProtocol {
				case PRIV_PROTOCOL_AES128:
					if len(Lkey) > 16 {
						Lkey = Lkey[:16]
					} // Только AES128!
				case PRIV_PROTOCOL_AES192, PRIV_PROTOCOL_AES256, PRIV_PROTOCOL_AES192A, PRIV_PROTOCOL_AES256A:
					Lkey = expandPrivKey(Lkey, Session.SNMPparams.PrivProtocol, Session.SNMPparams.AuthProtocol, Session.SNMPparams.EngineID)
				}

				Session.SNMPparams.LocalizedKeyPriv = Lkey
				Session.SNMPparams.PrivParameter = rand.Uint64()
				Session.SNMPparams.PrivParameterDes = rand.Uint32()
				atomic.OrUint32(&Session.SNMPparams.DataFlag, 1<<msgFlag_Encrypted_Bit)
			}

		}
		if rts.SecuritySettings.Boots > 0 || rts.SecuritySettings.Time > 0 {
			Session.SNMPparams.DiscoveredTimeBoots.Store(true)
			atomic.StoreInt32(&Session.SNMPparams.RBoots, rts.SecuritySettings.Boots)
			atomic.StoreInt32(&Session.SNMPparams.RTime, rts.SecuritySettings.Time)
		}

	}
	return Session, nil
}

// makeMessage constructs raw SNMPv3 packet for transmission (internal).
//
// Builds complete SNMPv3 USM packet with atomic MessageID, Boots/Time, Auth/Priv flags.
// Supports all combinations: SHA*/MD5 + AES*/DES encryption.
//
// Handles:
//   - Dynamic AuthParams length (SHA512=48 bytes)
//   - AES CFB IV (Boots+Time+PrivParam)
//   - DES Salt XOR PreIV
//   - Post-encrypt HMAC digest update
//
// Internal use only.
func (SNMPparameters *SNMPv3Session) makeMessage(oidValue []SNMP_Packet_V2_VarBind, ReqType int, RequestID int32, nonRepeaters int32, maxRepetitions int32) (msg []byte, err error) {
	var retbytes []byte
	var SNMP_Packet SNMPv3_Packet
	var SNMP_GlobalData SNMPv3_GlobalData
	var SNMP_SecuritySequence SNMPv3_SecSeq
	var SNMPv3_PDUdata SNMPv3_PDU
	var errread error
	var currentPrivParam uint64
	var currentPrivParamDes uint32

	if SNMPparameters.SNMPparams.PrivProtocol == PRIV_PROTOCOL_DES {
		if len(SNMPparameters.SNMPparams.LocalizedKeyPriv) < 16 {
			return retbytes, errors.New("DES необходим локализованный ключ хотябы 16 байт")
		}
	}

	SNMP_Packet.Version = 3
	TBoots := make([]byte, 4)
	TTime := make([]byte, 4)

	boots := atomic.LoadInt32(&SNMPparameters.SNMPparams.RBoots)
	timeVal := atomic.LoadInt32(&SNMPparameters.SNMPparams.RTime)
	binary.BigEndian.PutUint32(TBoots, uint32(boots))
	binary.BigEndian.PutUint32(TTime, uint32(timeVal))

	SNMP_GlobalData.MsgFlag = make([]byte, 1)
	SNMP_GlobalData.MsgFlag[0] = byte(atomic.LoadUint32(&SNMPparameters.SNMPparams.DataFlag))
	SNMP_GlobalData.MsgSecurityModel = msgSecurityModel_USM
	SNMP_GlobalData.MsgID = atomic.LoadInt32(&SNMPparameters.SNMPparams.MessageId)
	SNMP_GlobalData.MsgMaxSize = 1360
	GlobalData, GlobalDataError := ASNber.Marshal(SNMP_GlobalData)
	if GlobalDataError != nil {
		return retbytes, GlobalDataError
	} else {
		SNMP_Packet.GlobalData.FullBytes = GlobalData
	}

	SNMP_SecuritySequence.Time = atomic.LoadInt32(&SNMPparameters.SNMPparams.RTime)
	SNMP_SecuritySequence.Boots = atomic.LoadInt32(&SNMPparameters.SNMPparams.RBoots)
	SNMP_SecuritySequence.AuthEng = SNMPparameters.SNMPparams.EngineID
	//Проверяем флаг атомарно
	if atomic.LoadUint32(&SNMPparameters.SNMPparams.DataFlag)&(1<<msgFlag_Authenticated_Bit) != 0 {
		var authParamLen int
		switch SNMPparameters.SNMPparams.AuthProtocol {
		case AUTH_PROTOCOL_MD5, AUTH_PROTOCOL_SHA:
			authParamLen = 12
		case AUTH_PROTOCOL_SHA224:
			authParamLen = 16
		case AUTH_PROTOCOL_SHA256:
			authParamLen = 24
		case AUTH_PROTOCOL_SHA384:
			authParamLen = 32
		case AUTH_PROTOCOL_SHA512:
			authParamLen = 48
		default:
			authParamLen = 12
		}
		SNMP_SecuritySequence.AuthParams = make([]byte, authParamLen)
	}
	if atomic.LoadUint32(&SNMPparameters.SNMPparams.DataFlag)&(1<<msgFlag_Encrypted_Bit) != 0 {
		switch SNMPparameters.SNMPparams.PrivProtocol {
		case PRIV_PROTOCOL_AES128, PRIV_PROTOCOL_AES192, PRIV_PROTOCOL_AES256, PRIV_PROTOCOL_AES192A, PRIV_PROTOCOL_AES256A:
			//В PrivParameters в пакете SNMP записываем 64 битное значение SNMPsession.SNMPparams.PrivParameter
			currentPrivParam = atomic.AddUint64(&SNMPparameters.SNMPparams.PrivParameter, 1)
			SecParamByteArray := make([]byte, 8)
			binary.BigEndian.PutUint64(SecParamByteArray, currentPrivParam)
			SNMP_SecuritySequence.PrivParams = SecParamByteArray
		case PRIV_PROTOCOL_DES:
			//Создаем соль и вектор инициализации IV для шифрования данных по протоколу DES
			//PrivParameterDes имеет случайное 32 битное значение
			//В PrivParameters в пакете SNMP записываем 64 битное значение Boots + SNMPsession.SNMPparams.PrivParameterDes
			currentPrivParamDes = atomic.AddUint32(&SNMPparameters.SNMPparams.PrivParameterDes, 1)
			SecParamByteArray := make([]byte, 4)
			binary.BigEndian.PutUint32(SecParamByteArray, currentPrivParamDes)
			Salt := make([]byte, 0)
			Salt = append(Salt, TBoots...)
			Salt = append(Salt, SecParamByteArray...)
			SNMP_SecuritySequence.PrivParams = Salt
		}
	}

	SNMP_SecuritySequence.User = []byte(SNMPparameters.SNMPparams.Username)
	SecuritylData, SecuritylDataError := ASNber.Marshal(SNMP_SecuritySequence)
	if SecuritylDataError != nil {
		return retbytes, SecuritylDataError
	} else {
		SNMP_Packet.SecuritySettings = SecuritylData
	}

	var V2PDU SNMP_Packet_V2_PDU
	V2PDU.VarBinds = oidValue

	V2PDU.RequestID = RequestID
	V2PDU.ErrorStatusRaw = 0
	V2PDU.ErrorIndexRaw = 0
	if ReqType == SNMPv2_REQUEST_GETBULK {
		V2PDU.ErrorStatusRaw = nonRepeaters
		V2PDU.ErrorIndexRaw = maxRepetitions
	}
	V2PDU_ASNEncode, V2PDUEncodeErr := ASNber.Marshal(V2PDU)
	if V2PDUEncodeErr != nil {
		return retbytes, V2PDUEncodeErr
	}

	var pmval ASNber.RawValue
	pmval.Class = ASNber.ClassContextSpecific
	pmval.IsCompound = true
	pmval.Tag = ReqType
	//Извлекаем данные (без TAG LEN)
	PureData, ExErr := ASNber.ExtractDataWOTagAndLen(V2PDU_ASNEncode)
	if ExErr != nil {
		return nil, ExErr
	}
	pmval.Bytes = PureData //V2PDU_ASNEncode[2:]

	SNMPv3_PDUdata.V2VarBind = pmval
	SNMPv3_PDUdata.ContextName = []byte(SNMPparameters.SNMPparams.ContextName)
	SNMPv3_PDUdata.ContextEngineId = SNMPparameters.SNMPparams.ContextEngineId
	V3PduMarshal, V3duMarshalErr := ASNber.Marshal(SNMPv3_PDUdata)
	if V3duMarshalErr != nil {
		return retbytes, V3duMarshalErr
	}
	if atomic.LoadUint32(&SNMPparameters.SNMPparams.DataFlag)&(1<<msgFlag_Encrypted_Bit) != 0 {
		var EncryptedPdu []byte
		var Encerr error
		switch SNMPparameters.SNMPparams.PrivProtocol {
		case PRIV_PROTOCOL_AES128, PRIV_PROTOCOL_AES192, PRIV_PROTOCOL_AES256, PRIV_PROTOCOL_AES192A, PRIV_PROTOCOL_AES256A:
			SecParamByteArray := make([]byte, 8)
			binary.BigEndian.PutUint64(SecParamByteArray, currentPrivParam)
			IV := make([]byte, 0)
			IV = append(IV, TBoots...)
			IV = append(IV, TTime...)
			IV = append(IV, SecParamByteArray...)

			EncryptedPdu, Encerr = encryptAESCFB(V3PduMarshal, SNMPparameters.SNMPparams.LocalizedKeyPriv, IV)
			if Encerr != nil {
				return retbytes, errors.New("encryption error")
			}
			break
		case PRIV_PROTOCOL_DES:
			SecParamByteArray := make([]byte, 4)
			binary.BigEndian.PutUint32(SecParamByteArray, currentPrivParamDes)
			Salt := make([]byte, 0)
			Salt = append(Salt, TBoots...)
			Salt = append(Salt, SecParamByteArray...)

			Pre_IV := make([]byte, 8)
			copy(Pre_IV, SNMPparameters.SNMPparams.LocalizedKeyPriv[8:])
			IV := make([]byte, 8)
			for i := 0; i < 8; i++ {
				IV[i] = Pre_IV[i] ^ Salt[i]
			}

			EncryptedPdu, Encerr = encryptDES(V3PduMarshal, SNMPparameters.SNMPparams.LocalizedKeyPriv[:8], IV)
			if Encerr != nil {
				return retbytes, errors.New("encryption error")
			}
			break
		case PRIV_PROTOCOL_NONE:
			return retbytes, errors.New("msgFlag_Encrypted_Bit установлен но priv протокол NONE")
		default:
			return retbytes, errors.New("msgFlag_Encrypted_Bit установлен но priv протокол неизвестен")
		}

		SNMP_Packet.PtData.Bytes = EncryptedPdu
		SNMP_Packet.PtData.Tag = 0x04
	} else {
		SNMP_Packet.PtData.FullBytes = V3PduMarshal
	}

	SNMPv3Packet, SNMPv3PacketError := ASNber.Marshal(SNMP_Packet)
	if SNMPv3PacketError != nil {
		return retbytes, SNMPv3PacketError
	}

	if atomic.LoadUint32(&SNMPparameters.SNMPparams.DataFlag)&(1<<msgFlag_Authenticated_Bit) != 0 {
		Digest := makeDigest(SNMPv3Packet, SNMPparameters.SNMPparams.LocalizedKeyAuth, SNMPparameters.SNMPparams.AuthProtocol)
		SNMP_SecuritySequence.AuthParams = Digest

		SecuritylDataAfterDigist, SecuritylDataAfterDigistError := ASNber.Marshal(SNMP_SecuritySequence)
		if SecuritylDataAfterDigistError != nil {
			return retbytes, SecuritylDataAfterDigistError
		} else {
			SNMP_Packet.SecuritySettings = SecuritylDataAfterDigist
		}
		SNMPv3Packet, SNMPv3PacketError = ASNber.Marshal(SNMP_Packet)
		if SNMPv3PacketError != nil {
			return retbytes, SNMPv3PacketError
		}
	}
	return SNMPv3Packet, errread
}

// sendSnmpv3GetRequestPrototype sends SNMPv3 GET/GETNEXT/GETBULK request with retries.
//
// Internal: mutex-protected, atomic RequestID, exponential backoff timeout.
// Validates response RequestID/MessageID match.
//
// Handles:
//   - RetryCount (default 3) with progressive timeout
//   - WrongMsgID/WrongReqID error recovery
//   - Full packet send/receive cycle
func (SNMPparameters *SNMPv3Session) sendSnmpv3GetRequestPrototype(oidValue []SNMP_Packet_V2_VarBind, ReqType int, nonRepeaters int32, maxRepetitions int32) (SNMPretPacket SNMPv3_DecodePacket, err error) {
	SNMPparameters.cmux.Lock()
	defer SNMPparameters.cmux.Unlock()
	var ReturnSNMPpacker SNMPv3_DecodePacket
	var SNMPv3Packet []byte
	var errread error
	var recerr SNMPwrongReqID_MsgId_Errors
	LocalRequestId := atomic.LoadInt32(&SNMPparameters.SNMPparams.MessageIDv2)

	//Формирование запроса
	SNMPv3Packet, errread = SNMPparameters.makeMessage(oidValue, ReqType, LocalRequestId, nonRepeaters, maxRepetitions)
	if errread != nil {
		return ReturnSNMPpacker, errread
	}
	p := make([]byte, SNMP_BUFFERSIZE)
	//Таймаут на ожидание данных от агента
	tmms := time.Duration(SNMPparameters.SNMPparams.TimeoutBtwRepeat) * time.Millisecond

	writedn := 0
	SendRequest := true
	for itertry := 0; itertry < SNMPparameters.SNMPparams.RetryCount; itertry++ {
		//Установим таймаут на чтение
		TMread := time.Duration(SNMPparameters.SNMPparams.TimeoutBtwRepeat*(itertry+1)) * time.Millisecond
		errread = SNMPparameters.conn.SetReadDeadline(time.Now().Add(TMread))
		if errread != nil {
			continue
		}

		//Нужно послать запрос
		if SendRequest {
			errread = SNMPparameters.conn.SetWriteDeadline(time.Now().Add(tmms))
			if errread != nil {
				continue
			}
			writedn, errread = SNMPparameters.conn.Write(SNMPv3Packet)
			if errread != nil || writedn != len(SNMPv3Packet) {
				continue
			}
			//Запрос послан успешно
			//Снимаем флаг посылки
			SendRequest = false
		}

		rlen := 0
		//Ожидаем данные не позднее Текущее время плюс TMs
		rlen, errread = SNMPparameters.conn.Read(p)
		if errread == nil {
			//Пакет получен, разберем его
			ReturnSNMPpacker, errread = receiverV3parser(SNMPparameters, p[:rlen], true, LocalRequestId)
			if errread != nil {
				if errors.As(errread, &recerr) {
					if recerr.ErrorStatusCode == PARCE_ERR_WRONGMSGID || recerr.ErrorStatusCode == PARCE_ERR_WRONGREQID {
						//Принял ответ но это дубликат или неправильный ID
						//Просто ждем следующего пакета
						continue
					}
				} else {
					return ReturnSNMPpacker, errread
				}
			}
			break
		} else {
			var nerror net.Error
			if errors.As(errread, &nerror) {
				//Ошибка как net.Error
				if nerror.Timeout() {
					//Истек таймаут
					//Установим флаг повторной посылки
					SendRequest = true
				}
			}
			//Какая-то ошибка чтения, но не истечение таймаута
			continue
		}
	}
	return ReturnSNMPpacker, errread
}

// snmpv3_GetSet sends SNMPv3 GET/GETNEXT/GETBULK/SET request.
//
// Handles REPORT messages: auto-resyncs time on notInTime, maps common errors.
// Defaults: GetBulk(nonRepeaters=0, maxRepetitions=25).
//
// Example:
//
//	data, err := session.snmpv3_GetSet(oid, PowerSNMP.SNMPv2_REQUEST_GETNEXT,SNMPvbNullValue)
//	data, err := session.snmpv3_GetSet(oid, PowerSNMP.SNMPv2_REQUEST_GETBULK,SNMPvbNullValue)
//	data, err := session.snmpv3_GetSet(setOID, PowerSNMP.SNMPv2_REQUEST_SET, value)
func (SNMPparameters *SNMPv3Session) snmpv3_GetSet(oidValue []SNMP_Packet_V2_Decoded_VarBind, Request_Type int) (ReturnValue []SNMP_Packet_V2_Decoded_VarBind, err error) {
	atomic.AddInt32(&SNMPparameters.SNMPparams.MessageId, 1)
	atomic.AddInt32(&SNMPparameters.SNMPparams.MessageIDv2, 1)
	var ReturnVal []SNMP_Packet_V2_Decoded_VarBind
	var ReturnError error
	var partialerr SNMPne_Errors
	nonRepeaters, maxRepetitions := int32(0), int32(0)
	if Request_Type == SNMPv2_REQUEST_GETBULK {
		nonRepeaters = 0
		maxRepetitions = 25
	}

	defer func() {
		if ReturnError == nil && len(partialerr.Failedoids) > 0 {
			err = partialerr
		}
	}()

	OidVarConverted := make([]SNMP_Packet_V2_VarBind, 0)
	for _, elm := range oidValue {
		OidVarConverted = append(OidVarConverted, SNMP_Packet_V2_VarBind{elm.RSnmpOID, Convert_setvar_toasn1raw(elm.RSnmpVar)})
	}

	rts, complexerr := SNMPparameters.sendSnmpv3GetRequestPrototype(OidVarConverted, Request_Type, nonRepeaters, maxRepetitions)

	if complexerr != nil {
		if !errors.As(complexerr, &partialerr) {
			//Not partial error
			ReturnError = complexerr
			return ReturnVal, ReturnError
		}
	}
	if rts.MessageType == REPORT_MESSAGE {
		if len(rts.V3PDU.V2VarBind.VarBinds) == 0 {
			return ReturnVal, errors.New("empty report")
		}
		OID_NoInTime := []int{1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0}
		OID_WrongUsername := []int{1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0}
		OID_WrongDigest := []int{1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0}
		OID_DecryptionErrror := []int{1, 3, 6, 1, 6, 3, 15, 1, 1, 6, 0}
		OID_UnknownContext := []int{1, 3, 6, 1, 6, 3, 12, 1, 5, 0}
		if rts.V3PDU.V2VarBind.VarBinds[0].RSnmpOID.Equal(OID_NoInTime) {
			//fmt.Println("NoInTime -> Must syc time and resend")
			RecivedBoots := rts.SecuritySettings.Boots
			RecivedTime := rts.SecuritySettings.Time
			if RecivedBoots > 0 || RecivedTime > 0 {
				// Некоторые SNMP агенты, при определении Engine ID не присылают Boots и Time
				// поэтому их можно выставить после ополучения ошибки NoInTime с правильными значениями
				SNMPparameters.SNMPparams.DiscoveredTimeBoots.Store(true)
				atomic.StoreInt32(&SNMPparameters.SNMPparams.RBoots, RecivedBoots)
				atomic.StoreInt32(&SNMPparameters.SNMPparams.RTime, RecivedTime)
				atomic.AddInt32(&SNMPparameters.SNMPparams.MessageId, 1)
				atomic.AddInt32(&SNMPparameters.SNMPparams.MessageIDv2, 1)
				//Повторный запрос после синхронизации
				rts, complexerr = SNMPparameters.sendSnmpv3GetRequestPrototype(OidVarConverted, Request_Type, nonRepeaters, maxRepetitions)
				if complexerr != nil {
					//Если есть серьезная ошибка, то выходим и возвращаем ее
					if !errors.As(complexerr, &partialerr) {
						ReturnError = complexerr
						return nil, ReturnError
					}
				}
				if rts.MessageType == REPORT_MESSAGE {
					ReturnError = fmt.Errorf("repeat request failed")
					return nil, ReturnError
				}
				return rts.V3PDU.V2VarBind.VarBinds, nil

			} else {
				ReturnError = errors.New("time synchronization failed: boots and time are zero")
				return ReturnVal, ReturnError
			}
		}
		if rts.V3PDU.V2VarBind.VarBinds[0].RSnmpOID.Equal(OID_WrongUsername) {
			ReturnError = errors.New("wrong username")
			return ReturnVal, ReturnError
		}
		if rts.V3PDU.V2VarBind.VarBinds[0].RSnmpOID.Equal(OID_WrongDigest) {
			ReturnError = errors.New("wrong authkey")
			return ReturnVal, ReturnError
		}
		if rts.V3PDU.V2VarBind.VarBinds[0].RSnmpOID.Equal(OID_DecryptionErrror) {
			ReturnError = errors.New("decryption error")
			return ReturnVal, ReturnError
		}
		if rts.V3PDU.V2VarBind.VarBinds[0].RSnmpOID.Equal(OID_UnknownContext) {
			ReturnError = errors.New("unknown context")
			return ReturnVal, ReturnError
		}
		ReturnError = fmt.Errorf("unknown REPORT OID: %v", rts.V3PDU.V2VarBind.VarBinds[0].RSnmpOID)
		return ReturnVal, ReturnError
	} else {
		ReturnVal = rts.V3PDU.V2VarBind.VarBinds
	}
	return ReturnVal, ReturnError
}

// SNMP_Walk performs complete SNMP WALK starting from base OID using GETNEXT.
//
// Lexicographic traversal of MIB subtree using SNMPv2_GETNEXT PDUs (RFC3411 §4.2.3).
// Continues until lexicographic boundary reached (noError + next OID outside subtree).
//
// Arguments:
//
//	oid - Base OID for walk (e.g.: []int{1,3,6,1,2,1,2,2,1} = ifTable)
//
// Returns:
//
//	[]SNMP_Packet_V2_Decoded_VarBind - Complete subtree results (ordered lexicographically)
//	error - Network errors only. SNMP errors handled internally (noSuchName=endOfMibView)
//
// Behavior:
//   - Existing subtree → ALL objects until boundary
//   - Nonexistent base OID → [] + nil (RFC3411, SNMP4J compatible)
//   - Individual noSuchName → walk continues (GETNEXT semantics)
//   - Net-SNMP CLI difference: "No Such Object" (CLI-only extension)
//
// Examples:
//
//	// Walk ifTable (48 interfaces)
//	ifTableOID := []int{1,3,6,1,2,1,2,2,1}
//	results, err := sess.SNMP_Walk(ifTableOID)
//	// len(results) = 1000+ (ifTable complete)
//
//	// Nonexistent base OID (RFC3411 behavior)
//	badOID := []int{1,3,6,1,2,1,1,99,0}
//	results, err = sess.SNMP_Walk(badOID)
//	// len(results) == 0 && err == nil (SNMP4J compatible)
//
//	// Process results
//	for _, vb := range results {
//	    fmt.Printf("%s = %s\n",
//	        Convert_OID_IntArrayToString_RAW(vb.RSnmpOID),
//	        Convert_Variable_To_String(vb.RSnmpVar))
//	}
//
// Algorithm (RFC3411 §4.2.3):
//  1. GETNEXT(baseOID) → lexicographic next OID+value
//  2. If result startsWith(baseOID) → add to results, GOTO 1
//  3. If next OID outside subtree → normal termination (no error)
//
// Production usage:
//
//	// Network discovery (sysObjectID walk → vendor detection)
//	sysOID := []int{1,3,6,1,2,1,1,2,0}
//	walk, _ := sess.SNMP_Walk(sysOID)
//	vendor := extractVendor(walk[0].RSnmpVar)  // Cisco, Huawei, etc
//
// Error scenarios (network only):
//   - Connection timeout/disconnect
//   - Authentication failure (USM errors)
//   - "unsupported SNMP version" (v1,v4+)
//   - SNMP errors (noSuchName, endOfMibView) → NORMAL walk termination
//
// Performance notes:
//   - N PDUs for N objects (no GETBULK optimization)
//   - Use SNMP_GetBulk for large tables (1000+ rows)
//   - Results preserve discovery order (stable lexicographic)
func (SNMPparameters *SNMPv3Session) snmpv3_Walk(Oid []int, ReqType int) (SNMPData []SNMP_Packet_V2_Decoded_VarBind, err error) {
	OidVarConverted := []SNMP_Packet_V2_Decoded_VarBind{{Oid, SNMPvbNullValue}}
	var RetVar []SNMP_Packet_V2_Decoded_VarBind
	for a := 0; a < SNMP_MAXIMUMWALK; a++ {
		SNMPGet, SNMPGetErr := SNMPparameters.snmpv3_GetSet(OidVarConverted, ReqType)
		if SNMPGetErr != nil {
			return RetVar, SNMPGetErr
		}
		//Обходим результат и проверяем не вышли ли из ветки
		for _, val := range SNMPGet {
			//Проверяем не зациклились ли
			if reflect.DeepEqual(Oid, val.RSnmpOID) {
				RetVar = append(RetVar, val)
				reterr := fmt.Errorf("OID is not increased")
				return RetVar, reterr
			}
			if InSubTreeCheck(Oid, val.RSnmpOID) == false {
				return RetVar, nil
			} else {
				RetVar = append(RetVar, val)
			}
		}
		if len(SNMPGet) > 0 {
			OidVarConverted[0].RSnmpOID = SNMPGet[len(SNMPGet)-1].RSnmpOID
		} else {
			return RetVar, nil
		}
	}
	return RetVar, nil
}

// snmpv3_Walk_WChan performs streaming GetNext walk via channel.
//
// Non-blocking: sends each VarBind to channel as received (1946 rows/s tested).
// Consumer processes in separate goroutine, no memory buffering.
//
// Usage:
//
//	ch := make(chan PowerSNMP.ChanDataWErr)
//	go session.snmpv3_Walk_WChan(oid, SNMPv2_REQUEST_GETNEXT, ch)
//	for result := range ch { ... }
//
// Closes channel on completion/error/loop/subtree exit.
func (SNMPparameters *SNMPv3Session) snmpv3_Walk_WChan(Oid []int, ReqType int, CData chan<- ChanDataWErr) {
	var ChanData ChanDataWErr
	OidVarConverted := []SNMP_Packet_V2_Decoded_VarBind{{Oid, SNMPvbNullValue}}
	for a := 0; a < SNMP_MAXIMUMWALK; a++ {
		Data, Err := SNMPparameters.snmpv3_GetSet(OidVarConverted, ReqType)
		//if Err != nil {
		//	ChanData.Error = Err
		//	CData <- ChanData
		//	close(CData)
		//	return
		//}
		partialErrSend, needClose := false, false
		if Err != nil {
			var SNMPud_Err SNMPud_Errors
			var CommonError error
			SNMPud_Err, CommonError = ParseError(Err)
			if SNMPud_Err.IsFatal || CommonError != nil {
				//Non partial error - need to breake walk
				ChanData.Data = SNMP_Packet_V2_Decoded_VarBind{}
				ChanData.Error = Err
				ChanData.ValidData = false
				CData <- ChanData
				close(CData)
				return
			}
			partialErrSend = true
		}
		//Обходим результат и проверяем не вышли ли из ветки
		for _, val := range Data {
			//Проверяем не зациклились ли
			if slices.Equal(OidVarConverted[0].RSnmpOID, val.RSnmpOID) {
				//Если да то выйдем с ошибкой
				ChanData.Data = val
				ChanData.Error = fmt.Errorf("OID is not increased")
				ChanData.ValidData = false
				CData <- ChanData
				close(CData)
				return
			}
			if InSubTreeCheck(Oid, val.RSnmpOID) == false {
				needClose = true
				break
			} else {
				ChanData.Data = val
				ChanData.Error = nil
				ChanData.ValidData = true
				CData <- ChanData
			}
		}

		if partialErrSend {
			ChanData.Data = SNMP_Packet_V2_Decoded_VarBind{}
			ChanData.ValidData = false
			ChanData.Error = Err
			CData <- ChanData
			needClose = true
		}

		if needClose {
			close(CData)
			return
		}

		//Продолжаем Walk
		if len(Data) > 0 {
			OidVarConverted[0].RSnmpOID = Data[len(Data)-1].RSnmpOID
		} else {
			close(CData)
			return
		}
	}
	close(CData)
	return
}

// sendV3ACK sends SNMPv3 RESPONSE to acknowledge SNMPv3 INFORM (RFC 3416).
//
// Creates new UDP connection (fire-and-forget) and sends Response PDU with original
// RequestID to `1.3.6.1.2.1.1.3.0` (sysUpTime.0 null value).
//
// Required for INFORM compliance - sender retries without ACK.
func (SNMPparameters *SNMPv3Session) sendV3ACK(requestid int32) (err error) {
	var lasterr error
	Tmms := time.Duration(SNMPparameters.SNMPparams.TimeoutBtwRepeat) * time.Millisecond
	Ds := net.Dialer{Timeout: Tmms}
	//DialAddress := fmt.Sprintf("%s:%d", SNMPparameters.IPaddress, SNMPparameters.Port)
	DialAddress := net.JoinHostPort(SNMPparameters.IPaddress, fmt.Sprintf("%d", SNMPparameters.Port))
	conn, dialerr := Ds.Dial("udp", DialAddress)
	if dialerr != nil {
		return dialerr
	}
	defer func() {
		cerrc := conn.Close()
		if cerrc != nil && lasterr == nil {
			err = cerrc
		}
	}()

	Oid := []int{1, 3, 6, 1, 2, 1, 1, 3, 0}
	OidVarConverted := []SNMP_Packet_V2_VarBind{{Oid, ASNber.NullRawValue}}

	MS, lasterr := SNMPparameters.makeMessage(OidVarConverted, SNMPv2_REQUEST_RESPONSE, requestid, 0, 0)
	if lasterr != nil {
		return lasterr
	}
	lasterr = conn.SetWriteDeadline(time.Now().Add(Tmms))
	if lasterr != nil {
		return lasterr
	}
	writedn, lasterr := conn.Write(MS)
	if lasterr != nil {
		return lasterr
	}
	if writedn == 0 {
		lasterr = fmt.Errorf("SNMPv3 Write error")
	}
	return lasterr
}
