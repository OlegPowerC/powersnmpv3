// PowerSNMPv3 - SNMP library for Go
// Автор: Волков Олег
// Author: Volkov Oleg
// License: MIT
// Лицензия: MIT
// Commercial support and custom development available.
package PowerSNMPv3

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"slices"
	"sync/atomic"
	"time"

	ASNber "github.com/OlegPowerC/asn1modsnmp"
)

func (SNMPparameters *SNMPv3Session) embeddedNoInTime(rts SNMPv3_DecodePacket) error {

	RecivedBoots := rts.SecuritySettings.Boots
	RecivedTime := rts.SecuritySettings.Time
	var ReturnError error
	if RecivedBoots > 0 || RecivedTime > 0 {
		// Некоторые SNMP агенты, при определении Engine ID не присылают Boots и Time
		// поэтому их можно выставить после ополучения ошибки NoInTime с правильными значениями
		SNMPparameters.SNMPparams.DiscoveredTimeBoots.Store(true)
		atomic.StoreInt32(&SNMPparameters.SNMPparams.RBoots, RecivedBoots)
		atomic.StoreInt32(&SNMPparameters.SNMPparams.RTime, RecivedTime)

	} else {
		ReturnError = errors.New("time synchronization failed: boots and time are zero")
		return ReturnError
	}
	return nil
}

func (SNMPparameters *SNMPv3Session) reportHandle(rts SNMPv3_DecodePacket, OidVarConverted []SNMP_Packet_V2_VarBind, Request_Type int, nonRepeaters int32, maxRepetitions int32, depth uint8, perr error) (SNMPv3_DecodePacket, error) {
	if rts.MessageType != REPORT_MESSAGE {
		return rts, perr
	}
	atomic.AddInt32(&SNMPparameters.SNMPparams.MessageId, 1)
	atomic.AddInt32(&SNMPparameters.SNMPparams.MessageIDv2, 1)
	var ReturnError error
	var ReturnVal SNMPv3_DecodePacket
	var partialerr SNMPne_Errors
	depth = depth + 1
	if depth > 3 {
		return ReturnVal, errors.New("Too many calls")
	}

	if len(rts.V3PDU.V2VarBind.VarBinds) == 0 {
		return ReturnVal, errors.New("empty report")
	}
	if rts.V3PDU.V2VarBind.VarBinds[0].RSnmpOID.Equal(OID_NoInTime) {

		stimeerr := SNMPparameters.embeddedNoInTime(rts)
		if stimeerr != nil {
			return ReturnVal, stimeerr
		}

		//Повторный запрос
		rtspreq, complexerr := SNMPparameters.sendSnmpv3GetRequestPrototype(OidVarConverted, Request_Type, nonRepeaters, maxRepetitions)
		rtsp, complexerrfr := SNMPparameters.reportHandle(rtspreq, OidVarConverted, Request_Type, nonRepeaters, maxRepetitions, depth, complexerr)
		if complexerrfr != nil {
			//Если есть серьезная ошибка, то выходим и возвращаем ее
			if !errors.As(complexerrfr, &partialerr) {
				ReturnError = complexerrfr
				return ReturnVal, ReturnError
			}
		}
		return rtsp, complexerrfr
	}
	if rts.V3PDU.V2VarBind.VarBinds[0].RSnmpOID.Equal(OID_UnknownEngineId) && depth == 1 {
		discoer := SNMPparameters.embeddedDiscovery(rts)
		if discoer != nil {
			return ReturnVal, fmt.Errorf("discovery failed: %v", discoer)
		}

		//Повторный запрос
		rtspreq, complexerr := SNMPparameters.sendSnmpv3GetRequestPrototype(OidVarConverted, Request_Type, nonRepeaters, maxRepetitions)
		rtsp, complexerrfr := SNMPparameters.reportHandle(rtspreq, OidVarConverted, Request_Type, nonRepeaters, maxRepetitions, depth, complexerr)
		if complexerrfr != nil {
			//Если есть серьезная ошибка, то выходим и возвращаем ее
			if !errors.As(complexerrfr, &partialerr) {
				ReturnError = complexerrfr
				return ReturnVal, ReturnError
			}
		}
		return rtsp, complexerrfr

	}
	if rts.V3PDU.V2VarBind.VarBinds[0].RSnmpOID.Equal(OID_UnknownEngineId) && depth > 1 {
		return ReturnVal, errors.New("unknown engine id - discovery already done")
	}
	if rts.V3PDU.V2VarBind.VarBinds[0].RSnmpOID.Equal(OID_WrongUsername) {
		ReturnError = errors.New("wrong username")
		return ReturnVal, ReturnError
	}
	if rts.V3PDU.V2VarBind.VarBinds[0].RSnmpOID.Equal(OID_WrongDigest) {
		ReturnError = errors.New("wrong authkey")
		return ReturnVal, ReturnError
	}
	if rts.V3PDU.V2VarBind.VarBinds[0].RSnmpOID.Equal(OID_DecryptionError) {
		ReturnError = errors.New("decryption error")
		return ReturnVal, ReturnError
	}
	if rts.V3PDU.V2VarBind.VarBinds[0].RSnmpOID.Equal(OID_UnknownContext) {
		ReturnError = errors.New("unknown context")
		return ReturnVal, ReturnError
	}
	if rts.V3PDU.V2VarBind.VarBinds[0].RSnmpOID.Equal(OID_UnsupportedSecLevels) {
		ReturnError = errors.New("unsupported security levels")
		return ReturnVal, ReturnError
	}

	ReturnError = fmt.Errorf("unknown REPORT OID: %v", rts.V3PDU.V2VarBind.VarBinds[0].RSnmpOID)
	return ReturnVal, ReturnError
}

func (SNMPparameters *SNMPv3Session) embeddedDiscovery(rts SNMPv3_DecodePacket) error {

	if len(rts.V3PDU.V2VarBind.VarBinds) == 0 {
		return errors.New("discovery failed: empty VarBinds in response")

	}

	if !rts.V3PDU.V2VarBind.VarBinds[0].RSnmpOID.Equal(OID_UnknownEngineId) {
		return errors.New("wrong report")
	}

	if SNMPparameters.Debuglevel > 199 {
		fmt.Println("Unknown Engine ID!")
		fmt.Println("Discovered Engine ID:", hex.EncodeToString(rts.SecuritySettings.AuthEng), "Discovered boots:", rts.SecuritySettings.Boots, "Discovered times:", rts.SecuritySettings.Time)
	}

	SNMPparameters.SNMPparams.EngineID = rts.SecuritySettings.AuthEng
	SNMPparameters.SNMPparams.ContextEngineId = rts.SecuritySettings.AuthEng

	// Установим MaxMessageSize в сторону агента (из того что он нам предложил)
	if rts.GlobalData.MsgMaxSize >= MIN_ALLOWED_TX_MAXMESSAGESIZE {
		SNMPparameters.SNMPparams.txMaxMsgSize = rts.GlobalData.MsgMaxSize
	}

	if SNMPparameters.SNMPparams.SecurityLevel > SECLEVEL_NOAUTH_NOPRIV {
		Lkey := makeLocalizedKey(SNMPparameters.SNMPparams.AuthKey, SNMPparameters.SNMPparams.EngineID, SNMPparameters.SNMPparams.AuthProtocol)
		SNMPparameters.SNMPparams.LocalizedKeyAuth = Lkey
		atomic.OrUint32(&SNMPparameters.SNMPparams.DataFlag, 1<<msgFlag_Authenticated_Bit)
	}

	if SNMPparameters.SNMPparams.SecurityLevel == SECLEVEL_AUTHPRIV {
		Lkey := makeLocalizedKey(SNMPparameters.SNMPparams.PrivKey, SNMPparameters.SNMPparams.EngineID, SNMPparameters.SNMPparams.AuthProtocol)

		switch SNMPparameters.SNMPparams.PrivProtocol {
		case PRIV_PROTOCOL_AES128:
			if len(Lkey) > 16 {
				Lkey = Lkey[:16] // Только AES128!
			}
		case PRIV_PROTOCOL_AES192, PRIV_PROTOCOL_AES256, PRIV_PROTOCOL_AES192A, PRIV_PROTOCOL_AES256A:
			Lkey = expandPrivKey(Lkey, SNMPparameters.SNMPparams.PrivProtocol, SNMPparameters.SNMPparams.AuthProtocol, SNMPparameters.SNMPparams.EngineID)
		}

		SNMPparameters.SNMPparams.LocalizedKeyPriv = Lkey
		SNMPparameters.SNMPparams.PrivParameter = rand.Uint64()
		SNMPparameters.SNMPparams.PrivParameterDes = rand.Uint32()
		atomic.OrUint32(&SNMPparameters.SNMPparams.DataFlag, 1<<msgFlag_Encrypted_Bit)
	}

	if rts.SecuritySettings.Boots > 0 || rts.SecuritySettings.Time > 0 {
		SNMPparameters.SNMPparams.DiscoveredTimeBoots.Store(true)
		atomic.StoreInt32(&SNMPparameters.SNMPparams.RBoots, rts.SecuritySettings.Boots)
		atomic.StoreInt32(&SNMPparameters.SNMPparams.RTime, rts.SecuritySettings.Time)
	}

	SNMPparameters.SNMPparams.DiscoveredEngineId.Store(true)

	return nil
}

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
	Session.SNMPparams.txMaxMsgSize = SNMP_START_TX_MAXMSGSIZE
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

	if Ndev.SNMPparameters.MaxMsgSize <= SNMP_MINMSGSITE || Ndev.SNMPparameters.MaxMsgSize > SNMP_MAXMSGSIZE {
		Session.SNMPparams.MaxMsgSize = SNMP_DEFAULTMSGSITE
	} else {
		Session.SNMPparams.MaxMsgSize = Ndev.SNMPparameters.MaxMsgSize
	}
	Session.SNMPparams.rxbuffersize = Session.SNMPparams.MaxMsgSize

	Session.SNMPparams.AuthKey = Ndev.SNMPparameters.AuthKey
	Session.SNMPparams.PrivKey = Ndev.SNMPparameters.PrivKey
	Session.SNMPparams.MessageIDv2 = rand.Int31()
	Session.SNMPparams.MessageId = rand.Int31()
	//Тут устанавливается Reportable флаг и будет жить всю сессию
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
	seclevel, aproto, pproto, ReturnError := CheckSNMPv3StringParams(Ndev.SNMPparameters.AuthProtocol, Ndev.SNMPparameters.AuthKey, Ndev.SNMPparameters.PrivProtocol, Ndev.SNMPparameters.PrivKey)
	if ReturnError != nil {
		return Session, ReturnError
	}

	Session.SNMPparams.SecurityLevel = seclevel
	Session.SNMPparams.AuthProtocol = aproto
	Session.SNMPparams.AuthKey = Ndev.SNMPparameters.AuthKey
	Session.SNMPparams.PrivProtocol = pproto
	Session.SNMPparams.PrivKey = Ndev.SNMPparameters.PrivKey

	_, complexerr := Session.snmpv3_GetSet([]SNMP_Packet_V2_Decoded_VarBind{{internaluseOID_SysDescr, SNMPvbNullValue}}, SNMPv2_REQUEST_GET)
	if complexerr != nil {
		ReturnError = complexerr
		return Session, ReturnError

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
	SNMP_GlobalData.MsgMaxSize = int(SNMPparameters.SNMPparams.MaxMsgSize)
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

	if len(SNMPv3Packet) > SNMPparameters.SNMPparams.txMaxMsgSize {
		return ReturnSNMPpacker, fmt.Errorf("cannot send data, data too big")
	}

	p := make([]byte, SNMPparameters.SNMPparams.rxbuffersize)

	writedn := 0
	for itertry := 0; itertry < SNMPparameters.SNMPparams.RetryCount; itertry++ {
		//Установим таймаут на чтение
		TMread := time.Duration(SNMPparameters.SNMPparams.TimeoutBtwRepeat*(itertry+1)) * time.Millisecond
		rdeadLine := time.Now().Add(TMread)
		errread = SNMPparameters.conn.SetReadDeadline(rdeadLine)
		if errread != nil {
			continue
		}

		//Нужно послать запрос

		//Таймаут на запись данных
		TMwrite := time.Duration(SNMPparameters.SNMPparams.TimeoutBtwRepeat) * time.Millisecond
		wdeadLine := time.Now().Add(TMwrite)
		errread = SNMPparameters.conn.SetWriteDeadline(wdeadLine)
		if errread != nil {
			continue
		}
		writedn, errread = SNMPparameters.conn.Write(SNMPv3Packet)
		if errread != nil || writedn != len(SNMPv3Packet) {
			continue
		}
		//Запрос послан успешно

		for time.Now().Before(rdeadLine) {
			//Ожидаем данные не позднее Текущее время плюс rdeadLine
			rlen, readerr := SNMPparameters.conn.Read(p)
			if readerr == nil {
				if rlen > int(SNMPparameters.SNMPparams.rxbuffersize) {
					return ReturnSNMPpacker, fmt.Errorf("received data len bigger than buffer")
				}
				//Ошибок чтения нет
				//Пакет получен, разберем его
				var parcerror error
				ReturnSNMPpacker, parcerror = SNMPparameters.receiverV3parser(p[:rlen], true, false, LocalRequestId)
				if parcerror != nil {
					if errors.As(parcerror, &recerr) {
						if recerr.ErrorStatusCode == PARCE_ERR_WRONGMSGID || recerr.ErrorStatusCode == PARCE_ERR_WRONGREQID {
							//Принял ответ но это дубликат или неправильный ID
							//Просто ждем следующего пакета
							continue
						}
					} else {
						return ReturnSNMPpacker, parcerror
					}
				}
				return ReturnSNMPpacker, parcerror
			} else {
				//Ошибка чтения
				errread = readerr
				var nerror net.Error
				if errors.As(errread, &nerror) {
					//Ошибка как net.Error
					if nerror.Timeout() {
						//Истек таймаут
						//И выход во внешний цикл
						break
					} else {
						//Какая то другая сетевая ошибка
						return ReturnSNMPpacker, errread
					}
				} else {
					//не сетевая ошибка
					return ReturnSNMPpacker, errread
				}
			}
		}
		//Внутренний цикл завершен но ошибок нет
		if errread == nil {
			errread = fmt.Errorf("timeout waiting for correct SNMP response")
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
		maxRepetitions = SNMPparameters.SNMPparams.MaxRepetitions
	}

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
		rts, complexerr = SNMPparameters.reportHandle(rts, OidVarConverted, Request_Type, nonRepeaters, maxRepetitions, 0, complexerr)
		if complexerr != nil {
			//Если есть серьезная ошибка, то выходим и возвращаем ее
			if !errors.As(complexerr, &partialerr) {
				ReturnError = complexerr
				return nil, ReturnError
			}
		}
		return rts.V3PDU.V2VarBind.VarBinds, complexerr
	}
	return rts.V3PDU.V2VarBind.VarBinds, complexerr
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
		partialErr := false
		if SNMPGetErr != nil {
			var SNMPud_Err SNMPud_Errors
			var CommonError error
			SNMPud_Err, CommonError = ParseError(SNMPGetErr)
			if SNMPud_Err.IsFatal || CommonError != nil {
				//Фатальные ошибки, сразу выходим
				return RetVar, SNMPGetErr
			}
			partialErr = true
		}
		//Обходим результат и проверяем не вышли ли из ветки
		for _, val := range SNMPGet {
			//Проверяем не зациклились ли
			if slices.Equal(OidVarConverted[0].RSnmpOID, val.RSnmpOID) {
				reterr := fmt.Errorf("OID is not increased")
				return RetVar, reterr
			}
			if InSubTreeCheck(Oid, val.RSnmpOID) == false {
				//Выши за пределы ветки
				return RetVar, nil
			} else {
				//Нормальная ситуация, добавим данные
				RetVar = append(RetVar, val)
			}
		}

		if partialErr {
			return RetVar, SNMPGetErr
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
func (SNMPparameters *SNMPv3Session) snmpv3_Walk_WChan(ctx context.Context, Oid []int, ReqType int, CData chan<- ChanDataWErr) {
	var ChanData ChanDataWErr
	OidVarConverted := []SNMP_Packet_V2_Decoded_VarBind{{Oid, SNMPvbNullValue}}
	defer close(CData)
	for a := 0; a < SNMP_MAXIMUMWALK; a++ {
		select {
		case <-ctx.Done():
			ChanData.Data = SNMP_Packet_V2_Decoded_VarBind{}
			ChanData.ValidData = false
			ChanData.Error = ctx.Err()
			select {
			case CData <- ChanData:
			default:
			}
			return
		default:
		}
		Data, Err := SNMPparameters.snmpv3_GetSet(OidVarConverted, ReqType)
		partialErrSend, needClose := false, false
		if Err != nil {
			var SNMPud_Err SNMPud_Errors
			var CommonError error
			SNMPud_Err, CommonError = ParseError(Err)
			if SNMPud_Err.IsFatal || CommonError != nil {
				//Фатальные ошибки, сразу выходим
				ChanData.Data = SNMP_Packet_V2_Decoded_VarBind{}
				ChanData.Error = Err
				ChanData.ValidData = false
				select {
				case <-ctx.Done():
					return
				case CData <- ChanData:
				}

				return
			}
			partialErrSend = true
		}
		//Обходим результат и проверяем не вышли ли из ветки
		for _, val := range Data {
			//Проверяем не зациклились ли
			if slices.Equal(OidVarConverted[0].RSnmpOID, val.RSnmpOID) {
				//Если да то выйдем с ошибкой, данные не отправляем - это повтор
				ChanData.Data = SNMP_Packet_V2_Decoded_VarBind{}
				ChanData.Error = fmt.Errorf("OID is not increased")
				ChanData.ValidData = false
				select {
				case <-ctx.Done():
					return
				case CData <- ChanData:
				}
				return
			}
			if InSubTreeCheck(Oid, val.RSnmpOID) == false {
				needClose = true
				break
			} else {
				ChanData.Data = val
				ChanData.Error = nil
				ChanData.ValidData = true
				select {
				case <-ctx.Done():
					return
				case CData <- ChanData:
				}
			}
		}

		if partialErrSend {
			ChanData.Data = SNMP_Packet_V2_Decoded_VarBind{}
			ChanData.ValidData = false
			ChanData.Error = Err
			select {
			case <-ctx.Done():
				return
			case CData <- ChanData:
			}
			//В walk partial error при котором надо продолжить обход невозможен, так как OID к которым например нет доступа, просто не попадут в ответ.
			//Исключение первый OID но ответ будет только на него одного
			needClose = true
		}

		if needClose {
			return
		}

		//Продолжаем Walk
		if len(Data) > 0 {
			OidVarConverted[0].RSnmpOID = Data[len(Data)-1].RSnmpOID
		} else {
			return
		}
	}
	return
}

func (SNMPparameters *SNMPv3Session) snmpv3_Walk_WCallback(Oid []int, ReqType int, callback func(ChanDataWErr)) {
	var ChanData ChanDataWErr
	OidVarConverted := []SNMP_Packet_V2_Decoded_VarBind{{Oid, SNMPvbNullValue}}
	for a := 0; a < SNMP_MAXIMUMWALK; a++ {
		Data, Err := SNMPparameters.snmpv3_GetSet(OidVarConverted, ReqType)
		partialErrSend, needClose := false, false
		if Err != nil {
			var SNMPud_Err SNMPud_Errors
			var CommonError error
			SNMPud_Err, CommonError = ParseError(Err)
			if SNMPud_Err.IsFatal || CommonError != nil {
				//Фатальные ошибки, сразу выходим
				ChanData.Data = SNMP_Packet_V2_Decoded_VarBind{}
				ChanData.Error = Err
				ChanData.ValidData = false
				callback(ChanData)
				return
			}
			partialErrSend = true
		}
		//Обходим результат и проверяем не вышли ли из ветки
		for _, val := range Data {
			//Проверяем не зациклились ли
			if slices.Equal(OidVarConverted[0].RSnmpOID, val.RSnmpOID) {
				//Если да то выйдем с ошибкой, данные не отправляем - это повтор
				ChanData.Data = SNMP_Packet_V2_Decoded_VarBind{}
				ChanData.Error = fmt.Errorf("OID is not increased")
				ChanData.ValidData = false
				callback(ChanData)
				return
			}
			if InSubTreeCheck(Oid, val.RSnmpOID) == false {
				needClose = true
				break
			} else {
				ChanData.Data = val
				ChanData.Error = nil
				ChanData.ValidData = true
				callback(ChanData)
			}
		}

		if partialErrSend {
			ChanData.Data = SNMP_Packet_V2_Decoded_VarBind{}
			ChanData.ValidData = false
			ChanData.Error = Err
			callback(ChanData)
			needClose = true
		}

		if needClose {
			return
		}

		//Продолжаем Walk
		if len(Data) > 0 {
			OidVarConverted[0].RSnmpOID = Data[len(Data)-1].RSnmpOID
		} else {
			return
		}
	}
}

// sendV3ACK sends SNMPv3 RESPONSE to acknowledge SNMPv3 INFORM (RFC 3416).
//
// Creates new UDP connection (fire-and-forget) and sends Response PDU with original
// RequestID to `1.3.6.1.2.1.1.3.0` (sysUpTime.0 null value).
//
// Required for INFORM compliance - sender retries without ACK.
func (SNMPparameters *SNMPv3Session) sendV3ACK(conn net.PacketConn, dstAddr net.Addr, requestid int32) (err error) {
	var lasterr error
	Tmms := time.Duration(SNMPparameters.SNMPparams.TimeoutBtwRepeat) * time.Millisecond
	/*
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

	*/

	OidVarConverted := []SNMP_Packet_V2_VarBind{{internaluseOID_SysUpTime, ASNber.NullRawValue}}

	MS, lasterr := SNMPparameters.makeMessage(OidVarConverted, SNMPv2_REQUEST_RESPONSE, requestid, 0, 0)
	if lasterr != nil {
		return lasterr
	}
	lasterr = conn.SetWriteDeadline(time.Now().Add(Tmms))
	if lasterr != nil {
		return lasterr
	}
	writedn, lasterr := conn.WriteTo(MS, dstAddr)
	if lasterr != nil {
		return lasterr
	}
	if writedn == 0 {
		lasterr = fmt.Errorf("SNMPv3 Write error")
	}
	return lasterr
}

func (SNMPparameters *SNMPv3Session) sendV3REPORT(conn net.PacketConn, dstAddr net.Addr, requestid int32, ReportType []int) (err error) {
	var lasterr error
	Tmms := time.Duration(SNMPparameters.SNMPparams.TimeoutBtwRepeat) * time.Millisecond
	/*
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

	*/

	OidVarConverted := []SNMP_Packet_V2_VarBind{{internaluseOID_SysUpTime, ASNber.NullRawValue}}

	MS, lasterr := SNMPparameters.makeMessage(OidVarConverted, 8, requestid, 0, 0)
	if lasterr != nil {
		return lasterr
	}
	lasterr = conn.SetWriteDeadline(time.Now().Add(Tmms))
	if lasterr != nil {
		return lasterr
	}
	writedn, lasterr := conn.WriteTo(MS, dstAddr)
	if lasterr != nil {
		return lasterr
	}
	if writedn == 0 {
		lasterr = fmt.Errorf("SNMPv3 Write error")
	}
	return lasterr
}
