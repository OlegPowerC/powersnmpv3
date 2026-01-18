// PowerSNMPv3 - SNMP library for Go
// Автор: Волков Олег, ООО "Пауэр Си"
// Author: Volkov Oleg, PowerC LLC
// License: MIT (commercial version with support available)
// Лицензия: MIT (доступна коммерческая версия с поддержкой)
package PowerSNMPv3

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync/atomic"
	"time"

	ASNber "github.com/OlegPowerC/asn1modsnmp"
)

// makeSNMPPv2Packet constructs SNMPv2c packet (GET/GETNEXT/GETBULK/SET).
//
// Wraps V2 PDU in Community string + SNMPv2 version wrapper.
// Handles GetBulk nonRepeaters/maxRepetitions field mapping.
//
// Internal use for SNMPv2c operations.
func (SNMPparameters *SNMPv3Session) makeSNMPPv2Packet(oidValue []SNMP_Packet_V2_VarBind, requestid int32, SNMPv2_RequestType int, nonRepeaters int32, maxRepetitions int32) (SNMPPDU []byte, err error) {
	V2PDU := SNMP_Packet_V2_PDU{requestid, 0, 0, oidValue}
	V2PDU.ErrorStatusRaw = 0
	V2PDU.ErrorIndexRaw = 0
	if SNMPv2_RequestType == SNMPv2_REQUEST_GETBULK {
		V2PDU.ErrorStatusRaw = nonRepeaters
		V2PDU.ErrorIndexRaw = maxRepetitions
	}
	V2PDU_ASNEncode, V2PDU_ASNEncodeErr := ASNber.Marshal(V2PDU)
	if V2PDU_ASNEncodeErr != nil {
		return nil, V2PDU_ASNEncodeErr
	}

	//Тип составной записи - класс Context-Specified
	//Тег зависит от запроса
	var pmval ASNber.RawValue

	pmval.Class = ASNber.ClassContextSpecific
	pmval.IsCompound = true
	pmval.Tag = SNMPv2_RequestType
	SNMPversion := 1

	//Извлекаем данные (без TAG LEN)
	PureData, ExErr := ASNber.ExtractDataWOTagAndLen(V2PDU_ASNEncode)
	if ExErr != nil {
		return nil, ExErr
	}
	pmval.Bytes = PureData //V2PDU_ASNEncode[2:]

	if SNMPparameters.SNMPparams.SNMPversion != 2 {
		return nil, errors.New("unsupported SNMP version")
	}

	TestAns1Struct := SNMP_Packet_V2{SNMPversion, []byte(SNMPparameters.SNMPparams.Community), pmval}
	MS, MSerr := ASNber.Marshal(TestAns1Struct)
	if MSerr != nil {
		return nil, MSerr
	}
	return MS, nil
}

// snmpv2_Walk_WChan performs streaming SNMPv2c GetNext walk via channel.
//
// Identical to SNMPv3_Walk_WChan but uses snmpv2_GetSet (Community auth).
// Non-blocking streaming for large MIB tables.
//
// Usage identical to SNMPv3_Walk_WChan.
func (SNMPparameters *SNMPv3Session) snmpv2_Walk_WChan(Oid []int, ReqType int, CData chan<- ChanDataWErr) {
	var ChanData ChanDataWErr
	OidVarConverted := []SNMP_Packet_V2_Decoded_VarBind{{Oid, SNMPvbNullValue}}
	for a := 0; a < SNMP_MAXIMUMWALK; a++ {
		SNMPGet, SNMPGetErr := SNMPparameters.snmpv2_GetSet(OidVarConverted, ReqType)
		if SNMPGetErr != nil {
			ChanData.Error = SNMPGetErr
			CData <- ChanData
			close(CData)
			return
		}
		//Обходим результат и проверяем не вышли ли из ветки
		for _, val := range SNMPGet {
			//Проверяем не зациклились ли
			if reflect.DeepEqual(Oid, val.RSnmpOID) {
				ChanData.Data = val
				ChanData.Error = fmt.Errorf("OID is not increased")
				CData <- ChanData
				close(CData)
				return
			}
			if InSubTreeCheck(Oid, val.RSnmpOID) == false {
				close(CData)
				return
			} else {
				ChanData.Data = val
				ChanData.Error = nil
				CData <- ChanData
			}
		}
		if len(SNMPGet) > 0 {
			OidVarConverted[0].RSnmpOID = SNMPGet[len(SNMPGet)-1].RSnmpOID
		} else {
			close(CData)
			return
		}
	}
	close(CData)
	return
}

// snmpv2_Walk performs complete SNMPv2c GetNext walk of MIB subtree.
//
// Identical to SNMPv3_Walk but uses snmpv2_GetSet (Community authentication).
// For legacy devices without SNMPv3 support.
//
// Stops on subtree exit, loop detection, or SNMP_MAXIMUMWALK limit.
func (SNMPparameters *SNMPv3Session) snmpv2_Walk(Oid []int, ReqType int) (SNMPData []SNMP_Packet_V2_Decoded_VarBind, err error) {
	OidVarConverted := []SNMP_Packet_V2_Decoded_VarBind{{Oid, SNMPvbNullValue}}
	var RetVar []SNMP_Packet_V2_Decoded_VarBind
	for a := 0; a < SNMP_MAXIMUMWALK; a++ {
		SNMPGet, SNMPGetErr := SNMPparameters.snmpv2_GetSet(OidVarConverted, ReqType)
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

// SNMPv2_Init creates SNMPv2c session from NetworkDevice config.
//
// Validates and normalizes parameters (retries, timeouts, max-repetitions).
// Copies community string, IP/port, debug level for v2c operations.
//
// Prepares session for snmpv2_GetSet, snmpv2_Walk operations.
func SNMPv2_Init(Ndev NetworkDevice) (SNMPsession *SNMPv3Session, err error) {
	var Session SNMPv3Session
	Session.Debuglevel = Ndev.DebugLevel
	Session.SNMPparams.SNMPversion = Ndev.SNMPparameters.SNMPversion
	Session.IPaddress = Ndev.IPaddress
	Session.Port = Ndev.Port
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
	Session.SNMPparams.Community = Ndev.SNMPparameters.Community

	return &Session, nil
}

// snmpv2_GetSet executes SNMPv2c GET/GETNEXT/GETBULK/SET requests.
//
// Universal entry point for all v2c operations. Handles GetBulk parameters.
// Converts SET values to ASN.1, sends via sendSnmpv2GetRequestPrototype.
//
// Returns decoded VarBinds from response PDU.
func (SNMPparameters *SNMPv3Session) snmpv2_GetSet(oidValue []SNMP_Packet_V2_Decoded_VarBind, Request_Type int) (SNMPretPacket []SNMP_Packet_V2_Decoded_VarBind, err error) {
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

	rts, complexerr := SNMPparameters.sendSnmpv2GetRequestPrototype(OidVarConverted, Request_Type, nonRepeaters, maxRepetitions)
	if complexerr != nil {
		if !errors.As(complexerr, &partialerr) {
			//Not partial error
			ReturnError = complexerr
			return ReturnVal, ReturnError
		}
	}

	ReturnVal = rts.V2PDU.VarBinds
	return ReturnVal, ReturnError
}

// sendSnmpv2GetRequestPrototype sends SNMPv2c request with retry/timeout logic.
//
// Thread-safe (cmux.Lock). Atomic request ID. Progressive timeout (1x,2x...).
// Handles duplicate/wrong-ID responses. Send-once-per-retry optimization.
// Full UDP round-trip: packet → write → progressive read → v2 parser.
//
// Core v2c transport layer with production-grade reliability.
func (SNMPparameters *SNMPv3Session) sendSnmpv2GetRequestPrototype(oidValue []SNMP_Packet_V2_VarBind, ReqType int, nonRepeaters int32, maxRepetitions int32) (SNMPretPacket SNMPv2_DecodePacket, err error) {
	SNMPparameters.cmux.Lock()
	defer SNMPparameters.cmux.Unlock()
	var SNMPpackerv2_FP SNMPv2_DecodePacket
	var errread error
	var recerr SNMPwrongReqID_MsgId_Errors

	LocalRequestId := atomic.LoadInt32(&SNMPparameters.SNMPparams.MessageIDv2)

	MS, MSerr := SNMPparameters.makeSNMPPv2Packet(oidValue, LocalRequestId, ReqType, nonRepeaters, maxRepetitions)
	if MSerr != nil {
		return SNMPpackerv2_FP, MSerr
	}

	p := make([]byte, SNMP_BUFFERSIZE)
	Tmms := time.Duration(SNMPparameters.SNMPparams.TimeoutBtwRepeat) * time.Millisecond

	//Делаем несколько попыток получения данных
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
			errread = SNMPparameters.conn.SetWriteDeadline(time.Now().Add(Tmms))
			if errread != nil {
				continue
			}
			writedn, errread = SNMPparameters.conn.Write(MS)
			if errread != nil || writedn != len(MS) {
				continue
			}
			//Запрос послан успешно
			//сбросим флаг посылки
			SendRequest = false
		}

		rlen := 0
		//Ожидаем данные не позднее Текущее время плюс TMs
		rlen, errread = SNMPparameters.conn.Read(p)
		if errread == nil {
			//Пакет получен, разберем его
			SNMPpackerv2_FP, errread = receiverV2parser(SNMPparameters, p[:rlen], true, LocalRequestId)
			if errread != nil {
				if errors.As(errread, &recerr) {
					if recerr.ErrorStatusCode == PARCE_ERR_WRONGMSGID || recerr.ErrorStatusCode == PARCE_ERR_WRONGREQID {
						//Принял ответ, но это дубликат или неправильный ID
						//Просто ждем следующего пакета
						continue
					}
				} else {
					return SNMPpackerv2_FP, errread
				}
			}
			break
		} else {
			var nerror net.Error
			if errors.As(errread, &nerror) {
				//Ошибка как "net.Error"
				if nerror.Timeout() {
					//Истек таймаут
					//установим флаг повторной посылки
					SendRequest = true
				}
			}
			//Какая-то ошибка чтения, но не истечение таймаута
			continue
		}
	}
	return SNMPpackerv2_FP, errread
}

// sendV2ACK sends SNMPv2c RESPONSE acknowledgement to agent.
//
// NEW CONNECTION per ACK (not session reuse). Uses sysUpTime OID with null value.
// Matches request ID for correlation. Single-shot UDP dial+send for trap/inform ACK.
//
// For SNMPv2-INFORM reliability (RFC 1905) - agent expects RESPONSE PDU.
func (SNMPparameters *SNMPv3Session) sendV2ACK(requestid int32) (err error) {
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

	MS, lasterr := SNMPparameters.makeSNMPPv2Packet(OidVarConverted, requestid, SNMPv2_REQUEST_RESPONSE, 0, 0)
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
		lasterr = fmt.Errorf("SNMPv2 Write error")
	}
	return lasterr
}
