//nolint: gocyclo

// PowerSNMPv3 - SNMP library for Go
// Автор: Волков Олег
// Author: Volkov Oleg
// License: MIT
// Лицензия: MIT
// Commercial support and custom development available.

package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	PowerSNMP "github.com/OlegPowerC/powersnmpv3"
)

/*--------------------------------------------------------------------------------------------------------------------
Весь этот код надо вынести в отдельный файл или модуль
--------------------------------------------------------------------------------------------------------------------*/
//Результат одного канала
type Result struct {
	Channel     string `xml:"channel"`
	Value       string `xml:"value"`
	Unit        string `xml:"unit"`
	CustomUnit  string `xml:"CustomUnit"`
	Valuelookup string `xml:"ValueLookup"`
}

// Все тело XML ответа для PRTG
type Prtgbody struct {
	XMLName   xml.Name `xml:"prtg"`
	Error     int      `xml:"error"`
	TextField string   `xml:"text"`
	Res       []Result `xml:"result"`
}

// Выход с ошибкой (вывод ошибки в PRTG)
func ErrorInProgram(err error) {
	var estring string
	estring = fmt.Sprintf("%s", err)
	ErrorToText := &Prtgbody{TextField: estring, Error: 1}
	bolB, _ := xml.Marshal(ErrorToText)
	fmt.Println(string(bolB))
	os.Exit(1)
}

//--------------------------------------------------------------------------------------------------------------------

// Создаем константы с нужными нам OID'ами
const (
	OID_APName       = "1.3.6.1.4.1.14179.2.2.1.1.3"
	OID_AP_OP_Status = "1.3.6.1.4.1.14179.2.2.1.1.6"

	OPSTATUS_OID_NOTFOUND   = 4
	OPSTATUS_NO_INFORMATION = 5

	PRTG_VALUE_LOOKUP_NAME = "C9800AP_OPSTATUS_LOOKUP" //Имя lookup в PRTG
)

// Описываем структуру со списком точек, и эта структура будет сохраняться в XML файл
type AP struct {
	APName              string `xml:"Name"`
	APMAC               string `xml:"MAC"`
	ApStateOid          []int
	ApOperationalStatus int64
}

type Devices struct {
	XMLName xml.Name `xml:"Devices"`
	Devices []AP     `xml:"AP"`
}

type OpstatusData struct {
	FullOID  []int
	OpStatus int64
}

//gocyclo:ignore
func main() {
	WLCIP := flag.String("ip", "", "C9800 ip address")
	SNMPuser := flag.String("u", "", "SNMP username")
	SNMAuth := flag.String("a", "", "SNMP auth protocol")
	SNMAuthPpass := flag.String("A", "", "SNMP auth password")
	SNMPriv := flag.String("x", "", "SNMP priv protocol")
	SNMPrivPpass := flag.String("X", "", "SNMP priv password")
	APListFilename := flag.String("file", "aplist.xml", "File with APs")
	flag.Parse()

	//Извлекаем путь к папке откуда запускается сенсор
	ex, err := os.Executable()
	if err != nil {
		ErrorInProgram(err)
	}

	var devicesipstn Devices

	//Создаем описание устройства
	var C9800 PowerSNMP.NetworkDevice
	C9800.IPaddress = *WLCIP
	C9800.Port = 161
	C9800.SNMPparameters.Username = *SNMPuser
	C9800.SNMPparameters.SNMPversion = 3
	C9800.SNMPparameters.AuthProtocol = *SNMAuth
	C9800.SNMPparameters.PrivProtocol = *SNMPriv
	C9800.SNMPparameters.AuthKey = *SNMAuthPpass
	C9800.SNMPparameters.PrivKey = *SNMPrivPpass

	//Инициализируем SNTP сессию
	SNMPc9800dev, SNMPc9800Err := PowerSNMP.SNMP_Init(C9800)
	if SNMPc9800Err != nil {
		ErrorInProgram(SNMPc9800Err)
	}

	//Проверяем существует ли файл
	exPath := filepath.Dir(ex)
	_, err = os.Stat(exPath + "\\" + *APListFilename)
	if os.IsNotExist(err) {
		//Не существует, тогда делаем поиск точек

		//Конвертируем нужный OID из строки в нужный вид
		APNamesOIDint, cmerr := PowerSNMP.ParseOID(OID_APName)
		if cmerr != nil {
			//Тут на раннем этапе мы уже можем понять что в OID ошибка не производя запрос, это отличает библиотеку от gosnmp
			ErrorInProgram(cmerr)
		}

		APlist, APListErr := SNMPc9800dev.SNMP_BulkWalk(APNamesOIDint)
		if APListErr != nil {
			ErrorInProgram(APListErr)
		}

		//Перебираем данные
		for _, cuap := range APlist {
			if len(cuap.RSnmpOID) == (len(APNamesOIDint) + 6) {
				//Нам нужны 6 последних байт из возвращенного OID'а
				APMAC := cuap.RSnmpOID[len(APNamesOIDint):]
				//Переводим MAC в строку
				MACst := fmt.Sprintf("%d.%d.%d.%d.%d.%d", APMAC[0], APMAC[1], APMAC[2], APMAC[3], APMAC[4], APMAC[5])
				//И имя точки (значение, которое мы сконвертируем в строку)
				APName := PowerSNMP.Convert_Variable_To_String(cuap.RSnmpVar)
				//Добавляем точку в список
				Capn := AP{APName: APName, APMAC: MACst}
				devicesipstn.Devices = append(devicesipstn.Devices, Capn)
			}
		}

		xmlFile, errfr := os.Create(exPath + "\\" + *APListFilename)
		if errfr != nil {
			ErrorInProgram(errfr)
		}
		defer xmlFile.Close()

		xmlWriter := io.Writer(xmlFile)

		enc := xml.NewEncoder(xmlWriter)
		enc.Indent("  ", "  ")
		if err := enc.Encode(devicesipstn); err != nil {
			fmt.Printf("error: %v\n", err)
		}
		xmlFile.Close()
	} else {
		//Файл существует, загружаем данные в структуру
		xmlFile, errfr := os.Open(exPath + "\\" + *APListFilename)
		if errfr != nil {
			ErrorInProgram(errfr)
		}
		defer xmlFile.Close()
		byteValue, _ := io.ReadAll(xmlFile)
		umerr := xml.Unmarshal(byteValue, &devicesipstn)
		if umerr != nil {
			ErrorInProgram(umerr)
		}
	}

	var APstatoids []PowerSNMP.SNMP_Packet_V2_Decoded_VarBind

	//Теперь перебираем все точки и опрашиваем нужные OID'ы
	for capindex, curap := range devicesipstn.Devices {
		var MACiData []int
		MACDt := strings.Split(curap.APMAC, ".")
		for _, MBc := range MACDt {
			Id, Ie := strconv.Atoi(MBc)
			if Ie != nil {
				ErrorInProgram(Ie)
			}
			MACiData = append(MACiData, Id)
		}
		//Конвертируем нужный OID из строки в нужный вид
		APStatusOIDint, cmerr := PowerSNMP.ParseOID(OID_AP_OP_Status)
		if cmerr != nil {
			ErrorInProgram(cmerr)
		}
		//Добавляем к OID'у MAC и добавим его к записи об устройстве, оно нам еще пригодится
		APStatusOIDint = append(APStatusOIDint, MACiData...)
		devicesipstn.Devices[capindex].ApStateOid = APStatusOIDint

		//Сохраняем дабы потом опросить одним запросом
		APstatoids = append(APstatoids, PowerSNMP.SNMP_Packet_V2_Decoded_VarBind{RSnmpOID: APStatusOIDint, RSnmpVar: PowerSNMP.SNMPvbNullValue})
	}
	//Теперь создаем разпрос на все OID'ы сразу:
	AllApStat, AllApStatErr := SNMPc9800dev.SNMP_GetMulti(APstatoids)

	//Результат нужен в виде OID и значение
	OpStDataOIDs := make([]OpstatusData, 0)

	//Теперь обработаем ошибки, чтобы понять по какому из OID небыла получена информация:
	if AllApStatErr != nil {
		PErr, Cerr := PowerSNMP.ParseError(AllApStatErr)
		if Cerr != nil {
			ErrorInProgram(Cerr)
		}
		if PErr.IsFatal {
			if Cerr != nil {
				ErrorInProgram(Cerr)
			} else {
				ferr := ""
				for _, descr := range PErr.Oids {
					ferr = descr.ErrorDescription
				}
				fatalperr := fmt.Errorf("Fatal SNMP error: %s", ferr)
				ErrorInProgram(fatalperr)
			}
		} else {
			for _, EmptOids := range PErr.Oids {
				OpStDataOIDs = append(OpStDataOIDs, OpstatusData{FullOID: EmptOids.Failedoid, OpStatus: OPSTATUS_OID_NOTFOUND})
			}
		}
	}

	//Теперь обработаем все безошибочные данные
	for _, APOpstatusCrnt := range AllApStat {
		if PowerSNMP.IsInteger(APOpstatusCrnt.RSnmpVar) {
			StatusIVal := PowerSNMP.Convert_bytearray_to_int(APOpstatusCrnt.RSnmpVar.Value)
			OpStDataOIDs = append(OpStDataOIDs, OpstatusData{FullOID: APOpstatusCrnt.RSnmpOID, OpStatus: StatusIVal})
		}
	}

	//Теперь у нас есть все данные о статусах и данные о том на какие OID'ы ответы не получены.
	//Осталось свести все воедино
	for CAPIndex, CAP := range devicesipstn.Devices {
		devicesipstn.Devices[CAPIndex].ApOperationalStatus = OPSTATUS_NO_INFORMATION
		for _, StatusResult := range OpStDataOIDs {
			if slices.Equal(CAP.ApStateOid, StatusResult.FullOID) {
				devicesipstn.Devices[CAPIndex].ApOperationalStatus = StatusResult.OpStatus
			}
		}
	}

	//Теперь у нас есть вся информация и можно создать каналы
	var PRTGbodyNormal Prtgbody
	for _, APInfo := range devicesipstn.Devices {
		var PRTGOneChannel Result
		//В качестве имени канала используем имя точки доступа
		PRTGOneChannel.Channel = APInfo.APName
		PRTGOneChannel.Value = fmt.Sprintf("%d", APInfo.ApOperationalStatus)
		PRTGOneChannel.Valuelookup = PRTG_VALUE_LOOKUP_NAME

		//И добавим в результаты
		PRTGbodyNormal.Res = append(PRTGbodyNormal.Res, PRTGOneChannel)
	}

	//Теперь можно вывести результат:
	if len(PRTGbodyNormal.Res) == 0 {
		ErrorInProgram(fmt.Errorf("No data"))
	} else {
		XmlRawData, XMLMarshalErr := xml.Marshal(&PRTGbodyNormal)
		if XMLMarshalErr == nil {
			fmt.Println(string(XmlRawData))
		}
	}
}
