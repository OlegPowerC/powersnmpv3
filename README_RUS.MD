# PowerSNMPv3
[![Go Report Card](https://goreportcard.com/badge/github.com/OlegPowerC/powersnmpv3)](https://goreportcard.com/report/github.com/OlegPowerC/powersnmpv3)
[![GoDoc](https://godoc.org/github.com/OlegPowerC/powersnmpv3?status.svg)](https://godoc.org/github.com/OlegPowerC/powersnmpv3)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)  


**SNMP v2c/v3 библиотека на чистом Go**

Автор: Волков Олег, ООО "Пауэр Си"
Лицензия: MIT (доступна коммерческая версия с поддержкой)
Контакт: oleg@powerc.ru

---

## Особенности

- Поддержка SNMPv2c и SNMPv3
- Аутентификация: MD5, SHA, SHA-224, SHA-256, SHA-384, SHA-512
- Шифрование: DES, AES-128, AES-192, AES-256 (включая варианты AGENT++)
- SNMP операции: Get, GetMulti, Set, SetMulti, Walk, BulkWalk
- Потоковые операции через каналы: Walk_WChan, BulkWalk_WChan
- Прием TRAP/INFORM с автоматическим ACK
- Минимальные зависимости: только `github.com/OlegPowerC/asn1modsnmp`
- Обработка частичных ошибок (partial errors)

---

## Установка

```bash
go get github.com/OlegPowerC/powersnmpv3
```

---

## Быстрый старт

### SNMPv3 Get

```
package main

import (
    "fmt"
    "log"

    snmp "github.com/OlegPowerC/powersnmpv3"
)

func main() {
    device := snmp.NetworkDevice{
        IPaddress: "192.168.1.1",
        Port:      161,
        SNMPparameters: snmp.SNMPUserParameters{
            SNMPversion:      3,
            Username:         "snmpuser",
            AuthProtocol:     "sha",
            AuthKey:          "authpass123",
            PrivProtocol:     "aes",
            PrivKey:          "privpass123",
            RetryCount:       3,
            TimeoutBtwRepeat: 500,
        },
    }

    sess, err := snmp.SNMP_Init(device)
    if err != nil {
        log.Fatal(err)
    }
    defer sess.Close()

    // sysDescr.0
    oid, _ := snmp.Convert_OID_StringToIntArray_RAW("1.3.6.1.2.1.1.1.0")
    result, err := sess.SNMP_Get(oid)
    if err != nil {
        log.Fatal(err)
    }

    for _, vb := range result {
        fmt.Printf("%s = %s\n",
            snmp.Convert_OID_IntArrayToString_RAW(vb.RSnmpOID),
            snmp.Convert_Variable_To_String(vb.RSnmpVar))
    }
}
```

### SNMPv2c Get

```
device := snmp.NetworkDevice{
    IPaddress: "192.168.1.1",
    Port:      161,
    SNMPparameters: snmp.SNMPUserParameters{
        SNMPversion:      2,
        Community:        "public",
        RetryCount:       3,
        TimeoutBtwRepeat: 500,
    },
}

sess, err := snmp.SNMP_Init(device)
// ...
```

---

## Типы данных

### NetworkDevice

Конфигурация устройства для инициализации сессии.

```
type NetworkDevice struct {
    IPaddress      string             // IP адрес устройства
    Port           int                // UDP порт (обычно 161)
    SNMPparameters SNMPUserParameters // Параметры SNMP
    DebugLevel     uint8              // Уровень отладки (0-3)
}
```

### SNMPUserParameters

Параметры SNMP сессии.

```
type SNMPUserParameters struct {
    SNMPversion      int    // 2 для v2c, 3 для v3
    Username         string // Имя пользователя (v3)
    AuthKey          string // Пароль аутентификации (v3)
    AuthProtocol     string // "md5", "sha", "sha224", "sha256", "sha384", "sha512"
    PrivKey          string // Пароль шифрования (v3)
    PrivProtocol     string // "des", "aes", "aes192", "aes256", "aes192a", "aes256a"
    ContextName      string // Контекст SNMPv3 (опционально)
    RetryCount       int    // Количество повторов (1-10, по умолчанию 3)
    TimeoutBtwRepeat int    // Таймаут между повторами в мс (по умолчанию 300)
    MaxRepetitions   uint16 // Макс. повторений для BulkWalk (по умолчанию 25)
    Community        string // Community string (v2c)
}
```

### SNMPv3Session

Активная SNMP сессия. Создается через `SNMP_Init()`.

```
type SNMPv3Session struct {
    IPaddress  string
    Port       int
    Debuglevel uint8
    SNMPparams SNMPParameters
    // ... внутренние поля
}
```

### SNMP_Packet_V2_Decoded_VarBind

Результат SNMP запроса - пара OID и значение.

```
type SNMP_Packet_V2_Decoded_VarBind struct {
    RSnmpOID []int   // OID как массив int
    RSnmpVar SNMPVar // Значение переменной
}
```

### SNMPVar

SNMP переменная с типом и значением.

```
type SNMPVar struct {
    ValueType  int    // Тип значения (ASN.1 tag)
    ValueClass int    // Класс (Universal, Application, Context, Private)
    IsCompound bool   // Составной тип (SEQUENCE и т.п.)
    Value      []byte // Сырое значение
}
```

### ChanDataWErr

Результат для потоковых операций через каналы.

```
type ChanDataWErr struct {
    Data  SNMP_Packet_V2_Decoded_VarBind // Данные
    Error error                          // Ошибка (nil если OK)
}
```

### SNMPTrapParameters

Параметры для приема TRAP/INFORM.

```
type SNMPTrapParameters struct {
    SNMPversion  int    // 2 или 3
    Username     string // Имя пользователя (v3)
    AuthKey      string // Пароль аутентификации
    AuthProtocol string // Протокол аутентификации
    PrivKey      string // Пароль шифрования
    PrivProtocol string // Протокол шифрования
    Community    string // Community (v2c)
}
```

---

## Публичные функции

### Инициализация и закрытие сессии

#### SNMP_Init

Создает и инициализирует SNMP сессию. Для SNMPv3 выполняет Engine Discovery.

```
func SNMP_Init(Ndev NetworkDevice) (*SNMPv3Session, error)
```

**Параметры:**
- `Ndev` - конфигурация устройства

**Возвращает:**
- `*SNMPv3Session` - указатель на сессию
- `error` - ошибка инициализации или nil

**Пример:**
```
sess, err := snmp.SNMP_Init(device)
if err != nil {
    log.Fatal("Init failed:", err)
}
defer sess.Close()
```

#### Close

Закрывает UDP соединение и освобождает ресурсы.

```
func (s *SNMPv3Session) Close() error
```

---

### Операции чтения

#### SNMP_Get

Выполняет SNMP GET запрос для одного OID.

```
func (s *SNMPv3Session) SNMP_Get(Oid []int) ([]SNMP_Packet_V2_Decoded_VarBind, error)
```

**Параметры:**
- `Oid` - OID как массив int (используйте `Convert_OID_StringToIntArray_RAW`)

**Возвращает:**
- `[]SNMP_Packet_V2_Decoded_VarBind` - массив с одним результатом
- `error` - фатальная ошибка или nil

**Пример:**
```
oid, _ := snmp.Convert_OID_StringToIntArray_RAW("1.3.6.1.2.1.1.1.0")
result, err := sess.SNMP_Get(oid)
```

#### SNMP_GetMulti

Выполняет SNMP GET запрос для нескольких OID в одном PDU.

```
func (s *SNMPv3Session) SNMP_GetMulti(OidVar []SNMP_Packet_V2_Decoded_VarBind) ([]SNMP_Packet_V2_Decoded_VarBind, error)
```

**Параметры:**
- `OidVar` - массив VarBind с заполненными OID (поле `RSnmpOID`)

**Возвращает:**
- `[]SNMP_Packet_V2_Decoded_VarBind` - результаты
- `error` - может быть частичная ошибка (`SNMPne_Errors`) или фатальная

**Пример:**
```
oids := []snmp.SNMP_Packet_V2_Decoded_VarBind{
    {RSnmpOID: oid1},
    {RSnmpOID: oid2},
    {RSnmpOID: oid3},
}
results, err := sess.SNMP_GetMulti(oids)
```

#### SNMP_Walk

Выполняет полный SNMP Walk поддерева с помощью GETNEXT.

```
func (s *SNMPv3Session) SNMP_Walk(oid []int) ([]SNMP_Packet_V2_Decoded_VarBind, error)
```

**Параметры:**
- `oid` - корневой OID поддерева

**Возвращает:**
- `[]SNMP_Packet_V2_Decoded_VarBind` - все значения в поддереве
- `error` - ошибка или nil

**Пример:**
```
// Walk ifDescr (1.3.6.1.2.1.2.2.1.2)
oid, _ := snmp.Convert_OID_StringToIntArray_RAW("1.3.6.1.2.1.2.2.1.2")
interfaces, err := sess.SNMP_Walk(oid)
for _, iface := range interfaces {
    fmt.Println(snmp.Convert_Variable_To_String(iface.RSnmpVar))
}
```

#### SNMP_BulkWalk

Выполняет высокопроизводительный SNMP Walk с помощью GETBULK.

```
func (s *SNMPv3Session) SNMP_BulkWalk(oid []int) ([]SNMP_Packet_V2_Decoded_VarBind, error)
```

**Параметры и возврат** аналогичны `SNMP_Walk`.

Использует `MaxRepetitions` для получения нескольких значений за один запрос.

#### SNMP_Walk_WChan

Потоковый Walk через канал. Результаты отправляются по мере получения.

```
func (s *SNMPv3Session) SNMP_Walk_WChan(oid []int, CData chan<- ChanDataWErr)
```

**Параметры:**
- `oid` - корневой OID
- `CData` - канал для результатов (закрывается по завершении)

**Пример:**
```
ch := make(chan snmp.ChanDataWErr)
go sess.SNMP_Walk_WChan(oid, ch)

for result := range ch {
    if result.Error != nil {
        log.Println("Error:", result.Error)
        continue
    }
    fmt.Printf("%s = %s\n",
        snmp.Convert_OID_IntArrayToString_RAW(result.Data.RSnmpOID),
        snmp.Convert_Variable_To_String(result.Data.RSnmpVar))
}
```

#### SNMP_BulkWalk_WChan

Потоковый BulkWalk через канал.

```
func (s *SNMPv3Session) SNMP_BulkWalk_WChan(oid []int, CData chan<- ChanDataWErr)
```

Аналогично `SNMP_Walk_WChan`, но использует GETBULK.

---

### Операции записи

#### SNMP_Set

Выполняет SNMP SET для одного OID.

```
func (s *SNMPv3Session) SNMP_Set(Oid []int, VBvalue SNMPVar) ([]SNMP_Packet_V2_Decoded_VarBind, error)
```

**Параметры:**
- `Oid` - OID для записи
- `VBvalue` - значение (создайте через `SetSNMPVar_*` функции)

**Возвращает:**
- `[]SNMP_Packet_V2_Decoded_VarBind` - результат SET
- `error` - ошибка или nil

**Пример:**
```
oid, _ := snmp.Convert_OID_StringToIntArray_RAW("1.3.6.1.2.1.1.6.0") // sysLocation
value := snmp.SetSNMPVar_OctetString("Server Room A1")
result, err := sess.SNMP_Set(oid, value)
```

#### SNMP_SetMulti

Выполняет SNMP SET для нескольких OID в одном PDU.

```
func (s *SNMPv3Session) SNMP_SetMulti(OidVar []SNMP_Packet_V2_Decoded_VarBind) ([]SNMP_Packet_V2_Decoded_VarBind, error)
```

---

### Функции создания значений для SET

#### SetSNMPVar_OctetString

Создает SNMP OctetString.

```
func SetSNMPVar_OctetString(str string) SNMPVar
```

#### SetSNMPVar_Int

Создает SNMP Integer.

```
func SetSNMPVar_Int(ival int32) SNMPVar
```

#### SetSNMPVar_IpAddr

Создает SNMP IpAddress.

```
func SetSNMPVar_IpAddr(ipval net.IP) (SNMPVar, error)
```

---

### Функции конвертации

#### Convert_OID_StringToIntArray

Конвертирует строку OID в BER-кодированный массив int.

```
func Convert_OID_StringToIntArray(OIDStr string) ([]int, error)
```

**Пример:**
```
oid, err := snmp.Convert_OID_StringToIntArray("1.3.6.1.2.1.1.1.0")
// oid = []int{43, 6, 1, 2, 1, 1, 1, 0} (BER encoded)
```

#### Convert_OID_StringToIntArray_RAW

Конвертирует строку OID в "сырой" массив int (без BER кодирования).  
Она используется для конвертации строкорого OID в []int для передачи функциям Ge/Set/Walk

```
func Convert_OID_StringToIntArray_RAW(OIDStr string) ([]int, error)
```

**Пример:**
```
oid, err := snmp.Convert_OID_StringToIntArray_RAW("1.3.6.1.2.1.1.1.0")
// oid = []int{1, 3, 6, 1, 2, 1, 1, 1, 0}
```

#### Convert_OID_IntArrayToString_RAW

Конвертирует массив int обратно в строку OID.

```
func Convert_OID_IntArrayToString_RAW(OIDIntArray []int) string
```

**Пример:**
```
str := snmp.Convert_OID_IntArrayToString_RAW([]int{1, 3, 6, 1, 2, 1, 1, 1, 0})
// str = "1.3.6.1.2.1.1.1.0"
```

#### Convert_Variable_To_String

Конвертирует SNMPVar в человекочитаемую строку.

```
func Convert_Variable_To_String(Var SNMPVar) string
```

Автоматически определяет тип и форматирует:
- OctetString → строка
- Integer → число
- Counter32/64, Gauge32 → число
- TimeTicks → число
- IpAddress → "x.x.x.x"
- OID → "1.3.6.1..."

#### Convert_ClassTag_to_String

Возвращает название типа ASN.1/SNMP.

```
func Convert_ClassTag_to_String(Var SNMPVar) string
```

**Пример:**
```
typeStr := snmp.Convert_ClassTag_to_String(varbind.RSnmpVar)
// "Universal OCTET STRING", "Application COUNTER32", etc.
```

---

### Обработка TRAP/INFORM

#### ParseTrapUsername

Быстрое извлечение имени пользователя или community из TRAP пакета.

```
func ParseTrapUsername(packet []byte) (version int, username string, v3secdata SNMPv3_SecSeq, err error)
```

**Возвращает:**
- `version` - версия SNMP (1 для v2c, 3 для v3)
- `username` - имя пользователя (v3) или community (v2c)
- `v3secdata` - данные безопасности v3 (EngineID, Boots, Time)
- `err` - ошибка парсинга

#### ParseTrapWithCredentials

Полный разбор TRAP/INFORM с проверкой аутентификации и расшифровкой.

```
func ParseTrapWithCredentials(
    SenderIp string,
    SenderPort int,
    packet []byte,
    UserData SNMPTrapParameters,
    debuglevel uint8,
) (decodedversion int, messagetype int, decryptedData SNMP_Packet_V2_decoded_PDU, err error)
```

**Параметры:**
- `SenderIp`, `SenderPort` - адрес отправителя
- `packet` - сырой UDP пакет
- `UserData` - учетные данные для расшифровки
- `debuglevel` - уровень отладки

**Возвращает:**
- `decodedversion` - версия SNMP
- `messagetype` - тип (1=REPORT, 2=TRAP, 3=INFORM)
- `decryptedData` - расшифрованные данные PDU
- `err` - ошибка

**Константы типов сообщений:**
```
const (
    REPORT_MESSAGE = 1
    TRAP_MESSAGE   = 2
    INFORM_MESSAGE = 3
)
```

---

### Вспомогательные функции

#### InSubTreeCheck

Проверяет, находится ли OID в поддереве.

```
func InSubTreeCheck(OidMain []int, OidCurrent []int) bool
```

**Пример:**
```
main := []int{1, 3, 6, 1, 2, 1}
current := []int{1, 3, 6, 1, 2, 1, 1, 1}
inTree := snmp.InSubTreeCheck(main, current) // true
```

#### SNMPErrorIntToText

Конвертирует код ошибки SNMP в текст.

```
func SNMPErrorIntToText(code int) string
```

#### SNMPPDUErrorIntToText

Конвертирует код ошибки PDU в текст.

```
func SNMPPDUErrorIntToText(code int) string
```

---

## Обработка ошибок

Библиотека различает **фатальные** и **частичные** ошибки.

### Типы ошибок

#### SNMPfe_Errors - Фатальные ошибки

Операция полностью провалилась. Результаты недоступны.

```
type SNMPfe_Errors struct {
    ErrorStatusRaw int32  // Код ошибки SNMP
    ErrorIndexRaw  int32  // Индекс проблемного OID
    FailedOID      []int  // OID вызвавший ошибку
    RequestType    uint32 // Тип запроса
}
```

Примеры: таймаут сети, ошибка аутентификации, `notWritable`.

#### SNMPne_Errors - Частичные ошибки

Часть запроса выполнена успешно. **Результаты доступны!**

```
type SNMPne_Errors struct {
    Failedoids []PowerSNMPv3_Errors_FailedOids_Error
}

type PowerSNMPv3_Errors_FailedOids_Error struct {
    Failedoid []int // OID с ошибкой
    Error_id  int   // Код ошибки (noSuchInstance, etc.)
}
```

Примеры: `noSuchInstance`, `noSuchObject` для некоторых OID в GetMulti.

### ParseError - Унифицированный анализ ошибок

Функция `ParseError` помогает определить тип ошибки:

```
func ParseError(err error) (SNMPerr SNMPud_Errors, CommonError error)
```

**Возвращает:**

```
type SNMPud_Errors struct {
    IsFatal bool             // true = фатальная, false = частичная
    Oids    []SNMPud_OidError // Список проблемных OID
}

type SNMPud_OidError struct {
    Failedoid        []int  // Проблемный OID
    Error_id         int32  // Код ошибки
    ErrorDescription string // Описание ошибки
}
```

**Пример использования:**

```
results, err := sess.SNMP_GetMulti(oids)
if err != nil {
    snmpErr, commonErr := snmp.ParseError(err)

    if commonErr != nil {
        // Сетевая ошибка, криптография и т.п.
        log.Fatal("Network/system error:", commonErr)
    }

    if snmpErr.IsFatal {
        // Фатальная SNMP ошибка
        log.Fatal("Fatal SNMP error:", snmpErr.Oids[0].ErrorDescription)
    }

    // Частичная ошибка - результаты доступны!
    log.Printf("Partial error, %d OIDs failed:", len(snmpErr.Oids))
    for _, oidErr := range snmpErr.Oids {
        log.Printf("  - %s: %s",
            snmp.Convert_OID_IntArrayToString_RAW(oidErr.Failedoid),
            oidErr.ErrorDescription)
    }
}

// Обрабатываем успешные результаты
for _, vb := range results {
    // ...
}
```

---

## Примеры

### SNMP Walk CLI (examples/SNMPWalk.go)

Утилита командной строки для SNMP Walk.

```bash
# SNMPv3 Walk
go run examples/SNMPWalk.go -h 192.168.1.1 -v 3 \
    -u snmpuser -a sha -A authpass -x aes -X privpass \
    -o 1.3.6.1.2.1.2.2.1.2

# SNMPv3 BulkWalk
go run examples/SNMPWalk.go -h 192.168.1.1 -v 3 \
    -u snmpuser -a sha -A authpass -x aes -X privpass \
    -o 1.3.6.1.2.1.2.2.1.2 -bulk

# SNMPv2c Walk
go run examples/SNMPWalk.go -h 192.168.1.1 -v 2 -c public \
    -o 1.3.6.1.2.1.2.2.1.2
```

### TRAP/INFORM Receiver (examples/TrapInformReceiver.go)

Приемник TRAP и INFORM сообщений с поддержкой SNMPv3.

```
// Настройка учетных данных
Userv3Map := make(map[string]*snmp.SNMPTrapParameters)
Userv3Map["snmpuser"] = &snmp.SNMPTrapParameters{
    Username:     "snmpuser",
    AuthProtocol: "sha",
    AuthKey:      "authpass123",
    PrivProtocol: "aes",
    PrivKey:      "privpass123",
}

// Прием пакета
conn, _ := net.ListenPacket("udp", ":162")
n, addr, _ := conn.ReadFrom(buff)

// Парсинг
version, msgtype, data, err := snmp.ParseTrapWithCredentials(
    addr.IP.String(), addr.Port, buff[:n], credentials, 0)
```

Тестирование с net-snmp:
```bash
# SNMPv3 INFORM
snmpinform -v 3 -u snmpuser -a sha -A authpass123 \
    -l authPriv -x aes -X privpass123 \
    -e 0x80001f8880f7996d5a41965d69 192.168.1.100 42 coldStart.0

# SNMPv2c INFORM
snmpinform -v 2c -c public 192.168.1.100 42 coldStart.0
```

---

## Тестирование

### Требования

Для полного тестирования требуется **реальное SNMP устройство** (коммутатор, маршрутизатор).

### Запуск тестов

```bash
go test -v -args \
    -h <IP_УСТРОЙСТВА> \
    -u <SNMP_USER> \
    -a <AUTH_PROTO> \
    -A <AUTH_PASS> \
    -x <PRIV_PROTO> \
    -X <PRIV_PASS> \
    -c <COMMUNITY>
```

**Пример:**
```bash
go test -v -args -h 192.168.1.252 -u SNMPv3-U -a sha -A test123 -x aes -X test321 -c private123
```

### Что тестируется

1. **Unit тесты** (не требуют устройства):
   - `TestConvert_Variable_To_String` - конвертация значений
   - `TestConvert_ClassTag_to_String` - определение типов
   - `TestConvert_bytearray_to_int` - конвертация чисел
   - `TestConvert_bytearray_to_uint` - конвертация unsigned
   - `TestCovert_OID_IntArrayToString` - конвертация OID
   - `TestCovert_OID_IntArrayToString_RAW` - конвертация OID RAW
   - `TestConvert_bytearray_to_intarray_with_multibyte_data` - multibyte OID
   - `TestConvert_snmpint_to_int32` - SNMP int32
   - `TestConvert_snmpint_to_uint32` - SNMP uint32
   - `TestConvert_Covert_OID_StringToIntArray` - строка в OID
   - `Test_PKCS5Padding` - PKCS5 padding/unpadding

2. **Интеграционные тесты** (требуют устройства):
   - `TestSNMPv3Session_SNMP_Get_Set_Walk`:
     - SNMPv2c GET (чтение sysLocation)
     - SNMPv2c SET (запись sysLocation)
     - SNMPv3 инициализация с Engine Discovery
     - SNMPv3 GET (чтение sysLocation)
     - SNMPv3 SET (запись sysLocation)
     - Верификация V2→V3 (проверка что SET v2 виден из v3)
     - SNMPv3 Walk (ifDescr)
     - SNMPv3 BulkWalk (ifDescr)

### Ожидаемый результат

```
=== RUN   TestConvert_Variable_To_String
--- PASS: TestConvert_Variable_To_String (0.00s)
...
=== RUN   TestSNMPv3Session_SNMP_Get_Set_Walk
1.3.6.1.2.1.1.6.0 = Test location : Universal OCTET STRING
    snmpfunc_test.go:55: 59 <nil>
1.3.6.1.2.1.1.6.0 = Test location from V2 : Universal OCTET STRING
    snmpfunc_test.go:88: 67 <nil>
    snmpfunc_test.go:93: V2→V3 VERIFICATION PASS! 'Test location from V2'
1.3.6.1.2.1.2.2.1.2.1 = Vlan1 : Universal OCTET STRING
...
--- PASS: TestSNMPv3Session_SNMP_Get_Set_Walk (0.75s)
PASS
ok      github.com/OlegPowerC/powersnmpv3       2.273s
```

---

## Константы

### Протоколы аутентификации

| Константа | Значение | Строка |
|-----------|----------|--------|
| AUTH_PROTOCOL_NONE | 0 | - |
| AUTH_PROTOCOL_MD5 | 1 | "md5" |
| AUTH_PROTOCOL_SHA | 2 | "sha" |
| AUTH_PROTOCOL_SHA224 | 3 | "sha224" |
| AUTH_PROTOCOL_SHA256 | 4 | "sha256" |
| AUTH_PROTOCOL_SHA384 | 5 | "sha384" |
| AUTH_PROTOCOL_SHA512 | 6 | "sha512" |

### Протоколы шифрования

| Константа | Значение | Строка |
|-----------|----------|--------|
| PRIV_PROTOCOL_NONE | 0 | - |
| PRIV_PROTOCOL_DES | 2 | "des" |
| PRIV_PROTOCOL_AES128 | 1 | "aes" |
| PRIV_PROTOCOL_AES192 | 3 | "aes192" |
| PRIV_PROTOCOL_AES256 | 4 | "aes256" |
| PRIV_PROTOCOL_AES192A | 5 | "aes192a" (AGENT++) |
| PRIV_PROTOCOL_AES256A | 6 | "aes256a" (AGENT++) |

### Лимиты

| Константа | Значение | Описание |
|-----------|----------|----------|
| SNMP_MAXIMUMWALK | 1000000 | Макс. записей в Walk |
| SNMP_BUFFERSIZE | 2048 | Размер UDP буфера |
| SNMP_MAXTIMEOUT_MS | 1000 | Макс. таймаут |
| SNMP_DEFAULTTIMEOUT_MS | 300 | Таймаут по умолчанию |
| SNMP_MAXIMUM_RETRY | 10 | Макс. повторов |
| SNMP_DEFAULTRETRY | 3 | Повторов по умолчанию |
| SNMP_MAXREPETITION | 80 | Макс. repetitions |
| SNMP_DEFAULTREPETITION | 25 | Repetitions по умолчанию |

---

## Зависимости

- `github.com/OlegPowerC/asn1modsnmp` - форк стандартного `encoding/asn1` с оптимизациями для SNMP:
  - `ShortLengthAllow` - поддержка short-length кодирования (некоторые свитчи, например Moxa)
  - `FindSNMPv3AuthParamsOffset()` - поиск позиции AuthParams для USM верификации
  - `ExtractDataWOTagAndLen()` - извлечение данных без TLV обертки для криптографии

---

## Описание модификации стандартного парсера ASN.1

В функции **parseTagAndLength** две проверки на то что short длина закодирована как short (требование DER)  

			ret.length <<= 8
			ret.length |= int(b)
			if ret.length == 0 {
				// DER requires that lengths be minimal.
				err = StructuralError{"superfluous leading zeros in length"}
				return
			}

И

            // Short lengths must be encoded in short form.
            if ret.length < 0x80 {
            err = StructuralError{"non-minimal length"}
            return
            }

## Производительность

Тестировалось на 15,381 OID (SNMPv3 AES128+SHA, 1Gbps сеть, Cisco S8000v в качестве целевого устройства):

| Implementation                 | Time        | Throughput      | Memory     |
|--------------------------------|-------------|-----------------|------------|
| **PowerSNMPv3 (Channel)** ⭐   | **4.02s**   | **3,827 OID/s** | 12.4 MB    |
| PowerSNMPv3 (Callback)         | 4.46s       | 3,449 OID/s     | **8.8 MB** |
| gosnmp                         | 4.43s       | 3,472 OID/s     | 10.0 MB    |
| net-snmp (C)                   | 6.43s       | 2,393 OID/s     | 8.8 MB     |
| snmp4j (Java)                  | 8.27s       | 1,860 OID/s     | 145.6 MB   |

**PowerSNMP на 37% быстрее net-snmp и использует в 12 раз меньше памяти чем snmp4j.**

## Лицензия

MIT License

Доступна коммерческая версия с расширенной поддержкой.

**Контакт:** oleg@powerc.ru
