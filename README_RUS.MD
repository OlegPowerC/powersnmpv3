![logonw4.jpg](.github/images/logonw4.jpg)

[![Go](https://img.shields.io/badge/go-%3E%3D1.21-blue.svg)](https://pkg.go.dev/github.com/OlegPowerC/powersnmpv3)
[![Go Report Card](https://goreportcard.com/badge/github.com/OlegPowerC/powersnmpv3)](https://goreportcard.com/report/github.com/OlegPowerC/powersnmpv3)
[![PowerSNMPv3 CI](https://github.com/OlegPowerC/powersnmpv3/actions/workflows/ci.yml/badge.svg)](https://github.com/OlegPowerC/powersnmpv3/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![LibHunt](https://img.shields.io/badge/LibHunt-trending-brightgreen)](https://www.libhunt.com/r/powersnmpv3)
[![GitHub stars](https://img.shields.io/github/stars/OlegPowerC/powersnmpv3?style=social)](https://github.com/OlegPowerC/powersnmpv3/stargazers)
[![DEV.to Article](https://img.shields.io/badge/DEV.to-Article-blue)](https://dev.to/olegpowerc/powersnmpv3-a-new-pure-go-snmp-library-with-better-error-handling-10d1)
[![Examples](https://img.shields.io/badge/examples-📂-blue)](./cmd)
[![IPv6](https://img.shields.io/badge/IPv6-Supported-brightgreen)](#)
[![CodeQL](https://github.com/OlegPowerC/powersnmpv3/workflows/CodeQL/badge.svg)](https://github.com/OlegPowerC/powersnmpv3/security/code-scanning)

📖 **Оглавление:**
- [Установка](#Установка)
- [Быстрый старт](#Быстрый-старт)
- [Обработка ошибки несоответствия уровня безопасности](#Обработка-ошибки-несоответствия-уровня-безопасности)
- [Обработка ошибок](#Обработка-ошибок)
- [Протзводительность](#Производительность)
- [Примеры](#Примеры)
---


## PowerSNMPv3

**SNMP v2c/v3 библиотека на чистом Go**

Автор: Волков Олег
Контакт: oleg.powerc@gmail.com
Лицензия: MIT 
Будет доступна коммерческая версия с поддержкой

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
- Поддержка как IPv4 так и Pv6
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
    oid, _ := snmp.ParseOID("1.3.6.1.2.1.1.1.0")
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

### Параметры сессии для работы на различных каналах

| Параметр             | Значение по умолчанию | Описание                                                                                                                                                                                   |
|----------------------|-----------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **TimeoutBtwRepeat** | 300ms                 | с каждой попыткой таймаут увеличивается как: `base × (attempt+1)`: 300→600→900ms                                                                                                           |
| **MaxMsgSize**       | 1360 байт             | Максимальный размер данных (UDP payload), которые агент может передать в одной татаграмме, работа схожа с TCP MSS, подбирая значение под конкретный канал, можно избежать IP фрагментации  |
| **MaxRepetitions**   | 25                    | Максимальное количество строк таблицы за итерацию в GetBulk                                                                                                                                |


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
    SNMPversion      int    // 2 for v2c, 3 for v3
    Username         string // Username (v3)
    AuthKey          string // Authentication password (v3)
    AuthProtocol     string // "md5", "sha", "sha224", "sha256", "sha384", "sha512"
    PrivKey          string // Privacy password (v3)
    PrivProtocol     string // "des", "aes", "aes192", "aes256", "aes192a", "aes256a"
    ContextName      string // SNMPv3 context (optional)
    RetryCount       int    // Retry count (1-10, default 3)
    TimeoutBtwRepeat int    // Timeout between retries in ms (default 300)
    MaxRepetitions   uint16 // Max repetitions for BulkWalk (default 25)
    MaxMsgSize       uint16 // Max SNMP v3 message size
    Community        string // Community string (v2c)
}
```
| Параметр         | тип    | опимание                                                                                                                          |
|------------------|--------|-----------------------------------------------------------------------------------------------------------------------------------|
| SNMPversion      | int    | версия SNMP, 2 для v2c, 3 для v3                                                                                                  |
| Username         | string | Имя пользователя USM для SNMP v3                                                                                                  |
| AuthKey          | string | Ключ аутентификации, для v3                                                                                                       |
| AuthProtocol     | string | Протокол аутентификации "md5", "sha", "sha224", "sha256", "sha384", "sha512"                                                      |
| PrivKey          | string | Ключ шифрования, для v3                                                                                                           |
| PrivProtocol     | string | Протокол шифрования "des", "aes", "aes192", "aes256", "aes192a", "aes256a"                                                        |
| ContextName      | string | Контекст для SNMP v3 (опционально). К примеру для получения MAC адресов в VLAN 10 на коммутаторах Cisco, укажите контекст vlan-10 |
| RetryCount       | int    | Количество попыток запроса (1-10, по умолчанию 3)                                                                                 |
| TimeoutBtwRepeat | int    | Таймаут между запросами (default 300). Используется линейное возрастание таймаута: timeout = base × (attempt + 1)                 |
| MaxRepetitions   | uint16 | Максимальное количество строк таблицы за итерацию в GetBulk (по умолчанию 25)                                                     |
| MaxMsgSize       | Uint16 | Максимальный размер данных (UDP payload), которые агент может передать в одной татаграмме                                         |


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
    ValidData bool                       // Данные действительны
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

### Валидация параметров

#### CheckUserParams

Проверяет параметры агента SNMP.  
Вызывается из SNMP_Init, но может использоваться отдельно.

```
func CheckUserParams(ndev NetworkDevice) error 
```
**Параметры:**
- `Ndev` - конфигурация SNMP агента

**Возвращаемые значения:**
- `error` - ошибка или nil (может быть структурированной или нет)

**Пример:**
```
	dev := NetworkDevice{
	    IPaddress: "192.168.1.1",
	    Port:      161,
	    SNMPparameters: SNMPUserParameters{
	        SNMPversion:  3,
	        Username:     "snmpuser",
	        AuthProtocol: "sha256",
	        AuthKey:      "auth12345",
	        PrivProtocol: "aes",
	        PrivKey:      "priv12345",
	    },
	}
	if err := CheckUserParams(dev); err != nil {
	    var vErr SNMPSetparameters_Errors
	    if errors.As(err, &vErr) {
	        for _, e := range vErr.WrongParameters {
	            log.Printf("%s: %s", e.WrongParameter, e.ExtraMessage)
	        }
	    } else {
	        log.Printf("Critical error: %v", err)
	    }
	    return err
	}
```

#### CheckSNMPv3StringParams

Проверяет строковые параметры SNMPv3 и возвращает нумерованные константы.
Может быть использована, например при создании карты пользователь/параметры NMPv3 в приемнике трапов

```
func CheckSNMPv3StringParams(authproto string, authkey string, privproto string, privkey string) (seclevelInt int, authprotoInt int, privprotoInt int, err error)
```
**Параметры:**
- `authproto`: протокол аутентификации. поддерживаются: "","**none**", "**md5**", "**sha**", "**sha224**", "**sha256**", "**sha384**", "**sha512**".
- `authkey`: пароль аутентификации. Протокол аутентификации должен быть не "**none**". Минимальная длинна: **SNMP_AUTH_PRIV_KEY_MINLEN** символов.
- `privproto`: протокол шифрования. поддерживаются: "**none**", "**des**", "**aes**", "**aes192**", "**aes256**", "**aes192a**", "**aes256a**".
- `privkey`: пароль шифрования. Протокол шифрования должен быть не "**none**". Минимальная длинна: **SNMP_AUTH_PRIV_KEY_MINLEN** символов.
- Empty strings for authproto/privproto are treated as "**none**".

**Возвращаемые значения:**
- `seclevelInt`: SNMPv3 уровень безопасности: 0 = NoAuthNoPriv, 1 = AuthNoPriv, 2 = AuthPriv
- `authprotoInt`: константа протокола аутентификации
- `privprotoInt`: константа протокола шифрования
- `err`: ошибка типа **SNMPSetparameters_Errors**, либо **nil**. Возвращаемые значения верны, если err == nil.

**Пример:**

```
authLevel, authProto, privProto, err := CheckSNMPv3StringParams(
    "sha",
    "auth12345",
    "aes",
    "priv12345678",
)
if err != nil {
    var vErr SNMPSetparameters_Errors
    if errors.As(err, &vErr) {
        for _, e := range vErr.WrongParameters {
            log.Printf("%s: %s", e.WrongParameter, e.ExtraMessage)
        }
    } else {
        log.Printf("Critical error: %v", err)
    }
    return err
}
```


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
- `Oid` - OID как массив int (используйте `ParseOID`)

**Возвращает:**
- `[]SNMP_Packet_V2_Decoded_VarBind` - массив с одним результатом
- `error` - фатальная ошибка или nil

**Пример:**
```
oid, _ := snmp.ParseOID("1.3.6.1.2.1.1.1.0")
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
    {RSnmpOID: oid1, RSnmpVar: snmp.SNMPvbNullValue},
    {RSnmpOID: oid2, RSnmpVar: snmp.SNMPvbNullValue},
    {RSnmpOID: oid3, RSnmpVar: snmp.SNMPvbNullValue},
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
oid, _ := snmp.ParseOID("1.3.6.1.2.1.2.2.1.2")
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
func (s *SNMPv3Session) SNMP_Walk_WChan(ctx context.Context,oid []int, CData chan<- ChanDataWErr)
```

**Параметры:**
- `ctx` - контекст с таймаутом
- `oid` - корневой OID
- `CData` - канал для результатов (закрывается по завершении)

Рекомендация: используйте буферизированный канал и контекст с таймаутом

**Пример:**
```
ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
defer cancel()
ch := make(chan snmp.ChanDataWErr,30000)
go sess.SNMP_Walk_WChan(ctx,oid, ch)

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
func (s *SNMPv3Session) SNMP_BulkWalk_WChan(ctx context.Context,oid []int, CData chan<- ChanDataWErr)
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
oid, _ := snmp.ParseOID("1.3.6.1.2.1.1.6.0") // sysLocation
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

#### ParseOID

Конвертирует строку OID в "сырой" массив int (без BER кодирования).  
Она используется для конвертации строкорого OID в []int для передачи функциям Ge/Set/Walk

```
func ParseOID(OIDStr string) ([]int, error)
```

**Пример:**
```
oid, err := snmp.ParseOID("1.3.6.1.2.1.1.1.0")
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
### Функции проверки типа

Функции проверяют тип SNMP значения. Возвращают `true` если тип данных значения, является соответствующим типом ASN.1.

#### IsBoolean

Проверят является ли SNMPVar классом Universal типом BOOLEAN (Tag 1).
```
func IsBoolean(Val SNMPVar) bool
```

**Подробное описание типа:** Class=0, Constructed=0, Tag=1 (0x01)

**Пример:**
```
if snmp.IsBoolean(varbind.RSnmpVar) {
    fmt.Println("Boolean value:", varbind.RSnmpVar.Value[0] != 0)
}
```

#### IsInteger

Проверят является ли SNMPVar классом Universal типом INTEGER (Tag 2).
```
func IsInteger(Val SNMPVar) bool
```

**Подробное описание типа:** Class=0, Constructed=0, Tag=2 (0x02)

**Пример:**
```
if snmp.IsInteger(varbind.RSnmpVar) {
    value := snmp.Convert_snmpint_to_int32(varbind.RSnmpVar.Value)
    fmt.Println("Integer:", value)
}
```

#### IsBitstring

Проверят является ли SNMPVar классом Universal типом BIT STRING (Tag 3).
```
func IsBitstring(Val SNMPVar) bool
```

**Подробное описание типа:** Class=0, Constructed=0, Tag=3 (0x03)

#### IsOctetString

Проверят является ли SNMPVar классом Universal типом OCTET STRING (Tag 4).
```
func IsOctetString(Val SNMPVar) bool
```

**Подробное описание типа:** Class=0, Constructed=0, Tag=4 (0x04)  
**Используется для:** sysName, sysLocation и прочего

**Пример:**
```
if snmp.IsOctetString(varbind.RSnmpVar) {
    str := string(varbind.RSnmpVar.Value)
    fmt.Println("String:", str)
}
```

#### IsNull

Проверят является ли SNMPVar классом Universal типом NULL (Tag 5).
```
func IsNull(Val SNMPVar) bool
```

**Подробное описание типа:** Class=0, Constructed=0, Tag=5 (0x05)

**Пример:**
```
if snmp.IsNull(varbind.RSnmpVar) {
    fmt.Println("NULL value")
}
```

#### IsOid

Проверят является ли SNMPVar классом Universal типом OID (Tag 6).
```
func IsOid(Val SNMPVar) bool
```

**Подробное описание типа:** Class=0, Constructed=0, Tag=6 (0x06)  
**Used in:** OID value processing

**Пример:**
```
if snmp.IsOid(varbind.RSnmpVar) {
    oidArray := snmp.Convert_bytearray_to_intarray(varbind.RSnmpVar.Value)
    oidStr := snmp.Convert_OID_IntArrayToString_DER(oidArray)
    fmt.Println("OID:", oidStr)
}
```

#### IsIpaddr

Проверят является ли SNMPVar классом Application типом IPADDRESS (Tag 0).
```
func IsIpaddr(Val SNMPVar) bool
```

**Подробное описание типа:** Class=1, Constructed=0, Tag=0 (0x40)  
**Используется для:** ipAdEntAddr, определения типа с IP адресом.

#### IsCounter32

Проверят является ли SNMPVar классом Application типом Counter32 (Tag 1).
```
func IsCounter32(Val SNMPVar) bool
```

**Подробное описание типа:** Class=1, Constructed=0, Tag=1 (0x41)

**Пример:**
```
if snmp.IsCounter32(varbind.RSnmpVar) {
    counter := snmp.Convert_snmpint_to_int32(varbind.RSnmpVar.Value)
    fmt.Printf("Counter32: %d\n", counter)
}
```

#### IsGauge32

Проверят является ли SNMPVar классом Application типом Gauge32 (Tag 2).
```
func IsGauge32(Val SNMPVar) bool
```

**Подробное описание типа:** Class=1, Constructed=0, Tag=2 (0x42)

**Пример:**
```
if snmp.IsGauge32(varbind.RSnmpVar) {
    gauge := snmp.Convert_snmpint_to_int32(varbind.RSnmpVar.Value)
    fmt.Printf("Gauge32: %d\n", gauge)
}
```

#### IsTimetick

Проверят является ли SNMPVar классом Application типом Timeticks (Tag 3).
```
func IsTimetick(Val SNMPVar) bool
```

**Подробное описание типа:** Class=1, Constructed=0, Tag=3 (0x43)  
**Используется для:** sysUpTime.0, прочих значений содержащих время

**Пример:**
```
if snmp.IsTimetick(varbind.RSnmpVar) {
    ticks := snmp.Convert_bytearray_to_int(varbind.RSnmpVar.Value)
    duration := time.Duration(ticks * 10 * time.Millisecond)
    fmt.Println("Uptime:", duration.String())
}
```

#### IsOpaque

Проверят является ли SNMPVar классом Application типом Opaque (Tag 4).
```
func IsOpaque(Val SNMPVar) bool
```

**Подробное описание типа:** Class=1, Constructed=0, Tag=4 (0x44)  
**Используется для:** Бинарных данных

**Пример:**
```
if snmp.IsOpaque(varbind.RSnmpVar) {
    hexStr := hex.EncodeToString(varbind.RSnmpVar.Value)
    fmt.Println("Opaque (hex):", hexStr)
}
```

#### IsCounter64

Проверят является ли SNMPVar классом Application типом Counter64 (Tag 6).
```
func IsCounter64(Val SNMPVar) bool
```

**Подробное описание типа:** Class=1, Constructed=0, Tag=6 (0x46)  
**Используется для:** счетчиков с большой емкостью

**Пример:**
```
if snmp.IsCounter64(varbind.RSnmpVar) {
    counter := snmp.Convert_bytearray_to_uint(varbind.RSnmpVar.Value)
    fmt.Printf("Counter64: %d\n", counter)
}
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

Часть запроса выполнена успешно. **Результаты доступны если AllOIDsFail = false**

```
type SNMPne_Errors struct {
    AllOIDsFail bool
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

### разница в обработке ошибок в gosnmp и PowerSNMPv3 

#### Gosnmp:

**Пример кода:**
```
    fmt.Println("=== MULTI GET ===")
    oids := []string{
    "1.3.6.1.2.1.1.5.0",   // sysName
    "1.3.6.1.2.1.1.6.0",   // sysLocation
    "1.3.6.1.2.1.1.99.0",  // invalid oid (will be noSuchObject)
    "1.3.6.1.2.1.1.100.0", // invalid oid (will be noSuchObject)
    }

	result, err := params.Get(oids)
	fmt.Println("--- Check errors ---")
	if err != nil {
		fmt.Printf("MultiGet ERROR: %v\n", err)
	} else {
		fmt.Println("- NO Errors -")
		fmt.Println("--- Print result ---")
		for i, pdu := range result.Variables {
			fmt.Printf("OID[%d]: %s = ", i, pdu.Name)
			switch pdu.Type {
			case gosnmp.OctetString:
				fmt.Printf("%s\n", string(pdu.Value.([]byte)))
			case gosnmp.NoSuchObject:
				fmt.Printf("NoSuchObject\n")
			default:
				fmt.Printf("%v (%s)\n", pdu.Value, pdu.Type)
			}
		}
	}

	fmt.Println("=== MULTI SET ===")
	vars := []gosnmp.SnmpPDU{
		{
			Name:  "1.3.6.1.2.1.1.6.0", // sysLocation
			Type:  gosnmp.OctetString,
			Value: []byte("Test from gosnmp"),
		},
		{
			Name:  "1.3.6.1.2.1.1.99.0", // Wrong OID
			Type:  gosnmp.OctetString,
			Value: []byte("Should fail"),
		},
	}

	resultSet, err := params.Set(vars)
	fmt.Println("--- Check errors ---")
	if err != nil {
		fmt.Printf("MultiSet ERROR: %v\n", err)
	} else {
		fmt.Println("- NO Errors -")
		fmt.Println("--- Print result ---")
		for i, pdu := range resultSet.Variables {
			fmt.Printf("OID[%d]: %s = ", i, pdu.Name)
			switch pdu.Type {
			case gosnmp.OctetString:
				fmt.Printf("%s\n", string(pdu.Value.([]byte)))
			case gosnmp.NoSuchObject:
				fmt.Printf("NoSuchObject\n")
			default:
				fmt.Printf("%v (%s)\n", pdu.Value, pdu.Type)
			}
		}
	}

	fmt.Println("explicit check errors (resultSet.Error,resultSet.ErrorIndex)", resultSet.Error, resultSet.ErrorIndex)

	fmt.Println("=== Get 1.3.6.1.2.1.1.6.0 ===")
	oids = []string{
		"1.3.6.1.2.1.1.6.0", // sysLocation
	}

	result, err = params.Get(oids)
	if err != nil {
		fmt.Printf("Get ERROR: %v\n", err)
	} else {
		for i, pdu := range result.Variables {
			fmt.Println("- NO Errors -")
			fmt.Println("--- Print result ---")
			fmt.Printf("OID[%d]: %s = ", i, pdu.Name)
			switch pdu.Type {
			case gosnmp.OctetString:
				fmt.Printf("%s\n", string(pdu.Value.([]byte)))
			case gosnmp.NoSuchObject:
				fmt.Printf("NoSuchObject\n")
			default:
				fmt.Printf("%v (%s)\n", pdu.Value, pdu.Type)
			}
		}
	}
```

Результат:

```
=== MULTI GET ===
--- Check errors ---
- NO Errors -
  --- Print result ---
  OID[0]: .1.3.6.1.2.1.1.5.0 = powercsw01.powerc
  OID[1]: .1.3.6.1.2.1.1.6.0 = Test 6.0
  OID[2]: .1.3.6.1.2.1.1.99.0 = NoSuchObject
  OID[3]: .1.3.6.1.2.1.1.100.0 = NoSuchObject
  === MULTI SET ===
  --- Check errors ---
- NO Errors -
  --- Print result ---
  OID[0]: .1.3.6.1.2.1.1.6.0 = Test from gosnmp
  OID[1]: .1.3.6.1.2.1.1.99.0 = Should fail
  explicit check errors (resultSet.Error,resultSet.ErrorIndex) NoCreation 2
  === Get 1.3.6.1.2.1.1.6.0 ===
- NO Errors -
  --- Print result ---
  OID[0]: .1.3.6.1.2.1.1.6.0 = Test 6.0
```

#### PowerSNMPv3:

Пример кода:
```
fmt.Println("=== MULTI GET ===")
OidsStrings := []string{"1.3.6.1.2.1.1.6.0", "1.3.6.1.2.1.1.99.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.100.0"}
OidsConverted := []PowerSNMP.SNMP_Packet_V2_Decoded_VarBind{}

	for _, OidSting := range OidsStrings {
		Ioid, IoidErr := PowerSNMP.Convert_OID_StringToIntArray_RAW(OidSting)
		if IoidErr != nil {
			fmt.Println(IoidErr)
			return
		}
		OidsConverted = append(OidsConverted, PowerSNMP.SNMP_Packet_V2_Decoded_VarBind{Ioid, PowerSNMP.SNMPvbNullValue})
	}
	GetRes2, verr2 := Ssess.SNMP_GetMulti(OidsConverted)

	fmt.Println("--- Check errors ---")
	if verr2 != nil {
		snmpErr, commonErr := PowerSNMP.ParseError(verr2)
		if commonErr != nil {
			// Network error, cryptography, etc.
			fmt.Println("Network/system error:", commonErr)
		}

		if snmpErr.IsFatal {
			// Fatal SNMP error
			fmt.Println("Fatal SNMP error, results are not available")
			for _, descr := range snmpErr.Oids {
				fmt.Println("Error description:", descr.ErrorDescription, descr)
			}
		}

		// Partial error - results are available!
		fmt.Printf("Partial error, %d OIDs failed:", len(snmpErr.Oids))
		for _, oidErr := range snmpErr.Oids {
			fmt.Printf("  | %s", oidErr.ErrorDescription)
		}
		fmt.Println("")
	} else {
		fmt.Println("- NO Errors -")
	}

	fmt.Println("--- Print result ---")
	for _, wl := range GetRes2 {
		fmt.Println(PowerSNMP.Convert_OID_IntArrayToString_RAW(wl.RSnmpOID), "=", PowerSNMP.Convert_Variable_To_String(wl.RSnmpVar), ":", PowerSNMP.Convert_ClassTag_to_String(wl.RSnmpVar))
	}

	fmt.Println("=== MULTI SET ===")
	VarData := []PowerSNMP.SNMPVar{PowerSNMP.SetSNMPVar_OctetString("Test 6.0"), PowerSNMP.SetSNMPVar_OctetString("Test 99.0"), PowerSNMP.SetSNMPVar_OctetString("Test 5.0")}
	SetStringOids := []string{"1.3.6.1.2.1.1.6.0", "1.3.6.1.2.1.1.99.0", "1.3.6.1.2.1.1.5.0"}
	SetDataVB := []PowerSNMP.SNMP_Packet_V2_Decoded_VarBind{}
	if len(VarData) == len(SetStringOids) {
		for VdataInd, StoidS := range SetStringOids {
			IoidS, IoidErrS := PowerSNMP.Convert_OID_StringToIntArray_RAW(StoidS)
			if IoidErrS != nil {
				fmt.Println(IoidErrS)
				return
			}
			SetDataVB = append(SetDataVB, PowerSNMP.SNMP_Packet_V2_Decoded_VarBind{IoidS, VarData[VdataInd]})
		}
	} else {
		fmt.Println("Mismatch oids and data")
		return
	}

	sdata, verres3 := Ssess.SNMP_SetMulti(SetDataVB)
	fmt.Println("--- Check errors ---")
	if verres3 != nil {
		snmpErr, commonErr := PowerSNMP.ParseError(verres3)
		if commonErr != nil {
			// Network error, cryptography, etc.
			fmt.Println("Network/system error:", commonErr)
		}
		if snmpErr.IsFatal {
			// Fatal SNMP error
			fmt.Println("Fatal SNMP error, results are not available")
			for _, descr := range snmpErr.Oids {
				fmt.Println("Error description:", descr.ErrorDescription)
			}
		} else {
			// Partial error - results are available!
			fmt.Printf("Partial error, %d OIDs failed:", len(snmpErr.Oids))
			for _, oidErr := range snmpErr.Oids {
				fmt.Printf("  | %s", oidErr.ErrorDescription)
			}
		}

		fmt.Println("")
	} else {
		fmt.Println("- NO Errors -")
	}

	fmt.Println("--- Print result ---")
	for _, wl := range sdata {
		fmt.Println(PowerSNMP.Convert_OID_IntArrayToString_RAW(wl.RSnmpOID), "=", PowerSNMP.Convert_Variable_To_String(wl.RSnmpVar), ":", PowerSNMP.Convert_ClassTag_to_String(wl.RSnmpVar))
	}
```

Результат:
```
=== MULTI GET ===
--- Check errors ---
Partial error, 2 OIDs failed:  | 1.3.6.1.2.1.1.99.0 (status=128): NoSuchObject  | 1.3.6.1.2.1.1.100.0 (status=128): NoSuchObject
--- Print result ---
1.3.6.1.2.1.1.6.0 = Test 6.0 : Universal OCTET STRING
1.3.6.1.2.1.1.5.0 = powercsw01.powerc : Universal OCTET STRING
=== MULTI SET ===
--- Check errors ---
Fatal SNMP error, results are not available
Error description: 1.3.6.1.2.1.1.99.0 (status=11): CannotCreateVariable

--- Print result ---
```

#### Ключевое отличие:

При операции **Get**:

- **gosnmp** возвращает все VarBinds и пользователь должен самостоятельно проверить из на значения noSuchObject,noSuchInstance,endOfMibView

- **PowerSNMPv3** возвращает не фатальную ошибку, которая содержит информацию о том, какие именно OID'ы содержат значения noSuchObject,noSuchInstance,endOfMibView
  и результат без этих OID'ов

При операции **Set**:

- **gosnmp** Возвращает в результате все VarBinds которые была попытка записать
  Пользователь может некорректно интерпретировать результат, так как в нем содержаться все новые значения.
  Явной ошибки при этом нет.
  Для того чтоб понять успешна операция или нет, пользователь должен проверить значения: resultSet.Error,resultSet.ErrorIndex

- **PowerSNMPv3** Возвращает фатальную ошибку, содержащую OID, значение которого не удалось записать, и причину неудачи
  и пустой результат. Несмотря на то что часть OID возможно можно было бы записать, но SET атомарная операция, и в случае неудачи с каким то одним OID, отменяется вся операция.

---

### Обработка ошибки несоответствия уровня безопасности

PowerSNMPv3 обеспечивает RFC 3414-совместимую обработку ошибки не соответствия уровня безопасности без бесполезных повторов.

#### Метод тестирования

Поведение библиотек проверялось путем простого SNMP Walk опроса агента, с заведомо отличной конфигурацией уровня безопасности SNMP.  
Сценарий тестирования: Клиент настроен только с аутентификацией (authNoPriv or authPriv), на агенте настроен тот же USM пользователь, но уровень безопасности без аутентификации и шифрования. Что встречается в реальной жизни.

Все библиотеки тестировались с одинаковыми настройками (PowerSNMPv3, SNMP4J, gosnmp), трафик был захвачен в PCAP файлы для дальнейшего анализа.

#### Суть проблемы

Несоответствие уровня безопасности происходит тогда, когда клиент настроен с правильным SUM пользователем но например только с аутентификацией, а агент имеет того же USM пользователя но настроен например на работу без аутентификации и шифрования.  
В соответствии с RFC 3414 §3.2, агент должен ответить сообщением REPORT, содержащим значение `usmStatsUnsupportedSecLevels` (OID 1.3.6.1.6.3.15.1.1.1.0). Critically, **REPORT отправляется не зашифрованным и без аутентификации**.

#### Как PowerSNMPv3 обрабатываэт такую ситуацию

##### Фаза Discovery
```
Client → Agent: GetRequest (EngineID discovery, noAuthNoPriv)
Agent → Client: Report (usmStatsUnknownEngineIDs)
  Returns: EngineID, Boots, Time
```

##### Фаза запроса (Security Level Mismatch)
```
Client → Agent: GetRequest/GetBulk
  Flags: 0x05 (Auth, Reportable) или 0x07 (Auth, Priv, Reportable)
  Auth Params: HMAC digest присутствует
  Priv Params: AES/DES IV (если уровень безопасности authPriv)

Agent → Client: Report
  Flags: 0x00 (None) ← Нет аутентификации
  Report OID: 1.3.6.1.6.3.15.1.1.1.0 (usmStatsUnsupportedSecLevels)
  Counter: Увеличивается с каждой идентичной ошибкой

Реакция PowerSNMPv3:
  ✓ Прием REPORT (обработка флагов в сообщении)
  ✓ Проверка OID
  ✓ Возврат ошибки: "unsupported security levels"
  ✓ НЕТ ПОВТОРОВ - ошибка и выход
```

#### RFC 3414 совместимость

PowerSNMPv3 корректно реализует требования RFC 3414:

- **Принимает REPORT без аутентификации** - Даже если клиент ожидает ответов с аутентификацией, REPORT с msgFlags=0x00 принимаетя, так как содержит информацию об ошибке
- **Не делает повторных попыток** - UnsupportedSecLevels не разрешаемая ошибка без изменения настроек; повторные запросы без изменения настроек ничем не помогут
- **Проверяет флаги в сообщении** - Проверяет аутентификацию на основании актуальных данных в сообщении, а не в настройках

#### Классификация ошибок

PowerSNMPv3 разделяет ошибки на **Восстанавливаемые** и **Не восстанавливаемые**:

**Восстанавливаемые** (auto-retry with recovery):
- `usmStatsNotInTimeWindows` - Не соответствие времени, повтор после синхронизации
- `usmStatsUnknownEngineIDs` - Изменился EngineID, повтор после регенерации ключевого материала

**Не восстанавливаемые**:
- `usmStatsUnsupportedSecLevels` - Несоответствие конфигурации
- `usmStatsUnknownUserNames` - Неизвестный USM пользователь
- `usmStatsWrongDigests` - Неправильный ключ аутентификации
- `usmStatsDecryptionErrors` - Неправильный ключ шифрования или протокол

#### Сравнение с другими библиотеками

| Библиотека      | Всего пакетов | Повторов | RFC 3414 совместима | Автоматическая обработка REPORT |
|-----------------|---------------|----------|---------------------|----------------------------|
| **PowerSNMPv3** | **4**         | **0**    | **✅**               | **✅ Yes**                  |
| SNMP4J          | 6             | 1        | ✅                   | ❌ Manual                   |
| gosnmp          | 10            | 3        | ❌                   | ⚠️ Partial                 |

**Эффективность использования канала**: PowerSNMPv3 в общем случае испольщует **на 60% меньше датаграм** чем gosnmp и **на 33% меньше** чем SNMP4J при обработке случая несоответствия уровня безопасности.

---

## Примеры

### SNMP Walk CLI (examples/SNMPWalk.go)

Утилита командной строки для SNMP Walk.

```bash
# SNMPv3 Walk
go run cmd/SNMPWalk.go -h 192.168.1.1 -v 3 \
    -u snmpuser -a sha -A authpass -x aes -X privpass \
    -o 1.3.6.1.2.1.2.2.1.2

# SNMPv3 BulkWalk
go run cmd/SNMPWalk.go -h 192.168.1.1 -v 3 \
    -u snmpuser -a sha -A authpass -x aes -X privpass \
    -o 1.3.6.1.2.1.2.2.1.2 -bulk

# SNMPv2c Walk
go run cmd/SNMPWalk.go -h 192.168.1.1 -v 2 -c public \
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

#### Файлы с примерами находятся в директории **cmd**

---

## Тестирование

### Требования

Для полного тестирования требуется **реальное SNMP устройство** (коммутатор, маршрутизатор).

### Запуск тестов

Укажите tag **checkparams** для проверки валидации параметров.  
Укажите tag **integration** для выполнения тестов на реальном устройстве.

```bash
go test -v -tags=integration -args \
    -h <IP_УСТРОЙСТВА> \
    -u <SNMP_USER> \
    -a <AUTH_PROTO> \
    -A <AUTH_PASS> \
    -x <PRIV_PROTO> \
    -X <PRIV_PASS> \
    -c <COMMUNITY>
```
Для успешного прохождения интеграционного теста, **community** долно быть с правами на запись (**RW**) 
И так же, пользователь SNMPv3 тоже должен иметь права на запись.

**Пример:**
```bash
go test -v -tags=integration -args -h 192.168.1.252 -u snmpuser -a sha -A test123 -x aes -X test321 -c private123
```
Пример с IPv6:  
```bash
go test -v -tags=integration -args -h  2001:db8:1::120 -u snmpuser -a sha -A test123 -x aes -X test321 -c private123
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
   - `TestCheckUserParams` - валидация SNMP параметров
   - `TestSetAuthPrivParamsStToInt` - валидация/конвертация snmp auth/priv параметров
   - `TestCheckParamsIPandPortSNMP` - валидация IP адреса и порта
   - `TestBasicCheckParamsVersionSNMP` - валидация проверки версии SNMP
   - `TestBasicCheckParamsVersion2SNMP` - валидация SNMP v2 параметров

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

В парсере переписана функция поиска длины и смещения данных и добавлены две функции предназначеные для SNMP.
Парсер понимает короткую длинну, закодированную в длинной форме, неопределенную длину (включая вложенную)  
и полностью соответствует BER (но только на разбор данных). Кодировать данные можно в DER

## Производительность

Тестировалось на 15,381 OID (SNMPv3 AES128+SHA, 1Gbps сеть, Cisco S8000v в качестве целевого устройства):

| Implementation              | Time        | Throughput      | Memory     |
|-----------------------------|-------------|-----------------|------------|
| **PowerSNMPv3 (каналы)** ⭐  | **4.02s**   | **3,827 OID/s** | 12.4 MB    |
| PowerSNMPv3 (Callback)      | 4.46s       | 3,449 OID/s     | **8.8 MB** |
| gosnmp                      | 4.43s       | 3,472 OID/s     | 10.0 MB    |
| net-snmp (C)                | 6.43s       | 2,393 OID/s     | 8.8 MB     |
| snmp4j (Java)               | 8.27s       | 1,860 OID/s     | 145.6 MB   |

**PowerSNMP на 37% быстрее net-snmp и использует в 12 раз меньше памяти чем snmp4j.**

## Лицензия

MIT License

Доступна коммерческая версия с расширенной поддержкой.

**Контакт:** oleg.powerc@gmail.com


