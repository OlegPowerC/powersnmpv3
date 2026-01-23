//go:build !integration

// PowerSNMPv3 - SNMP library for Go
// Автор: Волков Олег, ООО "Пауэр Си"
// Author: Volkov Oleg, PowerC LLC
// License: MIT (commercial version with support available)
// Лицензия: MIT (доступна коммерческая версия с поддержкой)
package PowerSNMPv3

import (
	"crypto/des"
	"testing"
)

func Test_PKCS5Padding(t *testing.T) {
	TestSequence1 := []byte{0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x02}
	t.Log("Data before padding:", TestSequence1)
	blocksise := des.BlockSize
	PaddedData, perr := fPKCS5Padding(TestSequence1, blocksise, true)
	t.Log("Data after padding:", PaddedData)
	if len(PaddedData) != 16 {
		t.Error("Wrong padding")
	}
	if perr != nil {
		t.Error(perr)
	}
	UnpaddedData, uperr := fPKCS5UnPadding(PaddedData, blocksise, true)
	t.Log("Data after unpadding:", UnpaddedData)
	if len(UnpaddedData) != len(TestSequence1) {
		t.Error("Wrong Unpadding")
	}
	if uperr != nil {
		t.Error(uperr)
	}
}
