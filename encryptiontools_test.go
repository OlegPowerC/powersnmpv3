//go:build !integration

// PowerSNMPv3 - SNMP library for Go
// Автор: Волков Олег
// Author: Volkov Oleg
// License: MIT
// Лицензия: MIT
// Commercial support and custom development available.
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

func Test3DESEncryptDecryptRoundTrip(t *testing.T) {
	plaintext := []byte("0123456789abcdef") // 16 bytes, no PKCS5 pad in SNMPv3 mode
	key := []byte("12345678abcdefgh87654321") // 24 bytes
	iv := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	ct, err := encrypt3DES(plaintext, key, iv)
	if err != nil {
		t.Fatalf("encrypt3DES: %v", err)
	}
	pt, err := decrypt3DES(ct, key, iv)
	if err != nil {
		t.Fatalf("decrypt3DES: %v", err)
	}
	if !bytesEqual(pt, plaintext) {
		t.Fatalf("3DES round-trip mismatch\ngot  %x\nwant %x", pt, plaintext)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
