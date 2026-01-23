//go:build !integration

// PowerSNMPv3 - SNMP library for Go
// Автор: Волков Олег, ООО "Пауэр Си"
// Author: Volkov Oleg, PowerC LLC
// License: MIT (commercial version with support available)
// Лицензия: MIT (доступна коммерческая версия с поддержкой)
package PowerSNMPv3

import (
	"reflect"
	"slices"
	"testing"
)

func TestConvert_Variable_To_String(t *testing.T) {
	tests := []struct {
		name string
		var_ SNMPVar // ← var_ вместо var
		want string
	}{
		{
			name: "OctetString",
			var_: SNMPVar{ValueClass: 0, ValueType: 4, Value: []byte("TestVal123")},
			want: "TestVal123",
		},
		{
			name: "INTEGER",
			var_: SNMPVar{ValueClass: 0, ValueType: 2, Value: []byte{0, 7}},
			want: "7",
		},
		{
			name: "IPADDR",
			var_: SNMPVar{ValueClass: 1, ValueType: 0, Value: []byte{192, 168, 21, 119}},
			want: "192.168.21.119",
		},
		{
			name: "TIMETICKS",
			var_: SNMPVar{ValueClass: 1, ValueType: 3, Value: []byte{120}},
			want: "1.2s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Convert_Variable_To_String(tt.var_)
			if got != tt.want {
				t.Errorf("Convert_Variable_To_String() = %q; want %q", got, tt.want)
			}
		})
	}
}

func TestConvert_ClassTag_to_String(t *testing.T) {
	TypeIs := Convert_ClassTag_to_String(SNMPVar{ValueClass: 1, ValueType: 1})
	if TypeIs != "COUNTER32" {
		t.Errorf("Wrong classtag converted: %s!", TypeIs)
	}
}

func TestConvert_bytearray_to_int(t *testing.T) {
	intcoverted := Convert_bytearray_to_int([]byte{255, 255, 248, 148})
	if intcoverted != -1900 {
		t.Errorf("Error in TestConvert_bytearray_to_int, try to convert: []byte{255,255,248,148} to int, expected -1900, but got: %d", intcoverted)
	}
	intcoverted2 := Convert_bytearray_to_int([]byte{195})
	if intcoverted2 != -61 {
		t.Errorf("Error in TestConvert_bytearray_to_int, try to convert: []byte{255,255,248,148} to int, expected -1900, but got: %d", intcoverted2)
	}
}

func TestConvert_bytearray_to_uint(t *testing.T) {
	intcoverted := Convert_bytearray_to_uint([]byte{255, 248, 148})
	if intcoverted != 16775316 {
		t.Errorf("Error in TestConvert_bytearray_to_int, try to convert: []byte{255,255,248,148} to int, expected 16775316, but got: %d", intcoverted)
	}
	intcoverted2 := Convert_bytearray_to_uint([]byte{195})
	if intcoverted2 != 195 {
		t.Errorf("Error in TestConvert_bytearray_to_int, try to convert: []byte{255,255,248,148} to int, expected 195, but got: %d", intcoverted2)
	}
}

func TestConvert_OID_IntArrayToString_DER(t *testing.T) {
	//69533774
	TestIntArry := []byte{1, 3, 6, 0x86, 0x8d, 0x1f, 2, 1, 47, 1, 3, 2, 1, 2, 0x86, 0x8d, 0x1f, 1}
	Str2 := Convert_OID_IntArrayToString_DER(Convert_bytearray_to_intarray(TestIntArry))
	if Str2 != "1.3.6.99999.2.1.47.1.3.2.1.2.99999.1" {
		t.Errorf("Error in TestConvert_bytearray_to_int, try to convert: []byte{1, 3, 6, 0x86, 0x8d, 0x1f, 2, 1, 47, 1, 3, 2, 1, 2, 0x86, 0x8d, 0x1f, 1} to int, expected 1.3.6.99999.2.1.47.1.3.2.1.2.99999.1, but got: %s", Str2)
	}
}

func TestConvert_OID_IntArrayToString_RAW(t *testing.T) {
	TestIntArry := []byte{1, 3, 6, 0x86, 0x8d, 0x1f, 2, 1, 47, 1, 3, 2, 1, 2, 0x86, 0x8d, 0x1f, 1}
	Str2 := Convert_OID_IntArrayToString_RAW(Convert_bytearray_to_intarray(TestIntArry))
	if Str2 != "1.3.6.134.141.31.2.1.47.1.3.2.1.2.134.141.31.1" {
		t.Errorf("Error in TestConvert_bytearray_to_int, try to convert: []byte{1, 3, 6, 0x86, 0x8d, 0x1f, 2, 1, 47, 1, 3, 2, 1, 2, 0x86, 0x8d, 0x1f, 1} to int, expected 1.3.6.134.141.2.1.47.1.3.2.1.2.134.141.1, but got: %s", Str2)
	}
}

func TestConvert_bytearray_to_intarray_with_multibyte_data(t *testing.T) {
	TestIntArry := []byte{1, 3, 6, 0x86, 0x8d, 0x1f, 2, 1, 47, 1, 3, 2, 1, 2, 0x86, 0x8d, 0x1f, 1}
	TestIntiArry := []int{1, 3, 6, 99999, 2, 1, 47, 1, 3, 2, 1, 2, 99999, 1}
	IntArry := Convert_bytearray_to_intarray_with_multibyte_data(TestIntArry)
	if !reflect.DeepEqual(IntArry, TestIntiArry) {
		t.Error("Error in TestConvert_bytearray_to_int, try to convert: []byte{1, 3, 6, 0x86, 0x8d, 0x1f, 2, 1, 47, 1, 3, 2, 1, 2, 0x86, 0x8d, 0x1f, 1} to int, expected [1 3 6 99999 2 1 47 1 3 2 1 2 99999 1], but got", IntArry)
	}
}

func TestConvert_snmpint_to_int32(t *testing.T) {
	TestInt16SignedArray := []byte{0xf6, 0x31}
	ConvertetData := Convert_snmpint_to_int32(TestInt16SignedArray)
	if ConvertetData != -2511 {
		t.Errorf("Get value %d", ConvertetData)
	}
	TestInt16SignedArray2 := []byte{195}
	ConvertetData2 := Convert_snmpint_to_int32(TestInt16SignedArray2)
	if ConvertetData2 != -61 {
		t.Errorf("Get value %d", ConvertetData2)
	}
}

func TestConvert_snmpint_to_uint32(t *testing.T) {
	TestInt16SignedArray := []byte{0xf6, 0x31}
	ConvertetData := Convert_snmpint_to_uint32(TestInt16SignedArray)
	if ConvertetData != 63025 {
		t.Errorf("Get value %d", ConvertetData)
	}
	TestInt16SignedArray2 := []byte{195}
	ConvertetData2 := Convert_snmpint_to_uint32(TestInt16SignedArray2)
	if ConvertetData2 != 195 {
		t.Errorf("Get value %d", ConvertetData2)
	}
}

func TestConvert_Covert_OID_StringToIntArray_DER(t *testing.T) {
	TestStrOid := ".1.3.6"
	ConvertetData, _ := Convert_OID_StringToIntArray_DER(TestStrOid)
	if !reflect.DeepEqual(ConvertetData, []int{1, 3, 6}) {
		t.Errorf("Get value %d", ConvertetData)
	}
}

func TestParseOID(t *testing.T) {
	TestStrOid := ".1.3.6.abc.6"
	_, ConvErr := ParseOID(TestStrOid)
	if ConvErr == nil {
		t.Errorf("Do not get error but OID is wrong")
	}
	TestStrOid = "1.3.6.134.141.31.2.1.47.1.3.2.1.2.134.141.31.1"
	TestIntArry := []int{1, 3, 6, 134, 141, 31, 2, 1, 47, 1, 3, 2, 1, 2, 134, 141, 31, 1}
	intoid, cverr := ParseOID(TestStrOid)
	if cverr != nil {
		t.Error(ConvErr)
	}
	if !slices.Equal(intoid, TestIntArry) {
		t.Errorf("Get value %d", intoid)
	}

}
