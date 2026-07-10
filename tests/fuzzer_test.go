package tests

import (
	"testing"

	ASNber "github.com/OlegPowerC/asn1modsnmp"
	"github.com/OlegPowerC/powersnmpv3"
)

func fuzzSessionV2() *PowerSNMPv3.SNMPv3Session {
	s := &PowerSNMPv3.SNMPv3Session{}
	s.SNMPparams.SNMPversion = 2
	s.SNMPparams.Community = "fuzzcommunity"
	return s
}

func FuzzReceiverV2(f *testing.F) {
	s := fuzzSessionV2()

	oidSys := []int{1, 3, 6, 1, 2, 1, 1, 1, 0}
	oidIf := []int{1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1}

	nullVB := []PowerSNMPv3.SNMP_Packet_V2_VarBind{{oidSys, ASNber.NullRawValue}}
	multiVB := []PowerSNMPv3.SNMP_Packet_V2_VarBind{
		{oidSys, ASNber.NullRawValue},
		{oidIf, PowerSNMPv3.Convert_setvar_toasn1raw(PowerSNMPv3.SetSNMPVar_OctetString("fuzz-seed"))},
	}
	// Exception-varbind noSuchObject: context-specific, tag 0, пустое значение
	excVB := []PowerSNMPv3.SNMP_Packet_V2_VarBind{{oidSys,
		ASNber.RawValue{Class: ASNber.ClassContextSpecific, Tag: PowerSNMPv3.tagERR_noSuchObject}}}

	seeds := []struct {
		vbs        []PowerSNMPv3.SNMP_Packet_V2_VarBind
		reqType    int
		nr, maxRep int32
	}{
		{nullVB, PowerSNMPv3.SNMPv2_REQUEST_GET, 0, 0},
		{nullVB, PowerSNMPv3.SNMPv2_REQUEST_GETNEXT, 0, 0},
		{multiVB, PowerSNMPv3.SNMPv2_REQUEST_RESPONSE, 0, 0},
		{multiVB, PowerSNMPv3.SNMPv2_REQUEST_SET, 0, 0},
		{nullVB, PowerSNMPv3.SNMPv2_REQUEST_GETBULK, 0, 25},
		{multiVB, 6, 0, 0}, // InformRequest
		{multiVB, 7, 0, 0}, // SNMPv2-Trap
		{excVB, PowerSNMPv3.SNMPv2_REQUEST_RESPONSE, 0, 0},
	}
	for _, sd := range seeds {
		pkt, err := s.makeSNMPPv2Packet(sd.vbs, 12345, sd.reqType, sd.nr, sd.maxRep)
		if err != nil {
			f.Fatalf("seed generation failed: %v", err)
		}
		f.Add(pkt)
	}
	// Явные вырожденные seed'ы
	f.Add([]byte{})
	f.Add([]byte{0x30})
	f.Add([]byte{0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF})

	f.Fuzz(func(t *testing.T, data []byte) {
		sess := fuzzSessionV2()

		var vs PowerSNMPv3.SNMP_Packet_V2
		_, _ = ASNber.Unmarshal(data, &vs)

		_, _ = sess.receiverV2parser(data, false, 0)
		_, _ = sess.receiverV2parser(data, true, 12345)
		_, _, _, _ = PowerSNMPv3.ParseTrapUsername(data)
	})
}
