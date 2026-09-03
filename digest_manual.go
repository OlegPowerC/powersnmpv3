//go:build manual_hmac
// +build manual_hmac

package PowerSNMPv3

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"hash"

	ASNber "github.com/OlegPowerC/asn1modsnmp"
)

// makeDigest computes SNMPv3 USM HMAC authentication digest (RFC 3414).
//
// Parameters:
//
//	Wmsg         - Complete SNMPv3 packet bytes (for HMAC input)
//	LocalizedKey - USM localized authentication key (from makeLocalizedKey)
//	AuthProtocol - AUTH_PROTOCOL_* constant (MD5=1, SHA1=2, SHA224=8, SHA256=4, SHA384=5, SHA512=6)
//
// Algorithm:
//  1. Protocol-specific hash init + digest length (MD5/SHA1=12, SHA256=24 bytes, etc)
//  2. 64-byte key padding (RFC 2104): zeros + copy LocalizedKey
//  3. HMAC: (key⊕ipad | msg) → inner → (key⊕opad | inner) → truncate
//
// Returns:
//
//	digest - Truncated HMAC bytes (protocol-specific length)
func makeDigest(Wmsg []byte, LocalizedKey []byte, AuthProtocol int) (digest []byte) {
	var mac hash.Hash
	var digestLen int
	//Default block size
	blockSize := 64

	switch AuthProtocol {
	case AUTH_PROTOCOL_MD5:
		mac = md5.New()
		digestLen = 12
	case AUTH_PROTOCOL_SHA:
		mac = sha1.New()
		digestLen = 12
	case AUTH_PROTOCOL_SHA224:
		mac = sha256.New224()
		digestLen = 16
	case AUTH_PROTOCOL_SHA256:
		mac = sha256.New()
		digestLen = 24
	case AUTH_PROTOCOL_SHA384:
		mac = sha512.New384()
		digestLen = 32
		blockSize = 128
	case AUTH_PROTOCOL_SHA512:
		mac = sha512.New()
		digestLen = 48
		blockSize = 128
	default:
		mac = sha1.New()
		digestLen = 12
		break
	}

	extendedAuthKey := bytes.Repeat([]byte{0x00}, blockSize)
	ipad := bytes.Repeat([]byte{0x36}, blockSize)
	opad := bytes.Repeat([]byte{0x5c}, blockSize)
	copy(extendedAuthKey[:len(LocalizedKey)], LocalizedKey)
	k1 := make([]byte, blockSize)
	k2 := make([]byte, blockSize)
	for i := 0; i < blockSize; i++ {
		k1[i] = extendedAuthKey[i] ^ ipad[i]
		k2[i] = extendedAuthKey[i] ^ opad[i]
	}

	mac.Reset()
	mac.Write(append(k1, Wmsg...))
	mdigest := mac.Sum(nil)
	mac.Reset()
	mac.Write(append(k2, mdigest...))
	mdigestfull := mac.Sum(nil)

	return mdigestfull[:digestLen]
}

// verifyDigestRAW validates SNMPv3 USM auth digest on raw packet bytes (REPLACEMENT).
//
// Finds AuthParams offset/length via ASNber.FindSNMPv3AuthParamsOffset → zero-fill → recalc HMAC → compare.
// **PERFORMANCE**: Direct byte ops, no ASN.1 re-marshaling. Timing-safe constant-time comparison.
// Replaces slower verifyDigest (removed).
//
// Parameters:
//
//	SNMPv3Packet - Complete raw SNMPv3 packet bytes
//	digest       - Received auth digest from packet (12/16/24/32/48 bytes)
//	LocalizedKey - USM localized auth key (RFC 3414)
//	AuthProtocol - AUTH_PROTOCOL_* constant (MD5/SHA1/SHA2 variants)
//
// Returns:
//
//	Verified - true if HMAC matches (auth valid)
//	err      - AuthParam parse error or nil
func verifyDigestRAW(SNMPv3Packet []byte, digest []byte, LocalizedKey []byte, AuthProtocol int) (Verified bool, err error) {
	//Ищем где расположен AuthParam
	offset, aplen, ferr := ASNber.FindSNMPv3AuthParamsOffset(SNMPv3Packet)
	if ferr != nil {
		return false, ferr
	}

	//Если смещение равно 0 или оно указывает за пределы пакета то ошибка
	if offset == 0 || offset+aplen > len(SNMPv3Packet) {
		return false, errors.New("AuthParam not found")
	}

	DataCopy := make([]byte, len(SNMPv3Packet))
	copy(DataCopy, SNMPv3Packet)

	for i := 0; i < aplen; i++ {
		DataCopy[offset+i] = 0x00
	}

	DigestCalc := makeDigest(DataCopy, LocalizedKey, AuthProtocol)

	if len(DigestCalc) != len(digest) {
		return false, nil
	}
	if subtle.ConstantTimeCompare(DigestCalc, digest) == 1 {
		return true, nil
	}
	return false, nil
}
