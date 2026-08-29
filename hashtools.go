// PowerSNMPv3 - SNMP library for Go
// Автор: Волков Олег
// Author: Volkov Oleg
// License: MIT
// Лицензия: MIT
// Commercial support and custom development available.
package PowerSNMPv3

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"hash"

	ASNber "github.com/OlegPowerC/asn1modsnmp"
)

func hashForAuthProtocol(AuthProtocol int) hash.Hash {
	switch AuthProtocol {
	case AUTH_PROTOCOL_MD5:
		return md5.New()
	case AUTH_PROTOCOL_SHA:
		return sha1.New()
	case AUTH_PROTOCOL_SHA224:
		return sha256.New224()
	case AUTH_PROTOCOL_SHA256:
		return sha256.New()
	case AUTH_PROTOCOL_SHA384:
		return sha512.New384()
	case AUTH_PROTOCOL_SHA512:
		return sha512.New()
	default:
		return sha1.New()
	}
}

// makeLocalizedKeyFromBytes generates SNMPv3 USM localized authentication key (RFC 3414 STANDARD).
//
// Parameters:
//
//	keyBytes    - Raw password bytes (from string or other source)
//	EngineID    - SNMPv3 EngineID bytes (5-32 bytes, typically 5-13)
//	AuthProtocol- AUTH_PROTOCOL_* constant (MD5=1, SHA1=2, SHA224=3, SHA256=4, SHA384=5, SHA512=6)
//
// Algorithm (1,048,576 bytes processed):
//  1. **1M iterations**: Repeat 64-byte password blocks → hash (16K iterations)
//  2. K1 = hash(password×1M)
//  3. PmKey = K1 | EngineID | K1 (key+engine+key concatenation)
//  4. LocalizedKey = hash(PmKey)
//
// Returns:
//
//	AuthKeyComplete - EngineID-bound localized key (16/20/28/32/48/64 bytes)
func makeLocalizedKeyFromBytes(keyBytes []byte, EngineID []byte, AuthProtocol int) []byte {
	ku := kuFromBytes(keyBytes, AuthProtocol)
	return kulFromKu(ku, EngineID, AuthProtocol)
}

// kuFromBytes runs RFC 3414 password-to-key (1M iterations) without engine localization.
func kuFromBytes(keyBytes []byte, AuthProtocol int) []byte {
	hasf := hashForAuthProtocol(AuthProtocol)

	PassBuf := make([]byte, 64)
	count := 0
	password_index := 0

	passwordlen := len(keyBytes)
	for count < 1048576 {
		for i := 0; i < 64; i++ {
			bind := password_index % passwordlen
			password_index++
			PassBuf[i] = keyBytes[bind]
		}
		hasf.Write(PassBuf)
		count += 64
	}
	return hasf.Sum(nil)
}

// kulFromKu localizes a Ku key with engine ID per RFC 3414.
func kulFromKu(ku []byte, EngineID []byte, AuthProtocol int) []byte {
	hasf := hashForAuthProtocol(AuthProtocol)

	PmKey := make([]byte, (len(ku)*2)+len(EngineID))
	copy(PmKey[0:len(ku)], ku)
	copy(PmKey[len(ku):len(ku)+len(EngineID)], EngineID)
	copy(PmKey[len(ku)+len(EngineID):], ku)

	hasf.Write(PmKey)
	return hasf.Sum(nil)
}

// makeLocalizedKey generates SNMPv3 USM localized authentication key from password string.
//
// Parameters:
//
//	InKey       - Password string (ASCII/UTF-8, typical 8+ chars)
//	EngineID    - SNMPv3 EngineID bytes (5-32 bytes, typically 5-13)
//	AuthProtocol- AUTH_PROTOCOL_* constant (MD5=1, SHA1=2, SHA224=3, SHA256=4, SHA384=5, SHA512=6)
//
// Algorithm:
//
//	Converts string→bytes → calls makeLocalizedKeyFromBytes (RFC 3414 standard KDF, 1M iterations)
//
// Returns:
//
//	LocalizedKey - EngineID-bound authentication key (16/20/28/32/48/64 bytes per protocol)
func makeLocalizedKey(InKey string, EngineID []byte, AuthProtocol int) (LocalizedKey []byte) {
	return makeLocalizedKeyFromBytes([]byte(InKey), EngineID, AuthProtocol)
}

// expandPrivKeyReeder extends a localized priv key using the Reeder draft algorithm
// (Cisco AES192C/AES256C / 3DES / net-snmp _kul_extend_reeder).
func expandPrivKeyReeder(ku []byte, needLen int, authProto int, engineID []byte) []byte {
	if len(ku) >= needLen {
		return ku[:needLen]
	}
	result := make([]byte, needLen)
	kulLen := len(ku)
	copy(result, ku)
	need := needLen - kulLen
	for need > 0 {
		newKu := kuFromBytes(result[:kulLen], authProto)
		newKul := kulFromKu(newKu, engineID, authProto)
		copyLen := need
		if copyLen > len(newKul) {
			copyLen = len(newKul)
		}
		copy(result[kulLen:], newKul[:copyLen])
		kulLen += copyLen
		need -= copyLen
	}
	return result
}

// expandPrivKeyBlumenthal extends a localized key per Blumenthal AES draft (Kul || H(Kul) chaining).
func expandPrivKeyBlumenthal(ku []byte, needLen int, authProto int) []byte {
	if len(ku) >= needLen {
		return ku[:needLen]
	}
	result := make([]byte, needLen)
	kulLen := len(ku)
	copy(result, ku)
	need := needLen - kulLen

	hashBits := len(ku) * 8
	switch authProto {
	case AUTH_PROTOCOL_MD5:
		hashBits = 128
	case AUTH_PROTOCOL_SHA:
		hashBits = 160
	case AUTH_PROTOCOL_SHA224:
		hashBits = 224
	case AUTH_PROTOCOL_SHA256:
		hashBits = 256
	case AUTH_PROTOCOL_SHA384:
		hashBits = 384
	case AUTH_PROTOCOL_SHA512:
		hashBits = 512
	}

	count := (256 + hashBits - 1) / hashBits
	if count < 1 {
		count = 1
	}
	for i := 0; i < count && need > 0; i++ {
		hasher := hashForAuthProtocol(authProto)
		hasher.Write(result[:kulLen])
		h := hasher.Sum(nil)
		copyLen := need
		if copyLen > len(h) {
			copyLen = len(h)
		}
		copy(result[kulLen:], h[:copyLen])
		kulLen += copyLen
		need -= copyLen
	}
	return result
}

func expandPrivKeyAgentPlus(ku []byte, needLen int, authProto int) []byte {
	if len(ku) >= needLen {
		return ku[:needLen]
	}
	result := make([]byte, needLen)
	copy(result, ku)
	hasher := hashForAuthProtocol(authProto)
	hasher.Write(ku)
	k2 := hasher.Sum(nil)
	needed := needLen - len(ku)
	copy(result[len(ku):], k2[:needed])
	return result
}

// expandPrivKey expands authentication key to privacy key size for SNMPv3 USM.
//
// Parameters:
//
//	ku        - Input authentication key bytes (16/20/32+ bytes from localization)
//	privProto - PRIV_PROTOCOL_* constant (AES128/192/256/DES/3DES/AES192A/AES256A/AES192C/AES256C)
//	authProto - AUTH_PROTOCOL_* constant (determines hash for extension)
//	engineID  - SNMPv3 EngineID bytes (for recursive localization)
//
// Algorithms:
//
//	**STANDARD** (AES128/192/256, DES): Truncate or Blumenthal extension
//	**AGENT++/Huawei** (AES192A/256A): K1=ku | K2=hash(ku) simple padding
//	**Cisco/Reeder** (AES192C/256C, 3DES): KDF(Kul) → re-localize → append loop
//
// Returns:
//
//	Privacy key - Exact length bytes (8/16/24/32) ready for encryption
func expandPrivKey(ku []byte, privProto int, authProto int, engineID []byte) []byte {
	switch privProto {
	case PRIV_PROTOCOL_AES128:
		if len(ku) >= 16 {
			return ku[:16]
		}
		return ku

	case PRIV_PROTOCOL_AES192:
		if len(ku) >= 24 {
			return ku[0:24]
		}
		return expandPrivKeyBlumenthal(ku, 24, authProto)

	case PRIV_PROTOCOL_AES256:
		if len(ku) >= 32 {
			return ku[0:32]
		}
		return expandPrivKeyBlumenthal(ku, 32, authProto)

	case PRIV_PROTOCOL_AES192C:
		return expandPrivKeyReeder(ku, 24, authProto, engineID)

	case PRIV_PROTOCOL_AES256C, PRIV_PROTOCOL_3DES:
		return expandPrivKeyReeder(ku, 32, authProto, engineID)

	case PRIV_PROTOCOL_AES192A:
		return expandPrivKeyAgentPlus(ku, 24, authProto)

	case PRIV_PROTOCOL_AES256A:
		return expandPrivKeyAgentPlus(ku, 32, authProto)

	case PRIV_PROTOCOL_DES:
		if len(ku) >= 8 {
			return ku[:8]
		}
		return ku
	}

	if len(ku) >= 16 {
		return ku[:16]
	}
	return ku
}

// makeDigestRFC3414 computes HMAC for MD5 and SHA-1 (RFC 3414 64-byte block).
func makeDigestRFC3414(Wmsg []byte, LocalizedKey []byte, AuthProtocol int) (digest []byte) {
	var digestLen int
	mac := hashForAuthProtocol(AuthProtocol)
	switch AuthProtocol {
	case AUTH_PROTOCOL_MD5, AUTH_PROTOCOL_SHA:
		digestLen = 12
	default:
		digestLen = 12
	}

	extendedAuthKey := bytes.Repeat([]byte{0x00}, 64)
	ipad := bytes.Repeat([]byte{0x36}, 64)
	opad := bytes.Repeat([]byte{0x5c}, 64)
	copy(extendedAuthKey[:len(LocalizedKey)], LocalizedKey)
	k1 := make([]byte, 64)
	k2 := make([]byte, 64)
	for i := 0; i < 64; i++ {
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

// makeDigest computes SNMPv3 USM HMAC authentication digest.
// SHA-2 protocols use RFC 6234 HMAC (RFC 7860); MD5/SHA use RFC 3414.
func makeDigest(Wmsg []byte, LocalizedKey []byte, AuthProtocol int) (digest []byte) {
	switch AuthProtocol {
	case AUTH_PROTOCOL_SHA224:
		mac := hmac.New(sha256.New224, LocalizedKey)
		mac.Write(Wmsg)
		return mac.Sum(nil)[:16]
	case AUTH_PROTOCOL_SHA256:
		mac := hmac.New(sha256.New, LocalizedKey)
		mac.Write(Wmsg)
		return mac.Sum(nil)[:24]
	case AUTH_PROTOCOL_SHA384:
		mac := hmac.New(sha512.New384, LocalizedKey)
		mac.Write(Wmsg)
		return mac.Sum(nil)[:32]
	case AUTH_PROTOCOL_SHA512:
		mac := hmac.New(sha512.New, LocalizedKey)
		mac.Write(Wmsg)
		return mac.Sum(nil)[:48]
	default:
		return makeDigestRFC3414(Wmsg, LocalizedKey, AuthProtocol)
	}
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
	offset, aplen, ferr := ASNber.FindSNMPv3AuthParamsOffset(SNMPv3Packet)
	if ferr != nil {
		return false, ferr
	}

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
