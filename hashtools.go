// PowerSNMPv3 - SNMP library for Go
// Автор: Волков Олег
// Author: Volkov Oleg
// License: MIT
// Лицензия: MIT
// Commercial support and custom development available.
package PowerSNMPv3

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

// makeLocalizedKeyFromBytes generates SNMPv3 USM localized authentication key (RFC 3414 STANDARD).
//
// Parameters:
//
//	keyBytes    - Raw password bytes (from string or other source)
//	EngineID    - SNMPv3 EngineID bytes (5-32 bytes, typically 5-13)
//	AuthProtocol- AUTH_PROTOCOL_* constant (MD5=1, SHA1=2, SHA224=8, SHA256=4, SHA384=5, SHA512=6)
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
	var hasf hash.Hash
	switch AuthProtocol {
	case AUTH_PROTOCOL_MD5:
		hasf = md5.New()
	case AUTH_PROTOCOL_SHA:
		hasf = sha1.New()
	case AUTH_PROTOCOL_SHA224:
		hasf = sha256.New224()
	case AUTH_PROTOCOL_SHA256:
		hasf = sha256.New()
	case AUTH_PROTOCOL_SHA384:
		hasf = sha512.New384()
	case AUTH_PROTOCOL_SHA512:
		hasf = sha512.New()
	default:
		hasf = sha1.New()
	}

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
	finalykey := hasf.Sum(nil)

	PmKey := make([]byte, (len(finalykey)*2)+len(EngineID))
	copy(PmKey[0:len(finalykey)], finalykey)
	copy(PmKey[len(finalykey):len(finalykey)+len(EngineID)], EngineID)
	copy(PmKey[len(finalykey)+len(EngineID):], finalykey)

	hasf.Reset()
	hasf.Write(PmKey)
	AuthKeyComplete := hasf.Sum(nil)
	return AuthKeyComplete
}

// makeLocalizedKey generates SNMPv3 USM localized authentication key from password string.
//
// Parameters:
//
//	InKey       - Password string (ASCII/UTF-8, typical 8+ chars)
//	EngineID    - SNMPv3 EngineID bytes (5-32 bytes, typically 5-13)
//	AuthProtocol- AUTH_PROTOCOL_* constant (MD5=1, SHA1=2, SHA224=8, SHA256=4, SHA384=5, SHA512=6)
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

// expandPrivKey expands authentication key to privacy key size for SNMPv3 USM.
//
// Parameters:
//
//	ku        - Input authentication key bytes (16/20/32+ bytes from localization)
//	privProto - PRIV_PROTOCOL_* constant (AES128/192/256/DES/AES192A/AES256A)
//	authProto - AUTH_PROTOCOL_* constant (determines hash for extension)
//	engineID  - SNMPv3 EngineID bytes (for recursive localization)
//
// Algorithms:
//
//	**STANDARD** (AES128/192/256, DES): Truncate or recursive makeLocalizedKeyFromBytes extension
//	**AGENT++/Huawei** (AES192A/256A): K1=ku | K2=hash(ku) simple padding
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
			// SHA-224/256/384/512 → достаточно байт, просто обрезаем!
			return ku[0:24]
		}
		result := make([]byte, 24)

		if len(ku) >= 20 {
			// SHA-1 (20 байт): рекурсивная локализация
			copy(result[0:20], ku[0:20])
			ext := makeLocalizedKeyFromBytes(ku[0:20], engineID, authProto)
			copy(result[20:24], ext[0:4])
			return result

		} else if len(ku) >= 16 {
			// MD5 (16 байт): тот же метод рекурсивной локализации
			copy(result[0:16], ku[0:16])
			ext := makeLocalizedKeyFromBytes(ku[0:16], engineID, authProto)
			copy(result[16:24], ext[0:8])
			return result
		}

		return result

	case PRIV_PROTOCOL_AES256:
		if len(ku) >= 32 {
			// SHA-256/384/512 → достаточно байт!
			return ku[0:32]
		}

		result := make([]byte, 32)

		if len(ku) >= 20 {
			// SHA-1: рекурсивная локализация
			copy(result[0:20], ku[0:20])
			ext := makeLocalizedKeyFromBytes(ku[0:20], engineID, authProto)
			copy(result[20:32], ext[0:12])
			return result

		} else if len(ku) >= 16 {
			// MD5: тот же метод
			copy(result[0:16], ku[0:16])
			ext := makeLocalizedKeyFromBytes(ku[0:16], engineID, authProto)
			copy(result[16:32], ext[0:16])
			return result
		}

		return result

	case PRIV_PROTOCOL_AES192A:
		// Agent++ метод (Huawei)
		if len(ku) >= 24 {
			// SHA-224/256/384/512 → достаточно байт, просто обрезаем!
			return ku[0:24]
		}

		result := make([]byte, 24)
		copy(result, ku) // K1

		if len(ku) < 24 {
			// K2 = hash(K1)
			var hasher hash.Hash
			switch authProto {
			case AUTH_PROTOCOL_MD5:
				hasher = md5.New()
			case AUTH_PROTOCOL_SHA:
				hasher = sha1.New()
			case AUTH_PROTOCOL_SHA224:
				hasher = sha256.New224()
			case AUTH_PROTOCOL_SHA256:
				hasher = sha256.New()
			case AUTH_PROTOCOL_SHA384:
				hasher = sha512.New384()
			case AUTH_PROTOCOL_SHA512:
				hasher = sha512.New()
			default:
				hasher = sha1.New()
			}
			hasher.Write(ku)
			k2 := hasher.Sum(nil)

			needed := 24 - len(ku)
			copy(result[len(ku):], k2[:needed]) // K1 | K2
		}
		return result

	case PRIV_PROTOCOL_AES256A:
		// Agent++ метод (Huawei)
		if len(ku) >= 32 {
			// SHA-256/384/512 → достаточно байт!
			return ku[0:32]
		}
		result := make([]byte, 32)
		copy(result, ku) // K1

		if len(ku) < 32 {
			// K2 = hash(K1)
			var hasher hash.Hash
			switch authProto {
			case AUTH_PROTOCOL_MD5:
				hasher = md5.New()
			case AUTH_PROTOCOL_SHA:
				hasher = sha1.New()
			case AUTH_PROTOCOL_SHA224:
				hasher = sha256.New224()
			case AUTH_PROTOCOL_SHA256:
				hasher = sha256.New()
			case AUTH_PROTOCOL_SHA384:
				hasher = sha512.New384()
			case AUTH_PROTOCOL_SHA512:
				hasher = sha512.New()
			default:
				hasher = sha1.New()
			}
			hasher.Write(ku)
			k2 := hasher.Sum(nil)

			// Копируем нужное количество байт из K2
			needed := 32 - len(ku)
			copy(result[len(ku):], k2[:needed])
		}
		return result

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
