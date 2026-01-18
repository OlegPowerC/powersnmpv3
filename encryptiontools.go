// PowerSNMPv3 - SNMP library for Go
// Автор: Волков Олег, ООО "Пауэр Си"
// Author: Volkov Oleg, PowerC LLC
// License: MIT (commercial version with support available)
// Лицензия: MIT (доступна коммерческая версия с поддержкой)
package PowerSNMPv3

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"errors"
)

// fPKCS5Padding applies PKCS#5/PKCS#7 padding for SNMPv3 privacy cipher blocks.
//
// Parameters:
//
//	src       - Input plaintext bytes to pad
//	blockSize - Cipher block size (8=DES, 16=AES128/192/256)
//	snmp      - true=SNMPv3 mode (no padding if exact block multiple)
//
// SNMPv3 Behavior:
//   - snmp=true:  Exact multiples → no padding (RFC 3414 scopedPDU requirement)
//   - snmp=false: Standard PKCS#5 (always pad to next block)
//
// Returns:
//
//	data - Padded bytes (exact block multiple)
//	err  - Zero-length input error or nil
func fPKCS5Padding(src []byte, blockSize int, snmp bool) (data []byte, err error) {
	if len(src) == 0 {
		return nil, errors.New("Zero data length")
	}
	if snmp {
		if len(src)%blockSize == 0 {
			return src, nil
		}
	}

	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...), nil
}

// fPKCS5UnPadding removes PKCS#5/PKCS#7 padding from SNMPv3 privacy cipher blocks.
//
// Parameters:
//
//	src       - Padded ciphertext bytes (exact block multiple)
//	blockSize - Cipher block size (8=DES, 16=AES128/192/256)
//	snmp      - true=SNMPv3 mode (lenient unpadding)
//
// SNMPv3 Behavior (snmp=true):
//   - Invalid padding (bad length/values) → return raw data (no error)
//   - No padding expected → return as-is
//   - Valid PKCS5 → strip padding bytes
//
// Standard Behavior (snmp=false):
//   - Strict validation → error on invalid padding
//
// Returns:
//
//	data - Unpadded plaintext bytes
//	err  - Input validation errors (SNMP mode more tolerant)
func fPKCS5UnPadding(src []byte, blockSize int, snmp bool) (data []byte, err error) {
	if len(src) == 0 {
		return nil, errors.New("Zero data length")
	}

	unpadding := int(src[len(src)-1])

	// Если padding выглядит невалидным - возвращаем данные как есть
	if unpadding > blockSize || unpadding <= 0 || unpadding > len(src) {
		if snmp {
			return src, nil // Для SNMP не ошибка, просто нет padding
		} else {
			return nil, errors.New("UnPadding Error")
		}
	}

	// Проверяем, что все байты padding одинаковые (валидация PKCS5)
	for i := 0; i < unpadding; i++ {
		if src[len(src)-1-i] != byte(unpadding) {
			if snmp {
				return src, nil // Невалидный padding - возвращаем как есть
			} else {
				return nil, errors.New("UnPadding Error")
			}
		}
	}
	return src[:(len(src) - unpadding)], nil
}

// encryptAESCFB performs SNMPv3 AES-CFB128 encryption (RFC 3826).
//
// **SUPPORTS**: AES128/192/256 (16/24/32-byte keys)
//
// Parameters:
//
//	src - Plaintext bytes to encrypt (padded scopedPDU)
//	key - AES privacy key (16=AES128, 24=AES192, 32=AES256 bytes)
//	iv  - 16-byte initialization vector (salt + counter)
//
// Algorithm:
//
//	AES-CFB128 mode (8-byte segments) for all key sizes
//	XORKeyStream encryption (no padding, stream cipher semantics)
//
// Returns:
//
//	EncryptedData - CFB-encrypted ciphertext (same length as src)
//	err           - Key/IV length validation or cipher creation errors
func encryptAESCFB(src, key, iv []byte) (EncryptedData []byte, err error) {
	if len(src) == 0 {
		return nil, errors.New("Source data length error")
	}
	if len(iv) != 16 {
		return nil, errors.New("IV length error")
	}
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("Key length error")
	}
	dst := make([]byte, len(src))
	aesBlockEncrypter, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesEncrypter := cipher.NewCFBEncrypter(aesBlockEncrypter, iv)
	aesEncrypter.XORKeyStream(dst, src)
	return dst, nil
}

// decryptAESCFB performs SNMPv3 AES-CFB128 decryption (RFC 3826).
//
// **SUPPORTS**: AES128/192/256 (16/24/32-byte keys)
//
// Parameters:
//
//	src - Encrypted ciphertext bytes (CFB-encrypted scopedPDU)
//	key - AES privacy key (16=AES128, 24=AES192, 32=AES256 bytes)
//	iv  - 16-byte initialization vector (salt + counter)
//
// Algorithm:
//
//	AES-CFB128 decryption (8-byte segments) for all key sizes
//	XORKeyStream decryption (stream cipher semantics, no padding removal)
//
// Returns:
//
//	DecryptedData - Original plaintext bytes (for fPKCS5UnPadding)
//	err           - Key/IV length validation or cipher creation errors
func decryptAESCFB(src, key, iv []byte) (DecryptedData []byte, err error) {
	if len(src) == 0 {
		return nil, errors.New("Source data length error")
	}
	if len(iv) != 16 {
		return nil, errors.New("IV length error")
	}
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("Key length error")
	}
	dst := make([]byte, len(src))
	aesBlockDecrypter, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesDecrypter := cipher.NewCFBDecrypter(aesBlockDecrypter, iv)
	aesDecrypter.XORKeyStream(dst, src)
	return dst, nil
}

// decryptDES performs SNMPv3 DES-CBC decryption (RFC 3414 legacy privacy protocol).
//
// Parameters:
//
//	src - Encrypted ciphertext bytes (CBC-encrypted padded scopedPDU)
//	key - 8-byte DES privacy key (from expandPrivKey, PRIV_PROTOCOL_DES)
//	iv  - 8-byte initialization vector (salt + counter)
//
// Algorithm:
//  1. DES-CBC decryption (8-byte blocks, full validation)
//  2. SNMPv3 PKCS5 unpadding (lenient mode)
//  3. Block alignment check (src%8==0)
//
// Returns:
//
//	DecryptedData - Original unpadded plaintext (scopedPDU)
//	err           - Key/IV length, block alignment, or unpadding errors
func decryptDES(src, key, iv []byte) (DecryptedData []byte, err error) {
	if len(iv) != 8 {
		return DecryptedData, errors.New("IV length error")
	}
	if len(key) != 8 {
		return DecryptedData, errors.New("Key length error")
	}
	if len(src) == 0 || len(src)%8 != 0 {
		return DecryptedData, errors.New("Source length error")
	}
	var ReturnData []byte
	var UnpadingErr error
	desBlockDecrypter, err := des.NewCipher(key)
	if err != nil {
		return ReturnData, err
	}
	ReturnData = make([]byte, len(src))
	desDecrypter := cipher.NewCBCDecrypter(desBlockDecrypter, iv)
	desDecrypter.CryptBlocks(ReturnData, src)
	ReturnData, UnpadingErr = fPKCS5UnPadding(ReturnData, desBlockDecrypter.BlockSize(), true)
	if UnpadingErr != nil {
		return ReturnData, UnpadingErr
	}
	return ReturnData, nil
}

// encryptDES performs SNMPv3 DES-CBC encryption (RFC 3414 legacy privacy protocol).
//
// Parameters:
//
//	src - Plaintext bytes to encrypt (scopedPDU)
//	key - 8-byte DES privacy key (from expandPrivKey, PRIV_PROTOCOL_DES)
//	iv  - 8-byte initialization vector (salt + counter)
//
// Algorithm:
//  1. SNMPv3 PKCS5 padding (no pad if block-aligned)
//  2. DES-CBC encryption (8-byte blocks)
//  3. Full-block encryption (CryptBlocks)
//
// Returns:
//
//	EncryptedData - CBC-encrypted padded ciphertext
//	err           - Key/IV length or cipher/padding errors
func encryptDES(src, key, iv []byte) (EncryptedData []byte, err error) {
	if len(iv) != 8 {
		return EncryptedData, errors.New("IV length error")
	}
	if len(key) != 8 {
		return EncryptedData, errors.New("Key length error")
	}
	var ReturnData []byte
	desBlockEncrypter, err := des.NewCipher(key)
	if err != nil {
		return ReturnData, err
	}
	PaddedData, PadingErr := fPKCS5Padding(src, desBlockEncrypter.BlockSize(), true)
	if PadingErr != nil {
		return ReturnData, PadingErr
	}
	ReturnData = make([]byte, len(PaddedData))
	desEncrypter := cipher.NewCBCEncrypter(desBlockEncrypter, iv)
	desEncrypter.CryptBlocks(ReturnData, PaddedData)
	return ReturnData, nil
}
