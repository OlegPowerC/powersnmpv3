//go:build !integration

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
	"crypto/sha256"
	"crypto/sha512"
	"testing"
)

func TestMakeDigestSHA512RFC6234(t *testing.T) {
	key := bytes.Repeat([]byte{0x0b}, 64)
	data := []byte("Hi There")
	digest := makeDigest(data, key, AUTH_PROTOCOL_SHA512)
	if len(digest) != 48 {
		t.Fatalf("SHA-512 digest length = %d, want 48", len(digest))
	}

	mac := hmac.New(sha512.New, key)
	mac.Write(data)
	expected := mac.Sum(nil)[:48]
	if !bytes.Equal(expected, digest) {
		t.Fatalf("SHA-512 HMAC mismatch\ngot  %x\nwant %x", digest, expected)
	}
}

func TestMakeDigestSHA384RFC6234(t *testing.T) {
	key := bytes.Repeat([]byte{0x0b}, 48)
	data := []byte("Hi There")
	digest := makeDigest(data, key, AUTH_PROTOCOL_SHA384)
	if len(digest) != 32 {
		t.Fatalf("SHA-384 digest length = %d, want 32", len(digest))
	}

	mac := hmac.New(sha512.New384, key)
	mac.Write(data)
	expected := mac.Sum(nil)[:32]
	if !bytes.Equal(expected, digest) {
		t.Fatalf("SHA-384 HMAC mismatch\ngot  %x\nwant %x", digest, expected)
	}
}

func TestMakeDigestSHA256RFC6234(t *testing.T) {
	key := bytes.Repeat([]byte{0x0b}, 32)
	data := []byte("Hi There")
	digest := makeDigest(data, key, AUTH_PROTOCOL_SHA256)
	if len(digest) != 24 {
		t.Fatalf("SHA-256 digest length = %d, want 24", len(digest))
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	expected := mac.Sum(nil)[:24]
	if !bytes.Equal(expected, digest) {
		t.Fatalf("SHA-256 HMAC mismatch\ngot  %x\nwant %x", digest, expected)
	}
}

func TestExpandPrivKeyReederDiffersFromBlumenthal(t *testing.T) {
	engineID := []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0xf7, 0x99, 0x6d, 0x5a, 0x41, 0x96, 0x5d, 0x69}
	engineKu := bytes.Repeat([]byte{0x11}, 20)

	blumenthal := expandPrivKey(engineKu, PRIV_PROTOCOL_AES256, AUTH_PROTOCOL_SHA, engineID)
	reeder := expandPrivKey(engineKu, PRIV_PROTOCOL_AES256C, AUTH_PROTOCOL_SHA, engineID)
	if len(blumenthal) != 32 {
		t.Fatalf("Blumenthal AES-256 key length = %d, want 32", len(blumenthal))
	}
	if len(reeder) != 32 {
		t.Fatalf("Reeder AES-256C key length = %d, want 32", len(reeder))
	}
	if bytes.Equal(blumenthal, reeder) {
		t.Fatal("Reeder AES-256C key unexpectedly equal to Blumenthal AES-256 key")
	}
}

func TestExpandPrivKeySHA512AES256TruncateOnly(t *testing.T) {
	engineID := []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0xf7, 0x99, 0x6d, 0x5a, 0x41, 0x96, 0x5d, 0x69}
	engineKu := bytes.Repeat([]byte{0x22}, 64)

	aes256 := expandPrivKey(engineKu, PRIV_PROTOCOL_AES256, AUTH_PROTOCOL_SHA512, engineID)
	aes256c := expandPrivKey(engineKu, PRIV_PROTOCOL_AES256C, AUTH_PROTOCOL_SHA512, engineID)
	if !bytes.Equal(aes256, aes256c) {
		t.Fatal("SHA-512 AES-256 and AES-256C keys should both truncate to the first 32 bytes")
	}
	if !bytes.Equal(aes256, engineKu[:32]) {
		t.Fatal("SHA-512 AES-256 key should be the first 32 bytes of Kul")
	}
}

func TestExpandPrivKey3DESLength(t *testing.T) {
	engineID := []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0xf7, 0x99, 0x6d, 0x5a, 0x41, 0x96, 0x5d, 0x69}
	engineKu := bytes.Repeat([]byte{0x33}, 20)
	key := expandPrivKey(engineKu, PRIV_PROTOCOL_3DES, AUTH_PROTOCOL_SHA, engineID)
	if len(key) != 32 {
		t.Fatalf("3DES expanded key length = %d, want 32", len(key))
	}
}

func TestCheckSNMPv3StringParamsAES256C(t *testing.T) {
	_, _, priv, err := CheckSNMPv3StringParams("sha512", "changeme", "aes256c", "changeme")
	if err != nil {
		t.Fatalf("aes256c rejected: %v", err)
	}
	if priv != PRIV_PROTOCOL_AES256C {
		t.Fatalf("priv protocol = %d, want PRIV_PROTOCOL_AES256C (%d)", priv, PRIV_PROTOCOL_AES256C)
	}
}

func TestCheckSNMPv3StringParams3DES(t *testing.T) {
	_, _, priv, err := CheckSNMPv3StringParams("sha", "changeme", "3des", "changeme")
	if err != nil {
		t.Fatalf("3des rejected: %v", err)
	}
	if priv != PRIV_PROTOCOL_3DES {
		t.Fatalf("priv protocol = %d, want PRIV_PROTOCOL_3DES (%d)", priv, PRIV_PROTOCOL_3DES)
	}
}
