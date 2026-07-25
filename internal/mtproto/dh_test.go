package mtproto

import (
	"crypto/sha1"
	"math/big"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/cryptoutil"
	"github.com/mtgo-labs/raw/tl"
)

func TestDecryptServerDHParamsRejectsMalformedInput(t *testing.T) {
	if _, err := DecryptServerDHParams(&constantReader{value: 1}, [16]byte{}, [32]byte{}, [16]byte{}, nil); err != ErrInvalidDHAnswer {
		t.Fatalf("empty answer error = %v", err)
	}
	if _, err := DecryptServerDHParams(&constantReader{value: 1}, [16]byte{}, [32]byte{}, [16]byte{}, make([]byte, 15)); err != ErrInvalidDHAnswer {
		t.Fatalf("unaligned answer error = %v", err)
	}
}

func TestDecryptServerDHParamsIntegrityAndNonce(t *testing.T) {
	var serverNonce, nonce [16]byte
	var newNonce [32]byte
	for index := range serverNonce {
		serverNonce[index] = byte(index)
		nonce[index] = byte(index + 16)
	}
	for index := range newNonce {
		newNonce[index] = byte(index + 32)
	}
	inner := &tl.MTPServerDHInnerData{
		Nonce:       nonce,
		ServerNonce: serverNonce,
		G:           4,
		DHPrime:     []byte{1},
		GA:          []byte{2},
	}
	encrypted := encryptDHInner(t, serverNonce, newNonce, inner)
	badNonce := nonce
	badNonce[0]++
	if _, err := DecryptServerDHParams(&constantReader{value: 1}, serverNonce, newNonce, badNonce, encrypted); err != ErrDHAnswerNonce {
		t.Fatalf("nonce error = %v", err)
	}
	encrypted[0] ^= 1
	if _, err := DecryptServerDHParams(&constantReader{value: 1}, serverNonce, newNonce, nonce, encrypted); err != ErrDHAnswerIntegrity {
		t.Fatalf("integrity error = %v", err)
	}
}

func TestBuildClientDH(t *testing.T) {
	var nonce, serverNonce [16]byte
	var newNonce [32]byte
	for index := range nonce {
		nonce[index] = byte(index)
		serverNonce[index] = byte(index + 16)
	}
	for index := range newNonce {
		newNonce[index] = byte(index + 32)
	}
	prime := cryptoutil.TelegramDHPrime()
	ga := new(big.Int).Lsh(big.NewInt(1), 1984)
	ga.Add(ga, big.NewInt(1))
	result, err := BuildClientDH(&constantReader{value: 7}, nonce, serverNonce, newNonce, 0, time.Unix(1_700_000_000, 0), &tl.MTPServerDHInnerData{
		Nonce: nonce, ServerNonce: serverNonce, G: 4, DHPrime: prime.Bytes(), GA: ga.Bytes(), ServerTime: 1_700_000_123,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Request == nil || len(result.Request.EncryptedData)%16 != 0 || len(result.GB) != 256 || result.AuthKey.ID == 0 || result.AuthKey.TimeOffset != 123 {
		t.Fatalf("unexpected client DH result: %+v", result)
	}
}

func encryptDHInner(t *testing.T, serverNonce [16]byte, newNonce [32]byte, inner tl.Object) []byte {
	t.Helper()
	encoded, err := tl.Encode(inner)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha1.Sum(encoded)
	plain := append(append([]byte(nil), digest[:]...), encoded...)
	for len(plain)%16 != 0 {
		plain = append(plain, 0)
	}
	key, iv := cryptoutil.DeriveNonceAESKeyIV(serverNonce, newNonce)
	block, err := cryptoutil.NewAES256(key[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := cryptoutil.EncryptIGE(plain, plain, block, iv[:]); err != nil {
		t.Fatal(err)
	}
	return plain
}
