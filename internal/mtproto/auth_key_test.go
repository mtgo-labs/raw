package mtproto

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestNewAuthKey(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, authKeyBytes)
	var serverNonce [16]byte
	var newNonce [32]byte
	for index := range serverNonce {
		serverNonce[index] = byte(index)
		newNonce[index] = byte(index + 16)
	}
	now := time.Unix(1_700_000_000, 0)
	key, err := NewAuthKey(secret, serverNonce, newNonce, 1_700_000_123, now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key.Key[:], secret) || key.TimeOffset != 123 {
		t.Fatalf("unexpected auth-key state: %+v", key)
	}
	if key.ID != 0xf72c20ef89b3d0ae || key.AuxHash != 0x078be57b8d66b461 || key.Salt != [8]byte{16, 16, 16, 16, 16, 16, 16, 16} {
		t.Fatalf("unexpected auth-key ID/salt: %x %x", key.ID, key.Salt)
	}
	secret[0] = 0
	if key.Key[0] != 0x42 {
		t.Fatal("auth key aliases caller buffer")
	}
}

func TestNewAuthKeyRejectsInvalidLength(t *testing.T) {
	if _, err := NewAuthKey(nil, [16]byte{}, [32]byte{}, 0, time.Unix(0, 0)); !errors.Is(err, ErrInvalidAuthKey) {
		t.Fatalf("error = %v, want ErrInvalidAuthKey", err)
	}
}

func TestRestoreAuthKey(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, authKeyBytes)
	key, err := RestoreAuthKey(secret, 7, -12)
	if err != nil {
		t.Fatal(err)
	}
	if key.ID != 7 || key.TimeOffset != -12 || !bytes.Equal(key.Key[:], secret) {
		t.Fatalf("unexpected restored state: %+v", key)
	}
	if _, err := RestoreAuthKey(secret, 0, 0); !errors.Is(err, ErrInvalidAuthKey) {
		t.Fatalf("zero id error=%v", err)
	}
}

func TestNewNonceHash(t *testing.T) {
	var nonce [32]byte
	for index := range nonce {
		nonce[index] = byte(index)
	}
	got := NewNonceHash(nonce, 1, 0x1122334455667788)
	want := [16]byte{0x44, 0x95, 0xfb, 0xc8, 0x85, 0x15, 0x10, 0xfd, 0x40, 0x6d, 0xb9, 0x93, 0x19, 0x01, 0x6a, 0x9f}
	if got != want {
		t.Fatalf("hash = %x, want %x", got, want)
	}
}
