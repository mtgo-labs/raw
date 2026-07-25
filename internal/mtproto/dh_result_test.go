package mtproto

import (
	"errors"
	"testing"

	"github.com/mtgo-labs/raw/tl"
)

func TestVerifyDHGenResult(t *testing.T) {
	var nonce, serverNonce [16]byte
	var newNonce [32]byte
	for index := range nonce {
		nonce[index] = byte(index)
		serverNonce[index] = byte(index + 16)
	}
	for index := range newNonce {
		newNonce[index] = byte(index + 32)
	}
	authKey := AuthKey{ID: 0x1122334455667788}
	tests := []struct {
		name   string
		result tl.MTPSetClientDHParamsAnswerClass
		want   error
	}{
		{name: "ok", result: &tl.MTPDHGenOk{Nonce: nonce, ServerNonce: serverNonce, NewNonceHash1: NewNonceHash(newNonce, 1, authKey.AuxHash)}},
		{name: "retry", result: &tl.MTPDHGenRetry{Nonce: nonce, ServerNonce: serverNonce, NewNonceHash2: NewNonceHash(newNonce, 2, authKey.AuxHash)}, want: ErrDHRetry},
		{name: "fail", result: &tl.MTPDHGenFail{Nonce: nonce, ServerNonce: serverNonce, NewNonceHash3: NewNonceHash(newNonce, 3, authKey.AuxHash)}, want: ErrDHFail},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := VerifyDHGenResult(authKey, nonce, serverNonce, newNonce, test.result); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestVerifyDHGenResultRejectsTampering(t *testing.T) {
	var nonce, serverNonce [16]byte
	var newNonce [32]byte
	result := &tl.MTPDHGenOk{Nonce: nonce, ServerNonce: serverNonce, NewNonceHash1: NewNonceHash(newNonce, 1, 1)}
	if err := VerifyDHGenResult(AuthKey{AuxHash: 2}, nonce, serverNonce, newNonce, result); !errors.Is(err, ErrDHResultInvalid) {
		t.Fatalf("tampered hash error = %v", err)
	}
	if err := VerifyDHGenResult(AuthKey{}, nonce, serverNonce, newNonce, nil); !errors.Is(err, ErrDHResultInvalid) {
		t.Fatalf("nil result error = %v", err)
	}
}
