package mtproto

import (
	"errors"
	"testing"

	"github.com/mtgo-labs/raw/tl"
)

func TestFinalizeAuthKeyPersistsAfterVerification(t *testing.T) {
	var nonce, serverNonce [16]byte
	var newNonce [32]byte
	authKey := AuthKey{ID: 0x1234, AuxHash: 0x5678}
	result := &tl.MTPDHGenOk{Nonce: nonce, ServerNonce: serverNonce, NewNonceHash1: NewNonceHash(newNonce, 1, authKey.AuxHash)}
	called := false
	if err := FinalizeAuthKey(authKey, nonce, serverNonce, newNonce, result, func(got AuthKey) error {
		called = true
		if got.ID != authKey.ID {
			t.Fatalf("stored key ID = %x", got.ID)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("persistence callback was not called")
	}
}

func TestFinalizeAuthKeyNeverPersistsInvalidResult(t *testing.T) {
	var nonce, serverNonce [16]byte
	var newNonce [32]byte
	called := false
	err := FinalizeAuthKey(AuthKey{ID: 1}, nonce, serverNonce, newNonce, &tl.MTPDHGenOk{}, func(AuthKey) error {
		called = true
		return nil
	})
	if !errors.Is(err, ErrDHResultInvalid) || called {
		t.Fatalf("error=%v callback=%v", err, called)
	}
	if err := FinalizeAuthKey(AuthKey{}, nonce, serverNonce, newNonce, nil, nil); !errors.Is(err, ErrNilAuthKeyStore) {
		t.Fatalf("nil store error = %v", err)
	}
}
