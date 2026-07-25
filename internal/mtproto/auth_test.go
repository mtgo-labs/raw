package mtproto

import (
	"errors"
	"testing"

	"github.com/mtgo-labs/raw/tl"
)

func TestValidateResPQ(t *testing.T) {
	var nonce, serverNonce [16]byte
	for index := range nonce {
		nonce[index] = byte(index)
		serverNonce[index] = byte(index + 16)
	}
	res := &tl.MTPResPQ{
		Nonce:                       nonce,
		ServerNonce:                 serverNonce,
		PQ:                          []byte{15},
		ServerPublicKeyFingerprints: []int64{int64(testFingerprint)},
	}
	selection, err := ValidateResPQ(&constantReader{value: 7}, nonce, res, false)
	if err != nil {
		t.Fatal(err)
	}
	if selection.P != 3 || selection.Q != 5 || selection.ServerNonce != serverNonce || selection.PublicKey == nil {
		t.Fatalf("selection = %+v", selection)
	}
}

func TestValidateResPQRejectsNonceAndKey(t *testing.T) {
	var nonce [16]byte
	res := &tl.MTPResPQ{Nonce: nonce, PQ: []byte{15}, ServerPublicKeyFingerprints: []int64{1}}
	other := nonce
	other[0] = 1
	if _, err := ValidateResPQ(&constantReader{value: 7}, other, res, false); !errors.Is(err, ErrResPQNonce) {
		t.Fatalf("nonce error = %v", err)
	}
	if _, err := ValidateResPQ(&constantReader{value: 7}, nonce, res, false); !errors.Is(err, ErrResPQKeyNotFound) {
		t.Fatalf("key error = %v", err)
	}
}

type constantReader struct{ value byte }

func (reader *constantReader) Read(output []byte) (int, error) {
	for index := range output {
		output[index] = reader.value
	}
	return len(output), nil
}
