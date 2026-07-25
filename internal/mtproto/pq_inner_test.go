package mtproto

import (
	"testing"

	"github.com/mtgo-labs/raw/tl"
)

func TestBuildPQInnerData(t *testing.T) {
	var nonce, serverNonce [16]byte
	var newNonce [32]byte
	response := resPQForTest(nonce)
	selection, err := ValidateResPQ(&constantReader{value: 7}, nonce, &response, false)
	if err != nil {
		t.Fatal(err)
	}
	request, err := BuildPQInnerData(&constantReader{value: 7}, selection, []byte{15}, nonce, serverNonce, newNonce, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(request.EncryptedData) != 256 || request.P[0] != 3 || request.Q[0] != 5 || request.PublicKeyFingerprint != int64(selection.Fingerprint) {
		t.Fatalf("unexpected request: %+v", request)
	}
}

func TestBuildPQInnerDataTemp(t *testing.T) {
	var nonce, serverNonce [16]byte
	var newNonce [32]byte
	response := resPQForTest(nonce)
	selection, err := ValidateResPQ(&constantReader{value: 7}, nonce, &response, false)
	if err != nil {
		t.Fatal(err)
	}
	request, err := BuildPQInnerDataTemp(&constantReader{value: 7}, selection, []byte{15}, nonce, serverNonce, newNonce, 2, 3600)
	if err != nil {
		t.Fatal(err)
	}
	if len(request.EncryptedData) != 256 {
		t.Fatalf("temporary request length=%d", len(request.EncryptedData))
	}
	if _, err := BuildPQInnerDataTemp(&constantReader{value: 7}, selection, []byte{15}, nonce, serverNonce, newNonce, 2, 0); err == nil {
		t.Fatal("zero temporary lifetime accepted")
	}
}

var testFingerprint uint64 = 0xb25898df208d2603

func resPQForTest(nonce [16]byte) tl.MTPResPQ {
	return tl.MTPResPQ{Nonce: nonce, PQ: []byte{15}, ServerPublicKeyFingerprints: []int64{int64(testFingerprint)}}
}
