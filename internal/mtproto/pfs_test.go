package mtproto

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/cryptoutil"
	"github.com/mtgo-labs/raw/tl"
)

func TestBuildPFSBindingMessage(t *testing.T) {
	permanent, err := RestoreAuthKey(bytes.Repeat([]byte{1}, 256), 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	temporary, err := RestoreAuthKey(bytes.Repeat([]byte{2}, 256), 9, 0)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := BuildPFSBindingMessage(bytes.NewReader(bytes.Repeat([]byte{3}, 128)), permanent, temporary, [8]byte{4}, 100, 11)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 104 || binary.LittleEndian.Uint64(payload[:8]) != permanent.ID {
		t.Fatalf("payload length/id = %d/%d", len(payload), binary.LittleEndian.Uint64(payload[:8]))
	}
	if _, err := BuildPFSBindingMessage(nil, permanent, temporary, [8]byte{}, 100, 11); err == nil {
		t.Fatal("nil random source accepted")
	}
}

func TestPFSBindingReplacesAndExpiresTemporaryKey(t *testing.T) {
	permanent, err := RestoreAuthKey(bytes.Repeat([]byte{1}, 256), 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := RestoreAuthKey(bytes.Repeat([]byte{2}, 256), 9, 0)
	second, _ := RestoreAuthKey(bytes.Repeat([]byte{3}, 256), 11, 0)
	binding, err := NewPFSBinding(permanent)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Unix(200, 0)
	if err := binding.InstallTemporary(first, [8]byte{1}, deadline); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := binding.Current(time.Unix(100, 0)); ok {
		t.Fatal("unbound temporary key reported current")
	}
	if err := binding.MarkBound(); err != nil {
		t.Fatal(err)
	}
	got, sessionID, ok := binding.Current(time.Unix(100, 0))
	if !ok || got.ID != first.ID || sessionID != [8]byte{1} {
		t.Fatalf("current=%d/%x/%v", got.ID, sessionID, ok)
	}
	if err := binding.InstallTemporary(second, [8]byte{2}, time.Unix(300, 0)); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := binding.Current(time.Unix(100, 0)); ok {
		t.Fatal("replacement remained bound")
	}
	if err := binding.MarkBound(); err != nil {
		t.Fatal(err)
	}
	got, _, ok = binding.Current(time.Unix(250, 0))
	if !ok || got.ID != second.ID {
		t.Fatalf("replacement current=%d/%v", got.ID, ok)
	}
	if _, _, ok := binding.Current(time.Unix(300, 0)); ok {
		t.Fatal("expired temporary key reported current")
	}
}

func TestSessionSendPFSBindUsesTemporaryKey(t *testing.T) {
	permanent, _ := RestoreAuthKey(bytes.Repeat([]byte{1}, 256), 7, 0)
	temporary, _ := RestoreAuthKey(bytes.Repeat([]byte{2}, 256), 9, 0)
	binding, err := NewPFSBinding(permanent)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	if err := binding.InstallTemporary(temporary, [8]byte{1}, time.Unix(200, 0)); err != nil {
		t.Fatal(err)
	}
	session := NewSession(temporary, 3, [8]byte{1}, 2)
	var wire bytes.Buffer
	messageID, err := session.SendPFSBind(&wire, bytes.NewReader(bytes.Repeat([]byte{4}, 2048)), now, binding)
	if err != nil {
		t.Fatal(err)
	}
	if messageID == 0 || wire.Len() == 0 || session.Pending() != 1 {
		t.Fatalf("message=%d wire=%d pending=%d", messageID, wire.Len(), session.Pending())
	}
}

func TestBuildPFSBindRequestMatchesInnerMessage(t *testing.T) {
	permanent, _ := RestoreAuthKey(bytes.Repeat([]byte{1}, 256), 7, 0)
	temporary, _ := RestoreAuthKey(bytes.Repeat([]byte{2}, 256), 9, 0)
	const messageID = uint64(0x1122334455667788)
	request, err := BuildPFSBindRequest(
		bytes.NewReader(bytes.Repeat([]byte{3}, 128)),
		permanent, temporary, [8]byte{4}, 200, messageID,
	)
	if err != nil {
		t.Fatal(err)
	}
	key, iv := pfsAESKeyIV(permanent.Key[:], request.EncryptedMessage[8:24])
	block, err := cryptoutil.NewAES256(key[:])
	if err != nil {
		t.Fatal(err)
	}
	plain := append([]byte(nil), request.EncryptedMessage[24:]...)
	if err := cryptoutil.DecryptIGE(plain, plain, block, iv[:]); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(plain[16:24]); got != messageID {
		t.Fatalf("inner message ID=%x", got)
	}
	object, err := tl.Decode(plain[32:72], tl.DefaultDecodeLimits())
	if err != nil {
		t.Fatal(err)
	}
	inner, ok := object.(*tl.MTPBindAuthKeyInner)
	if !ok || inner.Nonce != request.Nonce || inner.TempAuthKeyID != int64(temporary.ID) {
		t.Fatalf("inner=%+v", inner)
	}
}
