package mtproto

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/cryptoutil"
	"github.com/mtgo-labs/raw/internal/transport"
	"github.com/mtgo-labs/raw/tl"
)

func TestSessionLifecycle(t *testing.T) {
	authKey, err := NewAuthKey(bytes.Repeat([]byte{0x42}, 256), [16]byte{}, [32]byte{}, 0, testNow())
	if err != nil {
		t.Fatal(err)
	}
	session := NewSession(authKey, 1, [8]byte{6}, 2)
	var wire bytes.Buffer
	if _, err := session.Send(&wire, &constantReader{value: 7}, time.Unix(1_700_000_000, 0), &tl.MTPReqPQMulti{}); err != nil {
		t.Fatal(err)
	}
	if session.Pending() != 1 {
		t.Fatalf("pending = %d", session.Pending())
	}
	if session.Close(ErrSessionClosed) != 1 || session.Pending() != 0 {
		t.Fatal("close did not clear pending state")
	}
	if _, err := session.Send(&wire, &constantReader{value: 7}, time.Unix(1_700_000_001, 0), &tl.MTPReqPQMulti{}); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("closed send error = %v", err)
	}
}

func TestSessionCloseNilErrorFailsPending(t *testing.T) {
	session := NewSession(AuthKey{}, 1, [8]byte{}, 1)
	if _, err := session.pending.Add(1); err != nil {
		t.Fatal(err)
	}
	if session.Close(nil) != 1 {
		t.Fatal("pending request was not closed")
	}
	if session.pending.Len() != 0 {
		t.Fatal("pending table is not empty")
	}
}

func TestSessionReceiveLoadsRotatedKeyAfterPacketReadStarts(t *testing.T) {
	permanent, _ := RestoreAuthKey(bytes.Repeat([]byte{1}, 256), 7, 0)
	temporary, _ := RestoreAuthKey(bytes.Repeat([]byte{2}, 256), 9, 0)
	sessionID := [8]byte{3}
	session := NewSession(permanent, 4, sessionID, 1)
	reader, writer := io.Pipe()
	observed := &observedReader{reader: reader, started: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		_, _, _, err := session.Receive(observed, 1024)
		result <- err
	}()
	<-observed.started
	if err := session.ReplaceAuthKeyWithSalt(temporary, 5); err != nil {
		t.Fatal(err)
	}
	body, err := tl.Encode(&tl.MTPPong{MessageID: 1, PingID: 2})
	if err != nil {
		t.Fatal(err)
	}
	responseID := serverMessageID(time.Now().Unix(), 1)
	message, err := encryptMessageWithSalt(
		&constantReader{value: 6}, temporary, 5, sessionID, responseID, 0, body,
		cryptoutil.ServerToClient,
	)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = transport.WriteIntermediate(writer, message.Payload)
		_ = writer.Close()
	}()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

type observedReader struct {
	reader  io.Reader
	started chan struct{}
	once    sync.Once
}

func (reader *observedReader) Read(payload []byte) (int, error) {
	reader.once.Do(func() { close(reader.started) })
	return reader.reader.Read(payload)
}
