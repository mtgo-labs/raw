package mtproto

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/cryptoutil"
	"github.com/mtgo-labs/raw/internal/transport"
	"github.com/mtgo-labs/raw/tl"
)

func TestEncryptedSessionTranscript(t *testing.T) {
	now := time.Now()
	authKey, err := NewAuthKey(bytes.Repeat([]byte{0x42}, 256), [16]byte{}, [32]byte{}, now.Unix(), now)
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	session := NewSession(authKey, 1, [8]byte{7}, 1)
	serverErr := make(chan error, 1)
	go func() {
		defer server.Close()
		payload, err := transport.ReadIntermediate(server, 4096)
		if err != nil {
			serverErr <- err
			return
		}
		messageID, _, body, err := decryptMessageWithSalt(authKey, 1, [8]byte{7}, payload, cryptoutil.ClientToServer)
		if err != nil {
			serverErr <- err
			return
		}
		if _, err := tl.Decode(body, tl.DefaultDecodeLimits()); err != nil {
			serverErr <- err
			return
		}
		responseBody, err := tl.Encode(&tl.MTPRPCResult{ReqMessageID: int64(messageID), Result: &tl.MTPReqPQMulti{}})
		if err != nil {
			serverErr <- err
			return
		}
		response, err := encryptMessageWithSalt(&constantReader{value: 7}, authKey, 1, [8]byte{7}, messageID+1, 2, responseBody, cryptoutil.ServerToClient)
		if err == nil {
			err = transport.WriteIntermediate(server, response.Payload)
		}
		serverErr <- err
	}()

	messageID, err := session.Send(client, &constantReader{value: 7}, now, &tl.MTPReqPQMulti{})
	if err != nil {
		t.Fatal(err)
	}
	result, responseID, sequenceNo, err := session.Receive(client, 4096)
	if err != nil || result.Resolved != 1 || responseID != messageID+1 || sequenceNo != 2 {
		t.Fatalf("result=%+v response=%x seq=%d err=%v", result, responseID, sequenceNo, err)
	}
	request, ok := session.pending.Take(messageID)
	if !ok || request.Result.Err != nil {
		t.Fatalf("pending=%+v ok=%v", request, ok)
	}
	if err := <-serverErr; err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}
