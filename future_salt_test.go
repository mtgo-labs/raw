package raw

import (
	"context"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/tl"
)

func TestInvokeFetchesFutureSaltsBeforeAPIRequest(t *testing.T) {
	client, server, key, sessionID := newInitConnectionTranscriptClient(t, Config{
		APIID: 1, Address: "127.0.0.1:1",
	})
	if err := client.session.ReplaceAuthKeyWithSalt(key, 3); err != nil {
		t.Fatal(err)
	}
	client.initConnectionDone = true
	now := time.Now().Unix()

	serverDone := make(chan error, 1)
	go func() {
		futureSaltRequestID, body, err := readClientRequest(server, key, sessionID)
		if err == nil && binary.LittleEndian.Uint32(body) != tl.MTPGetFutureSaltsConstructorID {
			err = fmt.Errorf("future-salt constructor=%#x", binary.LittleEndian.Uint32(body))
		}
		if err == nil {
			err = writeServerObject(
				server,
				key,
				3,
				sessionID,
				futureSaltRequestID+1,
				&tl.MTPFutureSalts{
					ReqMessageID: int64(futureSaltRequestID),
					Now:          int32(now),
					Salts: []tl.MTPFutureSalt{
						{ValidSince: int32(now - 1), ValidUntil: int32(now + 100), Salt: 3},
						{ValidSince: int32(now + 100), ValidUntil: int32(now + 200), Salt: 4},
						{ValidSince: int32(now + 200), ValidUntil: int32(now + 300), Salt: 5},
					},
				},
			)
		}

		var requestID uint64
		if err == nil {
			requestID, body, err = readClientRequest(server, key, sessionID)
		}
		if err == nil && binary.LittleEndian.Uint32(body) != tl.HelpGetConfigRequestConstructorID {
			err = fmt.Errorf("API constructor=%#x", binary.LittleEndian.Uint32(body))
		}
		if err == nil {
			err = writeServerObject(
				server,
				key,
				3,
				sessionID,
				requestID+1,
				&tl.MTPRPCResult{ReqMessageID: int64(requestID), Result: &tl.Config{}},
			)
		}
		serverDone <- err
	}()

	result, err := invokeRoute(
		context.Background(),
		client,
		&tl.HelpGetConfigRequest{},
		InvokeOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("invoke returned a nil config")
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if client.session.NeedsFutureSalts() {
		t.Fatal("future-salt refresh remained pending")
	}
}
