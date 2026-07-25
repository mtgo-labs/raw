package mtproto

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/tl"
)

func TestPlainAuthorizationTranscript(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	var nonce [16]byte
	for index := range nonce {
		nonce[index] = byte(index)
	}
	serverErr := make(chan error, 1)
	go func() {
		defer server.Close()
		object, _, err := ReceivePlainObject(server, 1024)
		if err != nil {
			serverErr <- err
			return
		}
		request, ok := object.(*tl.MTPReqPQMulti)
		if !ok || request.Nonce != nonce {
			serverErr <- errors.New("server received unexpected req_pq_multi")
			return
		}
		_, err = SendPlainObject(server, time.Unix(1_700_000_001, 0), &tl.MTPResPQ{
			Nonce: nonce, PQ: []byte{15}, ServerPublicKeyFingerprints: []int64{int64(testFingerprint)},
		})
		serverErr <- err
	}()

	if _, err := SendPlainObject(client, time.Unix(1_700_000_000, 0), &tl.MTPReqPQMulti{Nonce: nonce}); err != nil {
		t.Fatal(err)
	}
	object, messageID, err := ReceivePlainObject(client, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if messageID == 0 {
		t.Fatal("response message ID is zero")
	}
	if response, ok := object.(*tl.MTPResPQ); !ok || response.Nonce != nonce || len(response.PQ) != 1 || response.PQ[0] != 15 {
		t.Fatalf("response = %#v", object)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}
