package mtproto

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/mtgo-labs/raw/tl"
)

func TestInvokeContextRejectsCancellation(t *testing.T) {
	authKey, err := NewAuthKey(bytes.Repeat([]byte{0x42}, 256), [16]byte{}, [32]byte{}, 0, testNow())
	if err != nil {
		t.Fatal(err)
	}
	session := NewSession(authKey, 1, [8]byte{8}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var connection bytes.Buffer
	_, err = InvokeContext(ctx, session, &connection, &constantReader{value: 7}, testNow(), &tl.HelpGetConfigRequest{}, 4096)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}
