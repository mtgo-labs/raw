package tl_test

import (
	"testing"

	"github.com/mtgo-labs/raw/tl"
)

var (
	_ tl.Object                            = (*tl.User)(nil)
	_ tl.UserClass                         = (*tl.User)(nil)
	_ tl.Request[tl.MessagesMessagesClass] = (*tl.MessagesGetHistoryRequest)(nil)
	_ tl.UpdateClass                       = (*tl.SyntheticDummyUpdate)(nil)
	_ tl.Request[[]byte]                   = (*tl.SyntheticCustomMethodRequest)(nil)
)

func TestGeneratedConstructorID(t *testing.T) {
	t.Parallel()

	value := &tl.MessagesGetHistoryRequest{}
	if value.ConstructorID() != tl.MessagesGetHistoryRequestConstructorID {
		t.Fatalf(
			"ConstructorID() = %#08x, want %#08x",
			value.ConstructorID(),
			tl.MessagesGetHistoryRequestConstructorID,
		)
	}
}

func TestGeneratedRequestResultInference(t *testing.T) {
	t.Parallel()

	if result := resultOf(&tl.MessagesGetHistoryRequest{}); result != nil {
		t.Fatalf("resultOf() = %T, want nil", result)
	}
}

func TestGeneratedGenericRequestWrapper(t *testing.T) {
	t.Parallel()

	wrapped := &tl.InvokeAfterMessageRequest[tl.MessagesMessagesClass]{
		MessageID: 1,
		Query:     &tl.MessagesGetHistoryRequest{},
	}
	var _ tl.Request[tl.MessagesMessagesClass] = wrapped
	if wrapped.ConstructorID() != tl.InvokeAfterMessageRequestConstructorID {
		t.Fatalf("ConstructorID() = %#08x", wrapped.ConstructorID())
	}
}

func resultOf[T any](_ tl.Request[T]) T {
	var result T
	return result
}
