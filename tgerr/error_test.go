package tgerr

import (
	"errors"
	"fmt"
	"math"
	"testing"
	"time"
)

func TestNewClassifiesParameterizedErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		message   string
		errorType string
		argument  int32
	}{
		{"FLOOD_WAIT_60", ErrFloodWait, 60},
		{"FILE_REFERENCE_4_EXPIRED", ErrFileReferenceExpired, 4},
		{
			"PREVIOUS_CHAT_IMPORT_ACTIVE_WAIT_12MIN",
			ErrPreviousChatImportActiveWaitMin,
			12,
		},
		{"INTERDC_3_CALL_RICH_ERROR", ErrInterDCCallRichError, 3},
		{"FLOOD_WAIT_0", ErrFloodWait, 0},
		{"FLOOD_WAIT_2147483647", ErrFloodWait, math.MaxInt32},
	}
	for _, test := range tests {
		t.Run(test.message, func(t *testing.T) {
			t.Parallel()

			value := New(CodeFlood, test.message)
			if value.Message != test.message {
				t.Errorf("Message = %q, want %q", value.Message, test.message)
			}
			if value.Type != test.errorType {
				t.Errorf("Type = %q, want %q", value.Type, test.errorType)
			}
			if value.Argument != test.argument {
				t.Errorf("Argument = %d, want %d", value.Argument, test.argument)
			}
		})
	}
}

func TestNewKeepsExactAndUnknownErrors(t *testing.T) {
	t.Parallel()

	for _, message := range []string{
		ErrAuthKeyUnregistered,
		"CUSTOM_ERROR_12",
		"FLOOD_WAIT_-1",
		"FLOOD_WAIT_value",
		"FLOOD_WAIT_21474836470",
	} {
		value := New(CodeBadRequest, message)
		if value.Type != message {
			t.Errorf("New(%q).Type = %q, want original message", message, value.Type)
		}
		if value.Argument != 0 {
			t.Errorf("New(%q).Argument = %d, want 0", message, value.Argument)
		}
	}
}

func TestErrorMatching(t *testing.T) {
	t.Parallel()

	rpcError := New(CodeFlood, "FLOOD_WAIT_30")
	wrapped := fmt.Errorf("invoke: %w", rpcError)
	joined := errors.Join(errors.New("transport"), wrapped)

	if !rpcError.IsType(ErrFloodWait) {
		t.Fatal("IsType did not match")
	}
	if !rpcError.IsCode(CodeFlood) {
		t.Fatal("IsCode did not match")
	}
	if !IsFloodWait(joined) {
		t.Fatal("generated IsFloodWait did not match joined error")
	}
	if !IsCode(joined, CodeBadRequest, CodeFlood) {
		t.Fatal("IsCode did not match joined error")
	}
	matched, ok := AsType(joined, ErrFloodWait)
	if !ok || matched != rpcError {
		t.Fatalf("AsType = %p, %v; want %p, true", matched, ok, rpcError)
	}

	var standard *Error
	if !errors.As(joined, &standard) || standard != rpcError {
		t.Fatal("standard errors.As did not extract Error")
	}
	if !errors.Is(joined, &Error{Type: ErrFloodWait}) {
		t.Fatal("standard errors.Is did not match Error type")
	}
}

func TestNilErrorHelpers(t *testing.T) {
	t.Parallel()

	var rpcError *Error
	if rpcError.IsType(ErrFloodWait) ||
		rpcError.IsCode(CodeFlood) ||
		rpcError.IsOneOf(ErrFloodWait) ||
		rpcError.IsCodeOneOf(CodeFlood) ||
		Is(nil, ErrFloodWait) ||
		IsCode(nil, CodeFlood) {
		t.Fatal("nil error helper matched")
	}
	if got := rpcError.Error(); got != "rpc error: <nil>" {
		t.Fatalf("nil Error() = %q", got)
	}
}

func TestFindBoundsUnwrapDepth(t *testing.T) {
	t.Parallel()

	var err error = New(CodeFlood, "FLOOD_WAIT_1")
	for range 65 {
		err = singleWrapper{err: err}
	}
	if _, ok := As(err); ok {
		t.Fatal("As traversed beyond the unwrap depth limit")
	}
}

type singleWrapper struct {
	err error
}

func (w singleWrapper) Error() string {
	return "wrapped"
}

func (w singleWrapper) Unwrap() error {
	return w.err
}

func FuzzNew(f *testing.F) {
	for _, seed := range []string{
		"FLOOD_WAIT_60",
		"FILE_REFERENCE_4_EXPIRED",
		"PREVIOUS_CHAT_IMPORT_ACTIVE_WAIT_12MIN",
		ErrAuthKeyUnregistered,
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, message string) {
		value := New(CodeBadRequest, message)
		if value.Message != message {
			t.Fatalf("Message = %q, want %q", value.Message, message)
		}
		if value.Type == "" && message != "" {
			t.Fatal("non-empty message produced empty type")
		}
	})
}

func TestMigrationDC(t *testing.T) {
	for _, test := range []struct {
		message string
		want    int
	}{
		{"FILE_MIGRATE_4", 4},
		{"NETWORK_MIGRATE_5", 5},
		{"PHONE_MIGRATE_2", 2},
		{"USER_MIGRATE_3", 3},
	} {
		if got, ok := New(303, test.message).MigrationDC(); !ok || got != test.want {
			t.Fatalf("message=%q dc=%d ok=%v", test.message, got, ok)
		}
	}
}

func TestFloodWaitAndTransient(t *testing.T) {
	err := New(CodeFlood, "FLOOD_WAIT_7")
	if wait, ok := err.FloodWait(); !ok || wait != 7*time.Second {
		t.Fatalf("wait=%v ok=%v", wait, ok)
	}
	if !err.Transient() {
		t.Fatal("flood error is not transient")
	}
}
