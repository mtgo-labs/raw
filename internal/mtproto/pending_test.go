package mtproto

import (
	"context"
	"errors"
	"testing"

	"github.com/mtgo-labs/raw/tgerr"
	"github.com/mtgo-labs/raw/tl"
)

func TestPendingWait(t *testing.T) {
	table := NewPendingTable(1)
	request, err := table.Add(17)
	if err != nil {
		t.Fatal(err)
	}
	go func() { table.Resolve(17, PendingResult{Body: []byte("ok")}) }()
	got, err := table.Wait(context.Background(), request.MessageID)
	if err != nil || string(got.Result.Body) != "ok" {
		t.Fatalf("request=%+v err=%v", got, err)
	}
}

func TestPendingTableLifecycle(t *testing.T) {
	table := NewPendingTable(2)
	request, err := table.Add(1)
	if err != nil || request.MessageID != 1 || table.Len() != 1 {
		t.Fatalf("add = %+v/%v len=%d", request, err, table.Len())
	}
	if _, err := table.Add(1); !errors.Is(err, ErrPendingDuplicate) {
		t.Fatalf("duplicate error = %v", err)
	}
	if _, err := table.Add(2); err != nil {
		t.Fatal(err)
	}
	if _, err := table.Add(3); !errors.Is(err, ErrPendingLimit) {
		t.Fatalf("limit error = %v", err)
	}
	if unfinished, ok := table.Take(1); unfinished != nil || ok {
		t.Fatal("unfinished request was taken")
	}
	if !table.Resolve(1, PendingResult{Body: []byte{1, 2}}) || table.Resolve(1, PendingResult{}) {
		t.Fatal("resolve lifecycle failed")
	}
	completed, ok := table.Take(1)
	if !ok || !completed.Done || len(completed.Result.Body) != 2 || table.Len() != 1 {
		t.Fatalf("take = %+v/%v len=%d", completed, ok, table.Len())
	}
}

func TestPendingTableRPCResult(t *testing.T) {
	table := NewPendingTable(1)
	if _, err := table.Add(7); err != nil {
		t.Fatal(err)
	}
	resolved, err := table.ResolveRPCResult(&tl.MTPRPCResult{ReqMessageID: 7, Result: &tl.MTPReqPQMulti{}}, nil)
	if err != nil || !resolved {
		t.Fatalf("resolve rpc_result = %v/%v", resolved, err)
	}
	request, ok := table.Take(7)
	if !ok || len(request.Result.Body) == 0 {
		t.Fatalf("request = %+v/%v", request, ok)
	}
}

func TestPendingTableRPCError(t *testing.T) {
	table := NewPendingTable(1)
	if _, err := table.Add(10); err != nil {
		t.Fatal(err)
	}
	resolved, err := table.ResolveRPCResult(&tl.MTPRPCResult{ReqMessageID: 10, Result: &tl.MTPRPCError{ErrorCode: 400, ErrorMessage: "FLOOD_WAIT_3"}}, nil)
	if err != nil || !resolved {
		t.Fatalf("resolve rpc error = %v/%v", resolved, err)
	}
	request, ok := table.Take(10)
	if !ok {
		t.Fatal("rpc error was not completed")
	}
	if rpcError, ok := tgerr.As(request.Result.Err); !ok || !rpcError.IsType("FLOOD_WAIT") || rpcError.Argument != 3 {
		t.Fatalf("error = %v", request.Result.Err)
	}
}

func TestPendingTableMessageContainer(t *testing.T) {
	table := NewPendingTable(1)
	if _, err := table.Add(8); err != nil {
		t.Fatal(err)
	}
	count, err := table.ResolveMessage(&tl.MTPMessageContainer{Messages: []tl.MTPMessage{
		{MessageID: 9, Body: &tl.MTPRPCResult{ReqMessageID: 8, Result: &tl.MTPReqPQMulti{}}},
	}}, nil)
	if err != nil || count != 1 {
		t.Fatalf("resolved = %d/%v", count, err)
	}
	if _, ok := table.Take(8); !ok {
		t.Fatal("contained result was not completed")
	}
}

func TestPendingTableControlFailure(t *testing.T) {
	table := NewPendingTable(2)
	if _, err := table.Add(9); err != nil {
		t.Fatal(err)
	}
	if !table.ApplyControl(ControlEvent{Kind: ControlBadMessage, MessageID: 9}) {
		t.Fatal("bad-message control did not complete request")
	}
	request, ok := table.Take(9)
	if !ok || request.Result.Err != ErrRemoteBadMessage {
		t.Fatalf("request = %+v/%v", request, ok)
	}
}

func TestPendingTableClose(t *testing.T) {
	table := NewPendingTable(2)
	_, _ = table.Add(1)
	_, _ = table.Add(2)
	if count := table.Close(ErrSessionSend); count != 2 || table.Len() != 0 {
		t.Fatalf("closed count=%d len=%d", count, table.Len())
	}
}

func TestPendingTableCloseAfterCancellation(t *testing.T) {
	table := NewPendingTable(1)
	request, err := table.Add(1)
	if err != nil {
		t.Fatal(err)
	}
	cancelError := errors.New("canceled")
	if !table.Cancel(1, cancelError) {
		t.Fatal("cancel failed")
	}
	if count := table.Close(ErrSessionClosed); count != 1 || table.Len() != 0 {
		t.Fatalf("closed count=%d len=%d", count, table.Len())
	}
	if !errors.Is(request.Result.Err, cancelError) {
		t.Fatalf("cancel result=%v", request.Result.Err)
	}
}

func TestPendingWaitAfterClose(t *testing.T) {
	table := NewPendingTable(1)
	request, err := table.Add(1)
	if err != nil {
		t.Fatal(err)
	}
	if count := table.Close(ErrSessionClosed); count != 1 {
		t.Fatalf("closed count=%d", count)
	}
	got, err := table.WaitRequest(context.Background(), request)
	if err != nil || got != request || !errors.Is(got.Result.Err, ErrSessionClosed) {
		t.Fatalf("request=%+v err=%v", got, err)
	}
}

func TestPendingTableCancellation(t *testing.T) {
	table := NewPendingTable(1)
	if _, err := table.Add(2); err != nil {
		t.Fatal(err)
	}
	cancelError := errors.New("closed")
	if !table.Cancel(2, cancelError) {
		t.Fatal("cancel failed")
	}
	request, ok := table.Take(2)
	if !ok || !errors.Is(request.Result.Err, cancelError) {
		t.Fatalf("cancel result = %+v/%v", request, ok)
	}
}
