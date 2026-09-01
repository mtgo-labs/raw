package mtproto

import (
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"sync"

	"github.com/mtgo-labs/raw/tgerr"
	"github.com/mtgo-labs/raw/tl"
)

var (
	ErrPendingMessageID = errors.New("mtproto: invalid pending message ID")
	ErrPendingDuplicate = errors.New("mtproto: duplicate pending message ID")
	ErrPendingLimit     = errors.New("mtproto: pending request limit reached")
	ErrPendingContainer = errors.New("mtproto: invalid message container")
	ErrRemoteBadMessage = errors.New("mtproto: server rejected message")
	ErrRemoteBadSalt    = errors.New("mtproto: server rejected message salt")
)

// PendingResult is completed by the reader path and consumed by the owner of
// the matching request.
type PendingResult struct {
	Body []byte
	Err  error
}

// PendingRequest tracks one outbound message without creating a goroutine.
type PendingRequest struct {
	MessageID     uint64
	Done          bool
	Raw           bool // set by InvokeWithRawResult to skip inner TL decode
	Result        PendingResult
	done          chan struct{}
	wireMessageID uint64
	message       tl.MTPMessage
	containerID   uint64
	acknowledged  bool
	// msgIDDecreaseRetried guards the MSGID_DECREASE_RETRY recovery so one
	// request cannot ping-pong forever.
	msgIDDecreaseRetried bool
}

// PendingTable is a bounded-scope concurrent ID table. It owns request state,
// not scheduling or cancellation policy.
type PendingTable struct {
	mu       sync.Mutex
	entries  map[uint64]*PendingRequest
	capacity int
}

// pendingMapHint caps the map preallocation size. The configured capacity
// is a limit, not a steady-state size — most sessions hold a handful of
// pending requests, and a 128-slot hint cost several KiB per connection
// across large fleets. The map grows on demand up to the limit either way.
const pendingMapHint = 8

func NewPendingTable(capacity int) *PendingTable {
	if capacity < 1 {
		capacity = 1
	}
	return &PendingTable{entries: make(map[uint64]*PendingRequest, min(capacity, pendingMapHint)), capacity: capacity}
}
func (table *PendingTable) Add(messageID uint64) (*PendingRequest, error) {
	return table.AddMessage(messageID, tl.MTPMessage{}, false)
}

func (table *PendingTable) AddMessage(messageID uint64, message tl.MTPMessage, raw bool) (*PendingRequest, error) {
	if table == nil || messageID == 0 {
		return nil, ErrPendingMessageID
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	if table.entries == nil {
		table.entries = make(map[uint64]*PendingRequest)
	}
	if _, exists := table.entries[messageID]; exists {
		return nil, ErrPendingDuplicate
	}
	if len(table.entries) >= table.capacity {
		return nil, ErrPendingLimit
	}
	request := &PendingRequest{MessageID: messageID, Raw: raw, wireMessageID: messageID, message: message, done: make(chan struct{})}
	table.entries[messageID] = request
	return request, nil
}
func (table *PendingTable) Resolve(messageID uint64, result PendingResult) bool {
	if table == nil || messageID == 0 {
		return false
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	request, exists := table.entries[messageID]
	if !exists || request.Done {
		return false
	}
	request.Result = result
	request.Done = true
	close(request.done)
	return true
}

// ResolveRPCResult encodes the validated rpc_result payload and completes its
// matching pending request. Unknown request IDs are ignored by design.
func (table *PendingTable) ResolveRPCResult(result *tl.MTPRPCResult, rawBody []byte) (bool, error) {
	if result == nil || result.ReqMessageID == 0 ||
		(result.Result == nil && len(rawBody) < 4) {
		return false, ErrPendingMessageID
	}
	if rpcError, ok := result.Result.(*tl.MTPRPCError); ok {
		return table.Resolve(uint64(result.ReqMessageID), PendingResult{Err: tgerr.New(rpcError.ErrorCode, rpcError.ErrorMessage)}), nil
	}
	if len(rawBody) >= 4 {
		ctor := binary.LittleEndian.Uint32(rawBody[:4])
		if ctor == tl.MTPRPCErrorConstructorID {
			obj, err := tl.Decode(rawBody, tl.DefaultDecodeLimits())
			if err != nil {
				return false, err
			}
			if rpcError, ok := obj.(*tl.MTPRPCError); ok {
				return table.Resolve(uint64(result.ReqMessageID), PendingResult{Err: tgerr.New(rpcError.ErrorCode, rpcError.ErrorMessage)}), nil
			}
			return false, ErrPendingMessageID
		}
		return table.Resolve(uint64(result.ReqMessageID), PendingResult{Body: rawBody}), nil
	}

	body, err := tl.Encode(result.Result)
	if err != nil {
		return false, err
	}
	return table.Resolve(uint64(result.ReqMessageID), PendingResult{Body: body}), nil
}

// ResolveMessage dispatches only protocol response envelopes to the pending
// table. Non-rpc objects are intentionally ignored for the session layer.
func (table *PendingTable) ResolveMessage(object tl.Object, rawBody []byte) (int, error) {
	switch value := object.(type) {
	case *tl.MTPRPCResult:
		resolved, err := table.ResolveRPCResult(value, rawBody)
		if err != nil {
			return 0, err
		}
		if resolved {
			return 1, nil
		}
		return 0, nil
	case *tl.MTPMessageContainer:
		resolved := 0
		for _, message := range value.Messages {
			entry := message
			if entry.Body == nil {
				return resolved, ErrPendingContainer
			}
			count, err := table.ResolveMessage(entry.Body, nil)
			if err != nil {
				return resolved, err
			}
			resolved += count
		}
		return resolved, nil
	default:
		return 0, nil
	}
}

// ApplyControl completes a pending request affected by a validated bad
// message or bad salt. Acknowledgements and resend requests remain policy-free.
func (table *PendingTable) ApplyControl(event ControlEvent) bool {
	switch event.Kind {
	case ControlBadMessage:
		return table.Cancel(uint64(event.MessageID), ErrRemoteBadMessage)
	case ControlBadSalt:
		return table.Cancel(uint64(event.MessageID), ErrRemoteBadSalt)
	default:
		return false
	}
}

func (table *PendingTable) Take(messageID uint64) (*PendingRequest, bool) {
	if table == nil || messageID == 0 {
		return nil, false
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	request, exists := table.entries[messageID]
	if !exists || !request.Done {
		return nil, false
	}
	delete(table.entries, messageID)
	return request, true
}

// Wait blocks until one pending request is completed by the receive path.
// Completion ownership remains with the caller through the returned request.
func (table *PendingTable) Wait(ctx context.Context, messageID uint64) (*PendingRequest, error) {
	if table == nil || messageID == 0 {
		return nil, ErrPendingMessageID
	}
	table.mu.Lock()
	request := table.entries[messageID]
	table.mu.Unlock()
	return table.WaitRequest(ctx, request)
}

// WaitRequest waits on the request returned by Add. Holding that reference
// preserves completion when Close synchronously removes the table entry before
// the caller reaches the wait path.
func (table *PendingTable) WaitRequest(ctx context.Context, request *PendingRequest) (*PendingRequest, error) {
	if table == nil || request == nil || request.MessageID == 0 {
		return nil, ErrPendingMessageID
	}
	if ctx == nil {
		return nil, context.Canceled
	}
	table.mu.Lock()
	wireMessageID := request.wireMessageID
	current, exists := table.entries[wireMessageID]
	if exists && current != request {
		table.mu.Unlock()
		return nil, ErrPendingMessageID
	}
	if !exists {
		table.mu.Unlock()
		if request.Done {
			return request, nil
		}
		return nil, ErrPendingMessageID
	}
	if request.Done {
		delete(table.entries, wireMessageID)
		table.mu.Unlock()
		return request, nil
	}
	done := request.done
	table.mu.Unlock()
	select {
	case <-done:
		table.mu.Lock()
		if table.entries[request.wireMessageID] == request {
			delete(table.entries, request.wireMessageID)
		}
		table.mu.Unlock()
		return request, nil
	case <-ctx.Done():
		table.mu.Lock()
		wireMessageID = request.wireMessageID
		if table.entries[wireMessageID] == request && !request.Done {
			request.Result.Err = ctx.Err()
			request.Done = true
			close(request.done)
		}
		if table.entries[wireMessageID] == request {
			delete(table.entries, wireMessageID)
		}
		table.mu.Unlock()
		return request, ctx.Err()
	}
}

func (table *PendingTable) Cancel(messageID uint64, err error) bool {
	if table == nil || messageID == 0 {
		return false
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	request, exists := table.entries[messageID]
	if !exists || request.Done {
		return false
	}
	request.Result.Err = err
	request.Done = true
	close(request.done)
	return true
}

func (table *PendingTable) Contains(messageID uint64) bool {
	if table == nil || messageID == 0 {
		return false
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	request, exists := table.entries[messageID]
	return exists && !request.Done
}

// IsRaw reports whether the pending request was created by InvokeWithRawResult
// and should receive the undecoded response payload directly.
func (table *PendingTable) IsRaw(messageID uint64) bool {
	if table == nil || messageID == 0 {
		return false
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	request, exists := table.entries[messageID]
	return exists && request.Raw
}

// decodeRPCError extracts the rpc_error carried by one rpc_result, accepting
// both a decoded inner object and the raw body left undecoded by the receive
// fast path.
func decodeRPCError(result *tl.MTPRPCResult, rawBody []byte) *tl.MTPRPCError {
	if value, ok := result.Result.(*tl.MTPRPCError); ok {
		return value
	}
	if len(rawBody) < 4 || binary.LittleEndian.Uint32(rawBody) != tl.MTPRPCErrorConstructorID {
		return nil
	}
	object, err := tl.Decode(rawBody, tl.DefaultDecodeLimits())
	if err != nil {
		return nil
	}
	value, _ := object.(*tl.MTPRPCError)
	return value
}

// decreaseRetryTargets selects unresolved requests rejected with
// MSGID_DECREASE_RETRY for one retransmission with a fresh message id. A
// request that was already recovered this way is left to resolve through the
// normal error path.
func (table *PendingTable) decreaseRetryTargets(reqMessageID uint64) []RecoveryTarget {
	if table == nil || reqMessageID == 0 {
		return nil
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	targets := make([]RecoveryTarget, 0, 1)
	for _, request := range table.entries {
		if request.Done || request.message.Body == nil || request.msgIDDecreaseRetried {
			continue
		}
		if request.wireMessageID == reqMessageID || request.containerID == reqMessageID {
			request.msgIDDecreaseRetried = true
			targets = append(targets, RecoveryTarget{request: request})
		}
	}
	return targets
}

// RecoveryMessages snapshots unresolved outbound messages in message-ID order.
// It is used only after a route disconnects and does not add steady-state work.
func (table *PendingTable) RecoveryMessages() []tl.MTPMessage {
	if table == nil {
		return nil
	}
	table.mu.Lock()
	messages := make([]tl.MTPMessage, 0, len(table.entries))
	for _, request := range table.entries {
		if !request.Done && request.message.Body != nil {
			messages = append(messages, request.message)
		}
	}
	table.mu.Unlock()
	slices.SortFunc(messages, func(left, right tl.MTPMessage) int {
		switch {
		case left.MessageID < right.MessageID:
			return -1
		case left.MessageID > right.MessageID:
			return 1
		default:
			return 0
		}
	})
	return messages
}

func (table *PendingTable) Len() int {
	if table == nil {
		return 0
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	return len(table.entries)
}

// Close completes and removes every pending request with err.
func (table *PendingTable) Close(err error) int {
	if table == nil {
		return 0
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	count := len(table.entries)
	for messageID, request := range table.entries {
		if !request.Done {
			request.Done = true
			request.Result.Err = err
			close(request.done)
		}
		delete(table.entries, messageID)
	}
	return count
}
