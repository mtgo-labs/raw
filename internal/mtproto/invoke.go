package mtproto

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/mtgo-labs/raw/tl"
)

var ErrInvokeResponse = errors.New("mtproto: invalid invoke response")

// Invoke sends one generated raw request and synchronously waits for its
// correlated result. Control messages are processed while waiting.
func Invoke[T any](session *Session, connection io.ReadWriter, random io.Reader, now time.Time, request tl.Request[T], maxPayload int) (T, error) {
	return InvokeContext(context.Background(), session, connection, random, now, request, maxPayload)
}

// InvokeContext is Invoke with context cancellation and deadline propagation
// for connections implementing SetReadDeadline.
func InvokeContext[T any](ctx context.Context, session *Session, connection io.ReadWriter, random io.Reader, now time.Time, request tl.Request[T], maxPayload int) (T, error) {
	var zero T
	if ctx == nil {
		return zero, context.Canceled
	}
	if session == nil || session.closed.Load() {
		return zero, ErrSessionClosed
	}
	if request == nil {
		return zero, ErrInvokeResponse
	}
	messageID, err := session.Send(connection, random, now, request)
	if err != nil {
		return zero, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if deadlineConnection, ok := connection.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = deadlineConnection.SetReadDeadline(deadline)
		}
	}
	for {
		select {
		case <-ctx.Done():
			session.pending.Cancel(messageID, ctx.Err())
			return zero, ctx.Err()
		default:
		}
		_, _, _, err := session.Receive(connection, maxPayload)
		if err != nil {
			if ctx.Err() != nil {
				session.pending.Cancel(messageID, ctx.Err())
				return zero, ctx.Err()
			}
			return zero, err
		}
		pending, ok := session.pending.Take(messageID)
		if !ok {
			continue
		}
		if pending.Result.Err != nil {
			return zero, pending.Result.Err
		}
		return tl.DecodeResult(request, pending.Result.Body, tl.DefaultDecodeLimits())
	}
}
