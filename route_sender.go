package raw

import (
	"crypto/rand"
	"net"
	"sync"
	"time"

	"github.com/mtgo-labs/raw/internal/mtproto"
)

// routeSender flushes pending acknowledgements for one route. RPC requests
// and recoveries are written inline by their originating paths under the
// route write mutex; ids allocated for a queued message could reach the wire
// below ids a direct writer sent in between, so nothing that carries a
// pre-allocated message id may be queued here.
type routeSender struct {
	mu      sync.Mutex
	writeMu *sync.Mutex
	session *mtproto.Session
	conn    net.Conn
	now     func() time.Time
	onError func(error)
	acks    []int64
	wake    chan struct{}
	stop    chan struct{}
	stopped bool
}

func newRouteSender(
	writeMu *sync.Mutex,
	sessionState *mtproto.Session,
	connection net.Conn,
	now func() time.Time,
	capacity int,
	onError func(error),
) *routeSender {
	if capacity < 1 {
		capacity = 1
	}
	return &routeSender{
		writeMu: writeMu,
		session: sessionState,
		conn:    connection,
		now:     now,
		onError: onError,
		acks:    make([]int64, 0, min(capacity, mtproto.MaxAcknowledgementIDs)),
		wake:    make(chan struct{}, 1),
		stop:    make(chan struct{}),
	}
}

func (sender *routeSender) enqueueAcknowledgements(messageIDs []int64) error {
	if sender == nil || len(messageIDs) == 0 {
		return nil
	}
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if sender.stopped {
		return mtproto.ErrSessionClosed
	}
	if len(messageIDs) > mtproto.MaxAcknowledgementIDs-len(sender.acks) {
		return ErrAcknowledgementOverflow
	}
	for _, messageID := range messageIDs {
		if messageID == 0 {
			return ErrAcknowledgementOverflow
		}
	}
	sender.acks = append(sender.acks, messageIDs...)
	sender.signalLocked()
	return nil
}

// drainAcks atomically removes and returns all pending acknowledgement IDs.
// Used by the direct-write Invoke path to coalesce acks into the outgoing
// message without a goroutine hop.
func (sender *routeSender) drainAcks() []int64 {
	if sender == nil {
		return nil
	}
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if sender.stopped || len(sender.acks) == 0 {
		return nil
	}
	acks := sender.acks
	sender.acks = nil
	return acks
}

func (sender *routeSender) signalLocked() {
	select {
	case sender.wake <- struct{}{}:
	default:
	}
}

func (sender *routeSender) takeAcks() []int64 {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if sender.stopped {
		return nil
	}
	acks := sender.acks
	sender.acks = nil
	return acks
}

func (sender *routeSender) recycleAcks(acks []int64) {
	clear(acks)
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if sender.stopped {
		return
	}
	if len(sender.acks) == 0 {
		sender.acks = acks[:0]
	}
}

func (sender *routeSender) run() {
	for {
		select {
		case <-sender.wake:
			for {
				acks := sender.takeAcks()
				if len(acks) == 0 {
					break
				}
				sender.writeMu.Lock()
				_, err := sender.session.SendPrepared(
					sender.conn,
					rand.Reader,
					sender.now(),
					nil,
					acks,
					false,
				)
				sender.writeMu.Unlock()
				sender.recycleAcks(acks)
				if err != nil {
					sender.halt()
					if sender.onError != nil {
						sender.onError(err)
					}
					return
				}
			}
		case <-sender.stop:
			return
		}
	}
}

func (sender *routeSender) halt() {
	if sender == nil {
		return
	}
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if sender.stopped {
		return
	}
	sender.stopped = true
	sender.acks = nil
	close(sender.stop)
}
