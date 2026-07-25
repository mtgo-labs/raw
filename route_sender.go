package raw

import (
	"crypto/rand"
	"net"
	"sync"
	"time"

	"github.com/mtgo-labs/raw/internal/mtproto"
	"github.com/mtgo-labs/raw/tl"
)

type routeSender struct {
	mu       sync.Mutex
	writeMu  *sync.Mutex
	session  *mtproto.Session
	conn     net.Conn
	now      func() time.Time
	onError  func(error)
	capacity int
	requests []tl.MTPMessage
	retries  map[int64]struct{}
	acks     []int64
	wake     chan struct{}
	stop     chan struct{}
	stopped  bool
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
		writeMu:  writeMu,
		session:  sessionState,
		conn:     connection,
		now:      now,
		onError:  onError,
		capacity: capacity,
		requests: make([]tl.MTPMessage, 0, capacity),
		acks:     make([]int64, 0, min(capacity, mtproto.MaxAcknowledgementIDs)),
		wake:     make(chan struct{}, 1),
		stop:     make(chan struct{}),
	}
}

func (sender *routeSender) enqueueRequest(message tl.MTPMessage) error {
	return sender.enqueue(message, false)
}

func (sender *routeSender) enqueueRetry(message tl.MTPMessage) error {
	return sender.enqueue(message, true)
}

func (sender *routeSender) enqueue(message tl.MTPMessage, retry bool) error {
	if sender == nil {
		return mtproto.ErrSessionClosed
	}
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if sender.stopped {
		return mtproto.ErrSessionClosed
	}
	if len(sender.requests) >= sender.capacity {
		return mtproto.ErrPendingLimit
	}
	sender.requests = append(sender.requests, message)
	if retry {
		if sender.retries == nil {
			sender.retries = make(map[int64]struct{})
		}
		sender.retries[message.MessageID] = struct{}{}
	}
	sender.signalLocked()
	return nil
}

func (sender *routeSender) replaceRequests(messages []tl.MTPMessage) error {
	if sender == nil {
		return mtproto.ErrSessionClosed
	}
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if sender.stopped {
		return mtproto.ErrSessionClosed
	}
	if len(messages) > sender.capacity {
		return mtproto.ErrPendingLimit
	}
	sender.requests = append(sender.requests[:0], messages...)
	sender.retries = nil
	sender.acks = nil
	sender.signalLocked()
	return nil
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

func (sender *routeSender) takeBatch() ([]tl.MTPMessage, []int64, bool) {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if sender.stopped {
		return nil, nil, false
	}
	acknowledgements := sender.acks
	sender.acks = nil
	messageLimit := mtproto.MaxContainerMessages
	packetSize := 0
	if len(acknowledgements) != 0 {
		messageLimit--
		packetSize = 28 + len(acknowledgements)*8
	}
	count := 0
	for count < len(sender.requests) && count < messageLimit {
		messageSize := 16 + int(sender.requests[count].Bytes)
		if count != 0 && packetSize+messageSize > mtproto.MaxContainerPayload {
			break
		}
		packetSize += messageSize
		count++
	}
	var messages []tl.MTPMessage
	forceContainer := false
	if count != 0 {
		messages = sender.requests[:count]
		for _, message := range messages {
			if _, retry := sender.retries[message.MessageID]; retry {
				forceContainer = true
				delete(sender.retries, message.MessageID)
			}
		}
		if count == len(sender.requests) {
			sender.requests = nil
		} else {
			sender.requests = sender.requests[count:]
			sender.signalLocked()
		}
	}
	return messages, acknowledgements, forceContainer
}
func (sender *routeSender) recycleBatch(messages []tl.MTPMessage, acknowledgements []int64) {
	clear(messages)
	clear(acknowledgements)
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if sender.stopped {
		return
	}
	if len(sender.requests) == 0 {
		sender.requests = messages[:0]
	}
	if len(sender.acks) == 0 {
		sender.acks = acknowledgements[:0]
	}
}

func (sender *routeSender) run() {
	for {
		select {
		case <-sender.wake:
			for {
				messages, acknowledgements, forceContainer := sender.takeBatch()
				if len(messages) == 0 && len(acknowledgements) == 0 {
					break
				}
				sender.writeMu.Lock()
				_, err := sender.session.SendPrepared(
					sender.conn,
					rand.Reader,
					sender.now(),
					messages,
					acknowledgements,
					forceContainer,
				)
				sender.writeMu.Unlock()
				sender.recycleBatch(messages, acknowledgements)
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

func (sender *routeSender) halt() []tl.MTPMessage {
	if sender == nil {
		return nil
	}
	sender.mu.Lock()
	if sender.stopped {
		sender.mu.Unlock()
		return nil
	}
	sender.stopped = true
	requests := sender.requests
	sender.requests = nil
	sender.retries = nil
	sender.acks = nil
	close(sender.stop)
	sender.mu.Unlock()
	return requests
}

func (sender *routeSender) stopAndCancel(err error) {
	requests := sender.halt()
	for _, message := range requests {
		sender.session.Cancel(uint64(message.MessageID), err)
	}
}
