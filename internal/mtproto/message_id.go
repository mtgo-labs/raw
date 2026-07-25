package mtproto

import (
	"errors"
	"slices"
	"time"

	"github.com/mtgo-labs/raw/tl"
)

const (
	maxRecentIncomingMessageIDs = 1000
	maxContainerMessages        = 1024
	maxIncomingMessageAge       = 300 * time.Second
	maxIncomingMessageLead      = 30 * time.Second
)

var (
	ErrIncomingMessageIDParity = errors.New("mtproto: server message ID must be odd")
	ErrIncomingMessageIDReplay = errors.New("mtproto: duplicate or stale server message ID")
	ErrIncomingMessageIDTime   = errors.New("mtproto: server message ID is outside the accepted time range")
	ErrIncomingMessageIDOrder  = errors.New("mtproto: container message ID must exceed its children")
)

// incomingMessageIDs retains the greatest recent server IDs in sorted order.
// The circular layout makes the normal monotonic insertion path O(1) after a
// binary search, without allocating or shifting the fixed window.
type incomingMessageIDs struct {
	recent     [maxRecentIncomingMessageIDs]uint64
	scratch    [maxContainerMessages + 1]uint64
	recentHead int
	recentLen  int
}

func (ids *incomingMessageIDs) validateAndAdd(messageID uint64, object tl.Object, serverTime int64) error {
	count := 1
	ids.scratch[0] = messageID
	if err := validateIncomingMessageID(messageID, object, serverTime); err != nil {
		return err
	}
	if container, ok := object.(*tl.MTPMessageContainer); ok {
		if len(container.Messages) > maxContainerMessages {
			return ErrPendingContainer
		}
		for _, message := range container.Messages {
			entry := message
			if entry.Body == nil {
				return ErrPendingContainer
			}
			innerID := uint64(entry.MessageID)
			if innerID >= messageID {
				return ErrIncomingMessageIDOrder
			}
			if _, nested := entry.Body.(*tl.MTPMessageContainer); nested {
				return ErrPendingContainer
			}
			if err := validateIncomingMessageID(innerID, entry.Body, serverTime); err != nil {
				return err
			}
			ids.scratch[count] = innerID
			count++
		}
	}

	candidates := ids.scratch[:count]
	slices.Sort(candidates)
	for index, candidate := range candidates {
		if index > 0 && candidate == candidates[index-1] {
			return ErrIncomingMessageIDReplay
		}
		position, found := ids.search(candidate)
		if found || ids.recentLen > 0 && position == 0 {
			return ErrIncomingMessageIDReplay
		}
	}
	for _, candidate := range candidates {
		if !ids.add(candidate) {
			return ErrIncomingMessageIDReplay
		}
	}
	return nil
}

func validateIncomingMessageID(messageID uint64, object tl.Object, serverTime int64) error {
	if messageID&1 == 0 {
		return ErrIncomingMessageIDParity
	}
	messageTime := int64(messageID >> 32)
	if messageTime < serverTime-int64(maxIncomingMessageAge/time.Second) ||
		messageTime > serverTime+int64(maxIncomingMessageLead/time.Second) {
		if !allowsMessageIDTimeSkew(object) {
			return ErrIncomingMessageIDTime
		}
	}
	return nil
}

func allowsMessageIDTimeSkew(object tl.Object) bool {
	switch value := object.(type) {
	case *tl.MTPBadMessageNotification:
		return value != nil && (value.ErrorCode == 16 || value.ErrorCode == 17)
	case *tl.MTPBadServerSalt:
		return value != nil
	case *tl.MTPMessageContainer:
		if value == nil {
			return false
		}
		for _, message := range value.Messages {
			if allowsMessageIDTimeSkew(message.Body) {
				return true
			}
		}
	}
	return false
}

func (ids *incomingMessageIDs) add(messageID uint64) bool {
	position, found := ids.search(messageID)
	if found {
		return false
	}
	if ids.recentLen > 0 && position == 0 {
		return false
	}
	if ids.recentLen < maxRecentIncomingMessageIDs {
		for index := ids.recentLen; index > position; index-- {
			ids.set(index, ids.at(index-1))
		}
		ids.set(position, messageID)
		ids.recentLen++
		return true
	}
	if position == ids.recentLen {
		oldHead := ids.recentHead
		ids.recentHead = (ids.recentHead + 1) % len(ids.recent)
		ids.recent[oldHead] = messageID
		return true
	}
	for index := 0; index < position-1; index++ {
		ids.set(index, ids.at(index+1))
	}
	ids.set(position-1, messageID)
	return true
}

func (ids *incomingMessageIDs) search(messageID uint64) (int, bool) {
	low, high := 0, ids.recentLen
	for low < high {
		middle := int(uint(low+high) >> 1)
		if ids.at(middle) < messageID {
			low = middle + 1
		} else {
			high = middle
		}
	}
	return low, low < ids.recentLen && ids.at(low) == messageID
}

func (ids *incomingMessageIDs) at(index int) uint64 {
	return ids.recent[(ids.recentHead+index)%len(ids.recent)]
}

func (ids *incomingMessageIDs) set(index int, messageID uint64) {
	ids.recent[(ids.recentHead+index)%len(ids.recent)] = messageID
}
