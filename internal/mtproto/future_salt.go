package mtproto

import (
	"cmp"
	"errors"
	"slices"

	"github.com/mtgo-labs/raw/tl"
)

const maxFutureSalts = 64

var ErrInvalidFutureSalt = errors.New("mtproto: invalid future salt")

type FutureSalt struct {
	ValidSince int64
	ValidUntil int64
	Salt       int64
}

type FutureSaltTable struct {
	salts []FutureSalt
	next  int
}

func (table *FutureSaltTable) Apply(values *tl.MTPFutureSalts) error {
	if table == nil || values == nil || len(values.Salts) > maxFutureSalts {
		return ErrInvalidFutureSalt
	}
	validated := make([]FutureSalt, 0, len(values.Salts))
	for _, value := range values.Salts {
		if value.ValidSince >= value.ValidUntil || value.Salt == 0 {
			return ErrInvalidFutureSalt
		}
		validated = append(validated, FutureSalt{ValidSince: int64(value.ValidSince), ValidUntil: int64(value.ValidUntil), Salt: value.Salt})
	}
	slices.SortFunc(validated, func(left, right FutureSalt) int {
		return cmp.Compare(left.ValidSince, right.ValidSince)
	})
	table.salts = validated
	table.next = 0
	return nil
}

func (table *FutureSaltTable) Select(serverTime int64) (int64, bool) {
	if table == nil {
		return 0, false
	}
	for index := len(table.salts) - 1; index >= 0; index-- {
		value := table.salts[index]
		if serverTime >= value.ValidSince && serverTime < value.ValidUntil {
			return value.Salt, true
		}
	}
	return 0, false
}

// Activate advances across salts whose validity has started and returns the
// newest one that is valid now. Calls between validity boundaries are O(1).
func (table *FutureSaltTable) Activate(serverTime int64) (int64, bool) {
	if table == nil {
		return 0, false
	}
	var selected int64
	for table.next < len(table.salts) {
		value := table.salts[table.next]
		if value.ValidSince > serverTime {
			break
		}
		table.next++
		if serverTime < value.ValidUntil {
			selected = value.Salt
		}
	}
	return selected, selected != 0
}

func (table *FutureSaltTable) Remaining() int {
	if table == nil || table.next >= len(table.salts) {
		return 0
	}
	return len(table.salts) - table.next
}

func (table *FutureSaltTable) Snapshot() []FutureSalt {
	if table == nil {
		return nil
	}
	return append([]FutureSalt(nil), table.salts[table.next:]...)
}
