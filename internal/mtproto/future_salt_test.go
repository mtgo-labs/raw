package mtproto

import (
	"errors"
	"testing"

	"github.com/mtgo-labs/raw/tl"
)

func TestFutureSaltTableSelectsValidSalt(t *testing.T) {
	var table FutureSaltTable
	if err := table.Apply(&tl.MTPFutureSalts{Salts: []tl.MTPFutureSalt{{ValidSince: 100, ValidUntil: 200, Salt: 4}, {ValidSince: 200, ValidUntil: 300, Salt: 5}}}); err != nil {
		t.Fatal(err)
	}
	if salt, ok := table.Select(250); !ok || salt != 5 {
		t.Fatalf("salt=%d ok=%v", salt, ok)
	}
	if _, ok := table.Select(300); ok {
		t.Fatal("expired salt selected")
	}
}

func TestFutureSaltTableRejectsInvalidValues(t *testing.T) {
	var table FutureSaltTable
	if err := table.Apply(&tl.MTPFutureSalts{Salts: []tl.MTPFutureSalt{{ValidSince: 2, ValidUntil: 1, Salt: 4}}}); !errors.Is(err, ErrInvalidFutureSalt) {
		t.Fatalf("err=%v", err)
	}
}

func TestFutureSaltTableReplacesAndActivatesWithoutScanningPastBoundary(t *testing.T) {
	var table FutureSaltTable
	if err := table.Apply(&tl.MTPFutureSalts{Salts: []tl.MTPFutureSalt{
		{ValidSince: 200, ValidUntil: 300, Salt: 5},
		{ValidSince: 100, ValidUntil: 200, Salt: 4},
	}}); err != nil {
		t.Fatal(err)
	}
	if salt, ok := table.Activate(150); !ok || salt != 4 {
		t.Fatalf("salt=%d ok=%t", salt, ok)
	}
	if table.Remaining() != 1 {
		t.Fatalf("remaining=%d", table.Remaining())
	}
	if _, ok := table.Activate(150); ok {
		t.Fatal("unchanged time activated a salt twice")
	}
	if salt, ok := table.Activate(250); !ok || salt != 5 {
		t.Fatalf("next salt=%d ok=%t", salt, ok)
	}

	if err := table.Apply(&tl.MTPFutureSalts{Salts: []tl.MTPFutureSalt{
		{ValidSince: 400, ValidUntil: 500, Salt: 6},
	}}); err != nil {
		t.Fatal(err)
	}
	snapshot := table.Snapshot()
	if len(snapshot) != 1 || snapshot[0].Salt != 6 {
		t.Fatalf("replacement=%+v", snapshot)
	}
}

func TestFutureSaltTableRejectsOversizedResponse(t *testing.T) {
	var table FutureSaltTable
	values := &tl.MTPFutureSalts{Salts: make([]tl.MTPFutureSalt, maxFutureSalts+1)}
	if err := table.Apply(values); !errors.Is(err, ErrInvalidFutureSalt) {
		t.Fatalf("err=%v", err)
	}
}
