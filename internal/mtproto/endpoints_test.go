package mtproto

import (
	"errors"
	"testing"
)

func TestEndpointTableValidatesAndSorts(t *testing.T) {
	table := NewEndpointTable()
	if err := table.Set(DCEndpoint{ID: 4, Address: "127.0.0.1:443"}); err != nil {
		t.Fatal(err)
	}
	if err := table.Set(DCEndpoint{ID: 2, Address: "[::1]:443", IPv6: true}); err != nil {
		t.Fatal(err)
	}
	endpoints := table.Snapshot()
	if len(endpoints) != 2 || endpoints[0].ID != 2 || endpoints[1].ID != 4 {
		t.Fatalf("endpoints=%+v", endpoints)
	}
	if got, ok := table.Get(2); !ok || got.Address != "[::1]:443" {
		t.Fatalf("endpoint=%+v ok=%v", got, ok)
	}
}

func TestEndpointTableRejectsInvalidAddress(t *testing.T) {
	for _, endpoint := range []DCEndpoint{{ID: 0, Address: "127.0.0.1:443"}, {ID: 2, Address: "127.0.0.1"}, {ID: 2, Address: "127.0.0.1:0"}, {ID: 2, Address: "127.0.0.1:70000"}} {
		if err := NewEndpointTable().Set(endpoint); !errors.Is(err, ErrInvalidEndpoint) {
			t.Fatalf("endpoint=%+v err=%v", endpoint, err)
		}
	}
}
