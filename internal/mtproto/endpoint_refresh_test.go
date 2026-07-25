package mtproto

import (
	"testing"

	"github.com/mtgo-labs/raw/tl"
)

func TestRefreshEndpointsFiltersAndPrefersIPv4(t *testing.T) {
	table := NewEndpointTable()
	config := &tl.Config{DCOptions: []tl.DCOptionClass{
		&tl.DCOption{ID: 2, IPAddress: "::1", Port: 443, IPv6: true},
		&tl.DCOption{ID: 2, IPAddress: "127.0.0.1", Port: 443},
		&tl.DCOption{ID: 3, IPAddress: "127.0.0.2", Port: 443, CDN: true},
	}}
	if err := RefreshEndpoints(table, config); err != nil {
		t.Fatal(err)
	}
	endpoint, ok := table.Get(2)
	if !ok || endpoint.Address != "127.0.0.1:443" || endpoint.IPv6 {
		t.Fatalf("endpoint=%+v ok=%v", endpoint, ok)
	}
	if _, ok := table.Get(3); ok {
		t.Fatal("CDN endpoint was selected")
	}
}
