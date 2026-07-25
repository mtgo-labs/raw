package raw

import (
	"testing"

	"github.com/mtgo-labs/raw/tl"
)

func TestClientRefreshEndpoints(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:443"})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.RefreshEndpoints(&tl.Config{DCOptions: []tl.DCOptionClass{&tl.DCOption{ID: 4, IPAddress: "127.0.0.4", Port: 443}}}); err != nil {
		t.Fatal(err)
	}
	if client.config.DCAddresses[4] != "127.0.0.4:443" {
		t.Fatalf("addresses=%v", client.config.DCAddresses)
	}
}

func TestClientRefreshEndpointsTracksTemporarySessions(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:443"})
	if err != nil {
		t.Fatal(err)
	}
	limit := int32(3)
	if err := client.RefreshEndpoints(&tl.Config{TmpSessions: &limit}); err != nil {
		t.Fatal(err)
	}
	if got := client.TemporarySessionLimit(); got != 3 {
		t.Fatalf("temporary session limit=%d", got)
	}
}
