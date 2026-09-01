package mtproto

import (
	"testing"
)

// TestSessionStateFootprint pins the per-session fixed cost: the embedded
// replay window plus lazy scratch must keep NewSessionState to a single
// allocation — fleets run thousands of sessions and every KiB here is
// megabytes there. Before the lazy scratch, the struct also embedded an
// 8 KiB container workspace on every session.
func TestSessionStateFootprint(t *testing.T) {
	allocs := testing.AllocsPerRun(100, func() {
		_ = NewSessionState(1, [8]byte{4}, 0)
	})
	if allocs > 1 {
		t.Fatalf("NewSessionState allocs = %v, want <= 1", allocs)
	}

	// Container validation allocates the scratch workspace exactly once and
	// reuses it across calls.
	state := NewSessionState(1, [8]byte{4}, 0)
	if state.incoming.scratch != nil {
		t.Fatal("scratch must start nil (lazy)")
	}
}
