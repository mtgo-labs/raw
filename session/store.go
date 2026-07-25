// Package session provides caller-owned persistence for raw client state.
package session

import "context"

// Store loads and atomically saves an opaque, versioned session envelope.
// Implementations must not interpret its contents.
type Store interface {
	Load(context.Context) ([]byte, error)
	Save(context.Context, []byte) error
}
