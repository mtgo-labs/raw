//go:generate go run ./cmd/fixturegen
//go:generate go run ./cmd/tlgen
//go:generate go run ./cmd/errgen
//go:generate go run ./cmd/rsagen

// Package raw provides a high-performance, low-level MTProto 2.0 client.
//
// NewClient allocates local state without performing I/O. Client.Connect opens
// the primary session explicitly; the first default Invoke does so lazily when
// needed. Client.Close synchronously releases owned routes and timers. A client
// resumes state through session.Store,
// accepts an authorization key supplied in Config, or negotiates and persists
// a new permanent key when the configured store is empty.
//
// Invoke and InvokeWithOptions accept generated tl.Request values directly and
// preserve their compile-time result types. InvokeOptions selects a DC,
// connection kind, session slot, and optional ordering chain without creating
// a request DTO or middleware context.
//
// Raw updates are delivered through Client.Updates. Queue overflow is explicit
// rather than silently dropping decoded values.
// The package intentionally does not provide domain wrappers, dispatchers,
// middleware, or plugins. Client.Start handles bot and phone login; the
// underlying auth.* requests remain available for advanced flows.
package raw
