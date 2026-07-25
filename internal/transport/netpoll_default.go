//go:build !linux

package transport

import (
	"context"
	"errors"
	"net"
)

// DialNetPoll returns an error on platforms that do not support
// CloudWeGo/netpoll (all non-Linux systems). The Config.NetPoll flag is
// still accepted on every platform; this function is only called when the
// flag is set, so non-Linux users who leave it false are unaffected.
func DialNetPoll(_ context.Context, _ string) (net.Conn, error) {
	return nil, errors.New("transport: netpoll is only supported on Linux")
}
