//go:build linux

package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/cloudwego/netpoll"
)

// DialNetPoll opens a CloudWeGo/netpoll epoll-based TCP connection and
// returns it as a net.Conn. Only available on Linux.
//
// netpoll.Connection embeds net.Conn: its Read blocks until at least one
// byte is available then returns all buffered data (standard io.Reader
// semantics), and Write buffers and immediately flushes (standard
// io.Writer semantics). TCP_NODELAY is enabled by default inside netpoll,
// so Config.NoDelay is redundant when this transport is selected.
//
// The caller owns and must close the returned connection. A context
// deadline, if set, is translated to the dial timeout.
func DialNetPoll(ctx context.Context, address string) (net.Conn, error) {
	if ctx == nil {
		return nil, errors.New("transport: nil dial context")
	}
	if address == "" {
		return nil, errors.New("transport: empty dial address")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	timeout := time.Duration(0)
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
		if timeout <= 0 {
			return nil, context.DeadlineExceeded
		}
	}
	connection, err := netpoll.DialConnection("tcp", address, timeout)
	if err != nil {
		return nil, fmt.Errorf("transport: dial netpoll: %w", err)
	}
	return connection, nil
}
