package mtproto

import "sync"

var encodeBufPool = sync.Pool{
	New: func() any { buf := make([]byte, 0, 1024); return &buf },
}
