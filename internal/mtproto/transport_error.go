package mtproto

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// TransportError is a framed MTProto transport error returned instead of an
// encrypted payload.
type TransportError struct {
	Code int
}

func (err *TransportError) Error() string {
	if err == nil {
		return "mtproto: transport error"
	}
	return fmt.Sprintf("mtproto: transport error %d", err.Code)
}

func ParseTransportError(payload []byte) (*TransportError, bool) {
	if len(payload) != 4 {
		return nil, false
	}
	code := int32(binary.LittleEndian.Uint32(payload))
	if code >= 0 {
		return nil, false
	}
	return &TransportError{Code: int(-code)}, true
}

func TransportErrorCode(err error) (int, bool) {
	var transportError *TransportError
	if !errors.As(err, &transportError) {
		return 0, false
	}
	return transportError.Code, true
}
