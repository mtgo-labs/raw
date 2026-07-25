package tgerr

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Error is a Telegram RPC error returned by an API request.
type Error struct {
	// Message is the original error message returned by Telegram.
	Message string
	// Type is the normalized error type used for matching.
	Type string
	// Method is the TL method that returned the error, when known.
	Method string
	// Code is Telegram's numeric RPC error code.
	Code int32
	// Argument is the numeric parameter extracted from a known error pattern.
	Argument int32
	// DCID is the data center that returned the error, when known.
	DCID int32
}

func (e *Error) MigrationDC() (int, bool) {
	if e == nil || e.Argument <= 0 {
		return 0, false
	}
	switch e.Type {
	case ErrFileMigrate, ErrNetworkMigrate, ErrPhoneMigrate, ErrUserMigrate:
		return int(e.Argument), true
	default:
		return 0, false
	}
}

func (e *Error) FloodWait() (time.Duration, bool) {
	if e == nil || e.Type != ErrFloodWait || e.Argument < 0 {
		return 0, false
	}
	return time.Duration(e.Argument) * time.Second, true
}

func (e *Error) Transient() bool {
	return e != nil && (e.Code == 500 || e.Code == 420)
}

// New constructs an Error and classifies known parameterized messages.
func New(code int32, message string) *Error {
	errorType, argument, ok := matchParameterized(message)
	if !ok {
		errorType = message
	}
	return &Error{
		Code:     code,
		Message:  message,
		Type:     errorType,
		Argument: argument,
	}
}

// Error returns a concise RPC error description.
func (e *Error) Error() string {
	if e == nil {
		return "rpc error: <nil>"
	}
	if e.Type != e.Message {
		return fmt.Sprintf("rpc error %d: %s (%d)", e.Code, e.Type, e.Argument)
	}
	return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message)
}

// Is reports whether target's populated fields match e.
func (e *Error) Is(target error) bool {
	other, ok := target.(*Error)
	if !ok || e == nil || other == nil {
		return false
	}
	return (other.Code == 0 || e.Code == other.Code) &&
		(other.Message == "" || e.Message == other.Message) &&
		(other.Type == "" || e.Type == other.Type) &&
		(other.Argument == 0 || e.Argument == other.Argument) &&
		(other.Method == "" || e.Method == other.Method) &&
		(other.DCID == 0 || e.DCID == other.DCID)
}

// IsType reports whether e has the given normalized error type.
func (e *Error) IsType(errorType string) bool {
	return e != nil && e.Type == errorType
}

// IsCode reports whether e has the given numeric code.
func (e *Error) IsCode(code int32) bool {
	return e != nil && e.Code == code
}

// IsOneOf reports whether e matches any normalized error type.
func (e *Error) IsOneOf(errorTypes ...string) bool {
	if e == nil {
		return false
	}
	return slices.Contains(errorTypes, e.Type)
}

// IsCodeOneOf reports whether e matches any numeric error code.
func (e *Error) IsCodeOneOf(codes ...int32) bool {
	if e == nil {
		return false
	}
	return slices.Contains(codes, e.Code)
}

// As extracts the first Error from err's unwrap tree without reflection.
func As(err error) (*Error, bool) {
	rpcError := find(err)
	return rpcError, rpcError != nil
}

// AsType extracts an Error and reports whether it has errorType.
func AsType(err error, errorType string) (*Error, bool) {
	rpcError := find(err)
	if rpcError == nil || rpcError.Type != errorType {
		return nil, false
	}
	return rpcError, true
}

// Is reports whether err contains an Error matching any normalized type.
func Is(err error, errorTypes ...string) bool {
	rpcError := find(err)
	return rpcError != nil && rpcError.IsOneOf(errorTypes...)
}

// IsCode reports whether err contains an Error matching any numeric code.
func IsCode(err error, codes ...int32) bool {
	rpcError := find(err)
	return rpcError != nil && rpcError.IsCodeOneOf(codes...)
}

func find(err error) *Error {
	return findDepth(err, 0)
}

func findDepth(err error, depth int) *Error {
	if err == nil {
		return nil
	}
	if rpcError, ok := err.(*Error); ok {
		return rpcError
	}
	if depth == 64 {
		return nil
	}
	switch value := err.(type) {
	case interface{ Unwrap() error }:
		return findDepth(value.Unwrap(), depth+1)
	case interface{ Unwrap() []error }:
		for _, nested := range value.Unwrap() {
			if rpcError := findDepth(nested, depth+1); rpcError != nil {
				return rpcError
			}
		}
	}
	return nil
}

func matchDecimalPattern(
	message string,
	prefix string,
	suffix string,
) (int32, bool) {
	if len(message) <= len(prefix)+len(suffix) ||
		!strings.HasPrefix(message, prefix) ||
		!strings.HasSuffix(message, suffix) {
		return 0, false
	}
	end := len(message) - len(suffix)
	const maxInt32 = int32(^uint32(0) >> 1)
	var argument int32
	for index := len(prefix); index < end; index++ {
		digit := message[index]
		if digit < '0' || digit > '9' {
			return 0, false
		}
		value := int32(digit - '0')
		if argument > (maxInt32-value)/10 {
			return 0, false
		}
		argument = argument*10 + value
	}
	return argument, true
}
