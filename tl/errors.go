package tl

import (
	"errors"
	"fmt"
)

var (
	// ErrUnexpectedEOF reports truncated TL input.
	ErrUnexpectedEOF = errors.New("tl: unexpected end of input")
	// ErrInvalidLength reports a malformed or unsupported TL length.
	ErrInvalidLength = errors.New("tl: invalid length")
	// ErrInvalidPadding reports non-zero TL padding.
	ErrInvalidPadding = errors.New("tl: invalid padding")
	// ErrLimitExceeded reports input that exceeds a configured decode limit.
	ErrLimitExceeded = errors.New("tl: decode limit exceeded")
	// ErrUnexpectedConstructor reports a constructor that is invalid for the
	// value being decoded.
	ErrUnexpectedConstructor = errors.New("tl: unexpected constructor")
	// ErrTrailingData reports bytes remaining after one complete TL value.
	ErrTrailingData = errors.New("tl: trailing data")
	// ErrInvalidDecodeLimits reports unusable public decoder limits.
	ErrInvalidDecodeLimits = errors.New("tl: invalid decode limits")
	// ErrNilObject reports a nil value where TL requires an object.
	ErrNilObject = errors.New("tl: nil object")
	// ErrInconsistentFlags reports fields sharing a predicate bit with
	// different presence.
	ErrInconsistentFlags = errors.New("tl: inconsistent flag fields")
	// ErrSizeOverflow reports an encoded size that cannot fit in an int.
	ErrSizeOverflow = errors.New("tl: encoded size overflow")
)

// EncodeError identifies the TL type and field that could not be encoded.
type EncodeError struct {
	Type  string
	Field string
	Err   error
}

func (e *EncodeError) Error() string {
	if e.Field == "" {
		return fmt.Sprintf("tl: encode %s: %v", e.Type, e.Err)
	}
	return fmt.Sprintf("tl: encode %s field %s: %v", e.Type, e.Field, e.Err)
}

// Unwrap returns the underlying encode failure.
func (e *EncodeError) Unwrap() error {
	return e.Err
}

// DecodeError identifies the input offset and operation that rejected TL data.
type DecodeError struct {
	Offset    int
	Operation string
	Err       error
}

func (e *DecodeError) Error() string {
	return fmt.Sprintf("tl: decode %s at offset %d: %v", e.Operation, e.Offset, e.Err)
}

// Unwrap returns the underlying decode failure.
func (e *DecodeError) Unwrap() error {
	return e.Err
}

func encodeError(tlType, field string, err error) error {
	return &EncodeError{Type: tlType, Field: field, Err: err}
}
