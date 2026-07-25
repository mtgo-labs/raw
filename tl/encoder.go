package tl

import (
	"encoding/binary"
	"fmt"
	"math"
)

const (
	boolTrueConstructorID  uint32 = 0x997275b5
	boolFalseConstructorID uint32 = 0xbc799737
	nullConstructorID      uint32 = 0x56730bcc
	vectorConstructorID    uint32 = 0x1cb5c415
	maxBytesLength                = 0xffffff
	maxVectorLength               = math.MaxInt32
)

var zeroPadding [3]byte

type encoder struct {
	buffer []byte
}

// Encode serializes one boxed TL object into a newly allocated byte slice.
func Encode(value Object) ([]byte, error) {
	if value == nil {
		return nil, ErrNilObject
	}
	size, err := value.encodedSize()
	if err != nil {
		return nil, err
	}
	output := newEncoder(make([]byte, 0, size))
	output, err = value.encode(output)
	if err != nil {
		return nil, err
	}
	return output.data(), nil
}

// EncodedSize returns the exact number of bytes Encode will produce without
// allocating an output buffer.
func EncodedSize(value Object) (int, error) {
	if value == nil {
		return 0, ErrNilObject
	}
	return value.encodedSize()
}

// Append serializes one boxed TL object after dst and returns the extended
// slice. It writes directly and reuses dst's capacity when sufficient.
func Append(dst []byte, value Object) ([]byte, error) {
	if value == nil {
		return dst, ErrNilObject
	}
	output, err := value.encode(newEncoder(dst))
	if err != nil {
		return dst, err
	}
	return output.data(), nil
}

func newEncoder(buffer []byte) encoder {
	return encoder{buffer: buffer}
}

func (e *encoder) data() []byte {
	return e.buffer
}

func (e *encoder) putInt32(value int32) {
	e.putUint32(uint32(value))
}

func (e *encoder) putUint32(value uint32) {
	e.buffer = binary.LittleEndian.AppendUint32(e.buffer, value)
}

func (e *encoder) putInt64(value int64) {
	e.buffer = binary.LittleEndian.AppendUint64(e.buffer, uint64(value))
}

func (e *encoder) putFloat64(value float64) {
	e.buffer = binary.LittleEndian.AppendUint64(e.buffer, math.Float64bits(value))
}

func (e *encoder) putBool(value bool) {
	if value {
		e.putUint32(boolTrueConstructorID)
		return
	}
	e.putUint32(boolFalseConstructorID)
}

func (e *encoder) putNull() {
	e.putUint32(nullConstructorID)
}

func (e *encoder) putInt128(value [16]byte) {
	e.buffer = append(e.buffer, value[:]...)
}

func (e *encoder) putInt256(value [32]byte) {
	e.buffer = append(e.buffer, value[:]...)
}

func (e *encoder) putVectorHeader(count int) error {
	if err := validateVectorLength(count); err != nil {
		return err
	}
	e.putUint32(vectorConstructorID)
	e.putInt32(int32(count))
	return nil
}

func (e *encoder) putBareVectorHeader(count int) error {
	if err := validateVectorLength(count); err != nil {
		return err
	}
	e.putInt32(int32(count))
	return nil
}

func (e *encoder) putBytes(value []byte) error {
	padding, err := e.putBytesHeader(len(value))
	if err != nil {
		return err
	}
	e.buffer = append(e.buffer, value...)
	e.buffer = append(e.buffer, zeroPadding[:padding]...)
	return nil
}

func (e *encoder) putString(value string) error {
	padding, err := e.putBytesHeader(len(value))
	if err != nil {
		return err
	}
	e.buffer = append(e.buffer, value...)
	e.buffer = append(e.buffer, zeroPadding[:padding]...)
	return nil
}

func (e *encoder) putBytesHeader(length int) (int, error) {
	headerSize, padding, err := bytesLayout(length)
	if err != nil {
		return 0, err
	}
	if headerSize == 1 {
		e.buffer = append(e.buffer, byte(length))
		return padding, nil
	}
	e.buffer = append(
		e.buffer,
		254,
		byte(length),
		byte(length>>8),
		byte(length>>16),
	)
	return padding, nil
}

func bytesLayout(length int) (headerSize, padding int, err error) {
	switch {
	case length < 0:
		return 0, 0, fmt.Errorf("%w: negative size %d", ErrInvalidLength, length)
	case length <= 253:
		headerSize = 1
	case length <= maxBytesLength:
		headerSize = 4
	default:
		return 0, 0, fmt.Errorf(
			"%w: size %d exceeds %d",
			ErrInvalidLength,
			length,
			maxBytesLength,
		)
	}
	padding = -(headerSize + length) & 3
	return headerSize, padding, nil
}

func bytesEncodedSize(length int) (int, error) {
	headerSize, padding, err := bytesLayout(length)
	if err != nil {
		return 0, err
	}
	return headerSize + length + padding, nil
}

func checkedEncodedSizeAdd(left, right int) (int, error) {
	if left < 0 || right < 0 || right > int(^uint(0)>>1)-left {
		return 0, ErrSizeOverflow
	}
	return left + right, nil
}

func checkedEncodedSizeProduct(count, elementSize int) (int, error) {
	if count < 0 || elementSize < 0 {
		return 0, ErrSizeOverflow
	}
	if count != 0 && elementSize > int(^uint(0)>>1)/count {
		return 0, ErrSizeOverflow
	}
	return count * elementSize, nil
}

func validateVectorLength(length int) error {
	if length < 0 || int64(length) > maxVectorLength {
		return fmt.Errorf(
			"%w: vector size %d is outside 0..%d",
			ErrInvalidLength,
			length,
			maxVectorLength,
		)
	}
	return nil
}

func validateMessageBodyLength(declared int32, actual int) error {
	if declared < 4 || declared&3 != 0 || int64(declared) != int64(actual) {
		return fmt.Errorf(
			"%w: message body size %d does not match aligned object size %d",
			ErrInvalidLength,
			declared,
			actual,
		)
	}
	return nil
}
