package tl

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strconv"
	"sync"
)

const (
	defaultMaxBytes            = 16 << 20
	defaultMaxVectorElements   = 1 << 20
	defaultMaxDepth            = 128
	defaultMaxDecodeAllocation = 64 << 20
	defaultMaxDecompressed     = 64 << 20
	gzipPackedConstructorID    = 0x3072cfa1
)

// DecodeLimits bounds work and memory derived from untrusted TL input.
// MaxDecompressedBytes is cumulative across nested gzip_packed wrappers and
// accounts for allocated output capacity, not only the decoded length.
type DecodeLimits struct {
	MaxBytes             int
	MaxVectorElements    int
	MaxDepth             int
	MaxAllocation        int
	MaxDecompressedBytes int
}

// DefaultDecodeLimits returns conservative limits suitable for ordinary RPC
// results. Callers handling larger payloads can raise individual limits.
func DefaultDecodeLimits() DecodeLimits {
	return DecodeLimits{
		MaxBytes:             defaultMaxBytes,
		MaxVectorElements:    defaultMaxVectorElements,
		MaxDepth:             defaultMaxDepth,
		MaxAllocation:        defaultMaxDecodeAllocation,
		MaxDecompressedBytes: defaultMaxDecompressed,
	}
}

type decodeLimits struct {
	maxBytes            int
	maxVectorElements   int
	maxDepth            int
	allocationRemaining int
	decompressionLeft   int
}

type decoder struct {
	input  []byte
	offset int
	depth  int
	limits decodeLimits
}

type gzipDecoder struct {
	source bytes.Reader
	reader *gzip.Reader
}

var gzipDecoderPool sync.Pool

// Decode parses one boxed API or MTProto constructor and rejects trailing data.
func Decode(input []byte, limits DecodeLimits) (Object, error) {
	decoder, err := newPublicDecoder(input, limits)
	if err != nil {
		return nil, err
	}
	if err := decoder.unpackGzip(); err != nil {
		return nil, err
	}
	value, err := decodeObject(&decoder)
	if err != nil {
		return nil, err
	}
	if decoder.remaining() != 0 {
		return nil, decoder.trailing()
	}
	return value, nil
}

// DecodeResult parses the exact result shape declared by request and rejects
// trailing data.
func DecodeResult[T any](
	request Request[T],
	input []byte,
	limits DecodeLimits,
) (T, error) {
	var zero T
	if request == nil {
		return zero, ErrNilObject
	}
	decoder, err := newPublicDecoder(input, limits)
	if err != nil {
		return zero, err
	}
	if err := decoder.unpackGzip(); err != nil {
		return zero, err
	}
	value, decoder, err := request.decodeResult(decoder)
	if err != nil {
		return zero, err
	}
	if decoder.remaining() != 0 {
		return zero, decoder.trailing()
	}
	return value, nil
}

func newPublicDecoder(input []byte, limits DecodeLimits) (decoder, error) {
	if limits.MaxBytes <= 0 ||
		limits.MaxVectorElements <= 0 ||
		limits.MaxDepth <= 0 ||
		limits.MaxAllocation <= 0 ||
		limits.MaxDecompressedBytes <= 0 {
		return decoder{}, ErrInvalidDecodeLimits
	}
	if len(input) > limits.MaxBytes {
		return decoder{}, &DecodeError{
			Operation: "input",
			Err: fmt.Errorf(
				"%w: size %d exceeds byte limit %d",
				ErrLimitExceeded,
				len(input),
				limits.MaxBytes,
			),
		}
	}
	return newDecoder(input, decodeLimits{
		maxBytes:            limits.MaxBytes,
		maxVectorElements:   limits.MaxVectorElements,
		maxDepth:            limits.MaxDepth,
		allocationRemaining: limits.MaxAllocation,
		decompressionLeft:   limits.MaxDecompressedBytes,
	}), nil
}

func newDecoder(input []byte, limits decodeLimits) decoder {
	return decoder{
		input:  input,
		limits: limits,
	}
}

func (d *decoder) remaining() int {
	return len(d.input) - d.offset
}

func (d *decoder) unexpectedConstructor(
	start int,
	expected string,
	constructor uint32,
) error {
	return &DecodeError{
		Offset:    start,
		Operation: expected,
		Err: fmt.Errorf(
			"%w: %s ID %#08x",
			ErrUnexpectedConstructor,
			expected,
			constructor,
		),
	}
}

func (d *decoder) trailing() error {
	return &DecodeError{
		Offset:    d.offset,
		Operation: "value",
		Err: fmt.Errorf(
			"%w: %d bytes remain",
			ErrTrailingData,
			d.remaining(),
		),
	}
}

type rpcResultData struct {
	body []byte
}

func (value *rpcResultData) ConstructorID() uint32 {
	return binary.LittleEndian.Uint32(value.body)
}

func (value *rpcResultData) encodedSize() (int, error) {
	return len(value.body), nil
}

func (value *rpcResultData) encode(output encoder) (encoder, error) {
	output.buffer = append(output.buffer, value.body...)
	return output, nil
}

func (d *decoder) readObject() (Object, error) {
	start := d.offset
	if d.remaining() < 4 {
		return nil, d.truncated("RPC result", 4)
	}
	if binary.LittleEndian.Uint32(d.input[start:]) == gzipPackedConstructorID {
		if err := d.unpackGzip(); err != nil {
			return nil, err
		}
		start = d.offset
		if d.remaining() < 4 {
			return nil, d.truncated("RPC result", 4)
		}
	}
	if d.remaining()&3 != 0 {
		return nil, &DecodeError{
			Offset:    start,
			Operation: "RPC result",
			Err:       fmt.Errorf("%w: size %d is not four-byte aligned", ErrInvalidLength, d.remaining()),
		}
	}
	if binary.LittleEndian.Uint32(d.input[start:]) == MTPRPCErrorConstructorID {
		return decodeObject(d)
	}
	value := &rpcResultData{body: d.input[start:]}
	d.offset = len(d.input)
	return value, nil
}

func (d *decoder) readMessageBody(size int32) (Object, error) {
	start := d.offset
	if size < 4 || size&3 != 0 {
		return nil, &DecodeError{
			Offset:    start,
			Operation: "message body",
			Err: fmt.Errorf(
				"%w: size %d is not positive and four-byte aligned",
				ErrInvalidLength,
				size,
			),
		}
	}
	if int64(size) > int64(d.remaining()) {
		return nil, d.truncated("message body", int(size))
	}

	end := start + int(size)
	nested := decoder{
		input:  d.input[start:end],
		depth:  d.depth,
		limits: d.limits,
	}
	if err := nested.unpackGzip(); err != nil {
		d.limits = nested.limits
		return nil, rebaseDecodeError(err, start)
	}
	value, err := decodeObject(&nested)
	d.limits = nested.limits
	if err != nil {
		return nil, rebaseDecodeError(err, start)
	}
	if nested.remaining() != 0 {
		return nil, rebaseDecodeError(nested.trailing(), start)
	}
	d.offset = end
	return value, nil
}

func rebaseDecodeError(err error, base int) error {
	decoded, ok := err.(*DecodeError)
	if !ok {
		return err
	}
	rebased := *decoded
	rebased.Offset += base
	return &rebased
}

func decodedAllocationSize(size32, size64 int) int {
	if strconv.IntSize == 64 {
		return size64
	}
	return size32
}

func (d *decoder) unpackGzip() error {
	for d.remaining() >= 4 &&
		binary.LittleEndian.Uint32(d.input[d.offset:]) == gzipPackedConstructorID {
		if err := d.enter(); err != nil {
			return err
		}
		d.offset += 4
		packed, err := d.readBytesView()
		if err != nil {
			return err
		}
		if d.remaining() != 0 {
			return d.trailing()
		}
		unpacked, err := d.gunzip(packed)
		if err != nil {
			return err
		}
		d.input = unpacked
		d.offset = 0
	}
	return nil
}

func (d *decoder) gunzip(packed []byte) ([]byte, error) {
	pooled := gzipDecoderPool.Get()
	var decoder *gzipDecoder
	if pooled == nil {
		decoder = new(gzipDecoder)
	} else {
		decoder = pooled.(*gzipDecoder)
	}
	decoder.source.Reset(packed)

	var err error
	if decoder.reader == nil {
		decoder.reader, err = gzip.NewReader(&decoder.source)
	} else {
		err = decoder.reader.Reset(&decoder.source)
	}
	if err != nil {
		decoder.source.Reset(nil)
		gzipDecoderPool.Put(decoder)
		return nil, gzipDecodeError(d.offset, err)
	}
	decoder.reader.Multistream(false)

	limit := d.limits.decompressionLeft
	capacity := gzipInitialCapacity(packed, limit)
	output := make([]byte, 0, capacity)
	var readError error
	for {
		if len(output) == cap(output) {
			if len(output) == limit {
				var extra [1]byte
				count, err := decoder.reader.Read(extra[:])
				if count != 0 {
					readError = fmt.Errorf(
						"%w: output exceeds %d bytes",
						ErrLimitExceeded,
						limit,
					)
				} else if err == nil {
					readError = io.ErrNoProgress
				} else {
					readError = err
				}
				break
			}
			nextCapacity := min(limit, max(512, cap(output)*2))
			next := make([]byte, len(output), nextCapacity)
			copy(next, output)
			output = next
		}
		start := len(output)
		count, err := decoder.reader.Read(output[start:cap(output)])
		output = output[:start+count]
		switch {
		case err == nil && count != 0:
			continue
		case err == nil:
			readError = io.ErrNoProgress
		case err == io.EOF:
			readError = nil
		default:
			readError = err
		}
		break
	}
	trailing := decoder.source.Len()
	closeError := decoder.reader.Close()
	decoder.source.Reset(nil)
	gzipDecoderPool.Put(decoder)
	if readError != nil {
		return nil, gzipDecodeError(d.offset, readError)
	}
	if closeError != nil {
		return nil, gzipDecodeError(d.offset, closeError)
	}
	if trailing != 0 {
		return nil, gzipDecodeError(d.offset, ErrTrailingData)
	}
	d.limits.decompressionLeft -= cap(output)
	return output, nil
}

func gzipInitialCapacity(packed []byte, limit int) int {
	if limit <= 0 {
		return 0
	}
	const gzipTrailerSize = 8
	if len(packed) >= gzipTrailerSize {
		size := int(binary.LittleEndian.Uint32(packed[len(packed)-4:]))
		maxHint := len(packed) * 8
		if maxHint/8 == len(packed) &&
			size > 0 &&
			size <= limit &&
			size <= maxHint {
			return size
		}
	}
	return min(512, limit)
}

func gzipDecodeError(offset int, err error) error {
	return &DecodeError{
		Offset:    offset,
		Operation: "gzip_packed",
		Err:       err,
	}
}

func (d *decoder) readInt32() (int32, error) {
	value, err := d.readUint32()
	return int32(value), err
}

func (d *decoder) readUint32() (uint32, error) {
	const size = 4
	if d.remaining() < size {
		return 0, d.truncated("uint32", size)
	}
	value := binary.LittleEndian.Uint32(d.input[d.offset:])
	d.offset += size
	return value, nil
}

func (d *decoder) readInt64() (int64, error) {
	const size = 8
	if d.remaining() < size {
		return 0, d.truncated("int64", size)
	}
	value := int64(binary.LittleEndian.Uint64(d.input[d.offset:]))
	d.offset += size
	return value, nil
}

func (d *decoder) readFloat64() (float64, error) {
	const size = 8
	if d.remaining() < size {
		return 0, d.truncated("float64", size)
	}
	value := math.Float64frombits(binary.LittleEndian.Uint64(d.input[d.offset:]))
	d.offset += size
	return value, nil
}

func (d *decoder) readBool() (bool, error) {
	start := d.offset
	constructor, err := d.readUint32()
	if err != nil {
		return false, err
	}
	switch constructor {
	case boolTrueConstructorID:
		return true, nil
	case boolFalseConstructorID:
		return false, nil
	default:
		return false, &DecodeError{
			Offset:    start,
			Operation: "bool",
			Err: fmt.Errorf(
				"%w: bool ID %#08x",
				ErrUnexpectedConstructor,
				constructor,
			),
		}
	}
}

func (d *decoder) readNull() error {
	start := d.offset
	constructor, err := d.readUint32()
	if err != nil {
		return err
	}
	if constructor != nullConstructorID {
		return &DecodeError{
			Offset:    start,
			Operation: "null",
			Err: fmt.Errorf(
				"%w: null ID %#08x",
				ErrUnexpectedConstructor,
				constructor,
			),
		}
	}
	return nil
}

func (d *decoder) readInt128() ([16]byte, error) {
	const size = 16
	if d.remaining() < size {
		return [16]byte{}, d.truncated("int128", size)
	}
	var value [size]byte
	copy(value[:], d.input[d.offset:d.offset+size])
	d.offset += size
	return value, nil
}

func (d *decoder) readInt256() ([32]byte, error) {
	const size = 32
	if d.remaining() < size {
		return [32]byte{}, d.truncated("int256", size)
	}
	var value [size]byte
	copy(value[:], d.input[d.offset:d.offset+size])
	d.offset += size
	return value, nil
}

func (d *decoder) readVectorHeader() (int, error) {
	start := d.offset
	constructor, err := d.readUint32()
	if err != nil {
		return 0, err
	}
	if constructor != vectorConstructorID {
		return 0, &DecodeError{
			Offset:    start,
			Operation: "vector",
			Err: fmt.Errorf(
				"%w: vector ID %#08x",
				ErrUnexpectedConstructor,
				constructor,
			),
		}
	}
	return d.readVectorLength()
}

func (d *decoder) readBareVectorHeader() (int, error) {
	return d.readVectorLength()
}

func (d *decoder) readVectorLength() (int, error) {
	start := d.offset
	count, err := d.readInt32()
	if err != nil {
		return 0, err
	}
	if count < 0 {
		return 0, &DecodeError{
			Offset:    start,
			Operation: "vector length",
			Err: fmt.Errorf(
				"%w: negative vector size %d",
				ErrInvalidLength,
				count,
			),
		}
	}
	if int(count) > d.limits.maxVectorElements {
		return 0, &DecodeError{
			Offset:    start,
			Operation: "vector length",
			Err: fmt.Errorf(
				"%w: vector size %d exceeds element limit %d",
				ErrLimitExceeded,
				count,
				d.limits.maxVectorElements,
			),
		}
	}
	return int(count), nil
}

func (d *decoder) readBytes() ([]byte, error) {
	value, err := d.readBytesView()
	if err != nil {
		return nil, err
	}
	if err := d.reserveAllocation("bytes", len(value)); err != nil {
		return nil, err
	}
	result := make([]byte, len(value))
	copy(result, value)
	return result, nil
}

func (d *decoder) readString() (string, error) {
	value, err := d.readBytesView()
	if err != nil {
		return "", err
	}
	if err := d.reserveAllocation("string", len(value)); err != nil {
		return "", err
	}
	return string(value), nil
}

func (d *decoder) readBytesView() ([]byte, error) {
	start := d.offset
	if d.remaining() < 1 {
		return nil, d.truncated("bytes", 1)
	}

	first := d.input[start]
	var headerSize, length int
	switch {
	case first <= 253:
		headerSize = 1
		length = int(first)
	case first == 254:
		headerSize = 4
		if d.remaining() < headerSize {
			return nil, d.truncated("bytes length", headerSize)
		}
		length = int(d.input[start+1]) |
			int(d.input[start+2])<<8 |
			int(d.input[start+3])<<16
		if length < 254 {
			return nil, &DecodeError{
				Offset:    start,
				Operation: "bytes",
				Err: fmt.Errorf(
					"%w: extended size %d is below 254",
					ErrInvalidLength,
					length,
				),
			}
		}
	default:
		return nil, &DecodeError{
			Offset:    start,
			Operation: "bytes",
			Err:       fmt.Errorf("%w: invalid length marker 255", ErrInvalidLength),
		}
	}

	if length > d.limits.maxBytes {
		return nil, &DecodeError{
			Offset:    start,
			Operation: "bytes",
			Err: fmt.Errorf(
				"%w: size %d exceeds byte limit %d",
				ErrLimitExceeded,
				length,
				d.limits.maxBytes,
			),
		}
	}

	_, padding, err := bytesLayout(length)
	if err != nil {
		return nil, &DecodeError{
			Offset:    start,
			Operation: "bytes",
			Err:       err,
		}
	}
	total := headerSize + length + padding
	if d.remaining() < total {
		return nil, d.truncated("bytes payload", total)
	}
	payloadStart := start + headerSize
	payloadEnd := payloadStart + length
	for _, value := range d.input[payloadEnd : payloadEnd+padding] {
		if value != 0 {
			return nil, &DecodeError{
				Offset:    payloadEnd,
				Operation: "bytes padding",
				Err:       ErrInvalidPadding,
			}
		}
	}
	d.offset += total
	return d.input[payloadStart:payloadEnd], nil
}

func (d *decoder) reserveAllocation(operation string, size int) error {
	if size > d.limits.allocationRemaining {
		return &DecodeError{
			Offset:    d.offset,
			Operation: operation,
			Err: fmt.Errorf(
				"%w: allocation %d exceeds remaining budget %d",
				ErrLimitExceeded,
				size,
				d.limits.allocationRemaining,
			),
		}
	}
	d.limits.allocationRemaining -= size
	return nil
}

func (d *decoder) reserveAllocationProduct(
	operation string,
	count int,
	elementSize int,
) error {
	if count < 0 || elementSize < 0 {
		return &DecodeError{
			Offset:    d.offset,
			Operation: operation,
			Err: fmt.Errorf(
				"%w: allocation dimensions %d by %d",
				ErrInvalidLength,
				count,
				elementSize,
			),
		}
	}
	if count == 0 || elementSize == 0 {
		return nil
	}
	if elementSize > d.limits.allocationRemaining ||
		count > d.limits.allocationRemaining/elementSize {
		return &DecodeError{
			Offset:    d.offset,
			Operation: operation,
			Err: fmt.Errorf(
				"%w: allocation %d by %d exceeds remaining budget %d",
				ErrLimitExceeded,
				count,
				elementSize,
				d.limits.allocationRemaining,
			),
		}
	}
	return d.reserveAllocation(operation, count*elementSize)
}

func (d *decoder) enter() error {
	if d.depth >= d.limits.maxDepth {
		return &DecodeError{
			Offset:    d.offset,
			Operation: "nested value",
			Err: fmt.Errorf(
				"%w: depth %d reaches limit %d",
				ErrLimitExceeded,
				d.depth,
				d.limits.maxDepth,
			),
		}
	}
	d.depth++
	return nil
}

func (d *decoder) leave() {
	if d.depth > 0 {
		d.depth--
	}
}

func (d *decoder) truncated(operation string, size int) error {
	return &DecodeError{
		Offset:    d.offset,
		Operation: operation,
		Err: fmt.Errorf(
			"%w: need %d bytes, have %d",
			ErrUnexpectedEOF,
			size,
			d.remaining(),
		),
	}
}
