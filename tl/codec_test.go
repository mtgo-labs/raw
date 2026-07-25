package tl

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"testing"
)

type primitiveManifest struct {
	Fixtures []primitiveFixture `json:"fixtures"`
}

type primitiveFixture struct {
	Name      string `json:"name"`
	Operation string `json:"operation"`
	Hex       string `json:"hex"`
}

func TestPrimitiveFixtures(t *testing.T) {
	t.Parallel()

	for _, fixture := range loadPrimitiveFixtures(t) {
		t.Run(fixture.Name, func(t *testing.T) {
			t.Parallel()

			want, err := hex.DecodeString(fixture.Hex)
			if err != nil {
				t.Fatalf("decode fixture hex: %v", err)
			}
			decoder := newDecoder(want, decodeLimits{
				maxBytes:            maxBytesLength,
				maxVectorElements:   math.MaxInt32,
				maxDepth:            64,
				allocationRemaining: maxBytesLength,
			})
			var encoder encoder
			decodeAndReencodeFixture(t, fixture, &decoder, &encoder)
			if decoder.remaining() != 0 {
				t.Fatalf("decoder has %d trailing bytes", decoder.remaining())
			}
			if !bytes.Equal(encoder.data(), want) {
				t.Fatalf(
					"encoded bytes = %x, want %x",
					encoder.data(),
					want,
				)
			}
		})
	}
}

func TestPrimitiveFixtureTruncation(t *testing.T) {
	t.Parallel()

	for _, fixture := range loadPrimitiveFixtures(t) {
		t.Run(fixture.Name, func(t *testing.T) {
			t.Parallel()

			input, err := hex.DecodeString(fixture.Hex)
			if err != nil {
				t.Fatalf("decode fixture hex: %v", err)
			}
			for end := range len(input) {
				decoder := newDecoder(input[:end], decodeLimits{
					maxBytes:            maxBytesLength,
					maxVectorElements:   math.MaxInt32,
					maxDepth:            64,
					allocationRemaining: maxBytesLength,
				})
				err := decodeFixture(fixture, &decoder)
				if !errors.Is(err, ErrUnexpectedEOF) {
					t.Fatalf(
						"decode %d/%d bytes error = %v, want ErrUnexpectedEOF",
						end,
						len(input),
						err,
					)
				}
			}
		})
	}
}

func TestDecoderRejectsMalformedBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input []byte
		want  error
	}{
		{"marker 255", []byte{255, 0, 0, 0}, ErrInvalidLength},
		{"non-canonical extended length", []byte{254, 253, 0, 0}, ErrInvalidLength},
		{"declared length exceeds input", []byte{3, 1, 2}, ErrUnexpectedEOF},
		{"non-zero padding", []byte{1, 'x', 1, 0}, ErrInvalidPadding},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			decoder := newDecoder(tc.input, decodeLimits{
				maxBytes:            maxBytesLength,
				allocationRemaining: maxBytesLength,
			})
			_, err := decoder.readBytes()
			if !errors.Is(err, tc.want) {
				t.Fatalf("readBytes error = %v, want %v", err, tc.want)
			}
			var decodeError *DecodeError
			if !errors.As(err, &decodeError) {
				t.Fatalf("readBytes error type = %T, want *DecodeError", err)
			}
		})
	}
}

func TestDecoderEnforcesByteAndAllocationLimits(t *testing.T) {
	t.Parallel()

	var encoded encoder
	if err := encoded.putBytes([]byte("abcd")); err != nil {
		t.Fatalf("putBytes: %v", err)
	}

	byteLimited := newDecoder(encoded.data(), decodeLimits{
		maxBytes:            3,
		allocationRemaining: 4,
	})
	if _, err := byteLimited.readBytes(); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("byte-limited readBytes error = %v, want ErrLimitExceeded", err)
	}

	allocationLimited := newDecoder(encoded.data(), decodeLimits{
		maxBytes:            4,
		allocationRemaining: 3,
	})
	if _, err := allocationLimited.readBytes(); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("allocation-limited readBytes error = %v, want ErrLimitExceeded", err)
	}

	var repeated encoder
	if err := repeated.putBytes([]byte("abc")); err != nil {
		t.Fatalf("first putBytes: %v", err)
	}
	if err := repeated.putBytes([]byte("def")); err != nil {
		t.Fatalf("second putBytes: %v", err)
	}
	cumulative := newDecoder(repeated.data(), decodeLimits{
		maxBytes:            3,
		allocationRemaining: 5,
	})
	if _, err := cumulative.readBytes(); err != nil {
		t.Fatalf("first cumulative readBytes: %v", err)
	}
	if _, err := cumulative.readBytes(); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("second cumulative readBytes error = %v, want ErrLimitExceeded", err)
	}
}

func TestDecoderBytesOwnsResult(t *testing.T) {
	t.Parallel()

	input := []byte{3, 'a', 'b', 'c'}
	decoder := newDecoder(input, decodeLimits{
		maxBytes:            3,
		allocationRemaining: 3,
	})
	value, err := decoder.readBytes()
	if err != nil {
		t.Fatalf("readBytes: %v", err)
	}
	input[1] = 'z'
	if string(value) != "abc" {
		t.Fatalf("decoded bytes changed with input: %q", value)
	}
}

func TestPrimitiveRoundTrip(t *testing.T) {
	t.Parallel()

	var encoder encoder
	encoder.putInt64(math.MinInt64)
	if err := encoder.putString("raw"); err != nil {
		t.Fatalf("putString: %v", err)
	}

	decoder := newDecoder(encoder.data(), decodeLimits{
		maxBytes:            3,
		allocationRemaining: 3,
	})
	integer, err := decoder.readInt64()
	if err != nil {
		t.Fatalf("readInt64: %v", err)
	}
	if integer != math.MinInt64 {
		t.Fatalf("readInt64 = %d, want %d", integer, int64(math.MinInt64))
	}
	text, err := decoder.readString()
	if err != nil {
		t.Fatalf("readString: %v", err)
	}
	if text != "raw" {
		t.Fatalf("readString = %q, want raw", text)
	}
}

func TestDecoderRejectsUnexpectedConstructors(t *testing.T) {
	t.Parallel()

	input := []byte{0, 0, 0, 0}
	boolDecoder := newDecoder(input, decodeLimits{})
	if _, err := boolDecoder.readBool(); !errors.Is(err, ErrUnexpectedConstructor) {
		t.Fatalf("readBool error = %v, want ErrUnexpectedConstructor", err)
	}
	nullDecoder := newDecoder(input, decodeLimits{})
	if err := nullDecoder.readNull(); !errors.Is(err, ErrUnexpectedConstructor) {
		t.Fatalf("readNull error = %v, want ErrUnexpectedConstructor", err)
	}
}

func TestBytesLayoutRejectsInvalidLength(t *testing.T) {
	t.Parallel()

	for _, length := range []int{-1, maxBytesLength + 1} {
		if _, _, err := bytesLayout(length); !errors.Is(err, ErrInvalidLength) {
			t.Errorf("bytesLayout(%d) error = %v, want ErrInvalidLength", length, err)
		}
	}
}

func TestVectorRejectsInvalidConstructorLengthAndLimit(t *testing.T) {
	t.Parallel()

	var wrongConstructor encoder
	wrongConstructor.putUint32(0)
	wrongConstructor.putInt32(0)
	decoder := newDecoder(wrongConstructor.data(), decodeLimits{
		maxVectorElements: 1,
	})
	if _, err := decoder.readVectorHeader(); !errors.Is(
		err,
		ErrUnexpectedConstructor,
	) {
		t.Fatalf("wrong constructor error = %v, want ErrUnexpectedConstructor", err)
	}

	var negative encoder
	negative.putInt32(-1)
	decoder = newDecoder(negative.data(), decodeLimits{
		maxVectorElements: 1,
	})
	if _, err := decoder.readBareVectorHeader(); !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("negative count error = %v, want ErrInvalidLength", err)
	}

	var excessive encoder
	if err := excessive.putVectorHeader(4); err != nil {
		t.Fatalf("putVectorHeader: %v", err)
	}
	decoder = newDecoder(excessive.data(), decodeLimits{
		maxVectorElements: 3,
	})
	if _, err := decoder.readVectorHeader(); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("excessive count error = %v, want ErrLimitExceeded", err)
	}
}

func TestEncoderRejectsInvalidVectorLength(t *testing.T) {
	t.Parallel()

	var encoder encoder
	if err := encoder.putVectorHeader(-1); !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("negative vector error = %v, want ErrInvalidLength", err)
	}
	if len(encoder.data()) != 0 {
		t.Fatalf("failed vector encoding wrote %d bytes", len(encoder.data()))
	}
}

func TestDecoderReservesVectorAllocation(t *testing.T) {
	t.Parallel()

	decoder := newDecoder(nil, decodeLimits{allocationRemaining: 15})
	if err := decoder.reserveAllocationProduct("vector", 4, 4); !errors.Is(
		err,
		ErrLimitExceeded,
	) {
		t.Fatalf("oversized reservation error = %v, want ErrLimitExceeded", err)
	}
	if err := decoder.reserveAllocationProduct("vector", 3, 4); err != nil {
		t.Fatalf("valid reservation: %v", err)
	}
	if decoder.limits.allocationRemaining != 3 {
		t.Fatalf(
			"remaining allocation = %d, want 3",
			decoder.limits.allocationRemaining,
		)
	}
	if err := decoder.reserveAllocationProduct("vector", -1, 4); !errors.Is(
		err,
		ErrInvalidLength,
	) {
		t.Fatalf("negative reservation error = %v, want ErrInvalidLength", err)
	}
}

func TestDecoderEnforcesNestingDepth(t *testing.T) {
	t.Parallel()

	decoder := newDecoder(nil, decodeLimits{maxDepth: 2})
	if err := decoder.enter(); err != nil {
		t.Fatalf("first enter: %v", err)
	}
	if err := decoder.enter(); err != nil {
		t.Fatalf("second enter: %v", err)
	}
	if err := decoder.enter(); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("third enter error = %v, want ErrLimitExceeded", err)
	}
	decoder.leave()
	if err := decoder.enter(); err != nil {
		t.Fatalf("enter after leave: %v", err)
	}
}

func FuzzDecoderBytes(f *testing.F) {
	for _, seed := range [][]byte{
		{},
		{0, 0, 0, 0},
		{1, 'x', 0, 0},
		{254, 254, 0, 0},
		{255, 0, 0, 0},
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 4096 {
			t.Skip()
		}
		decoder := newDecoder(input, decodeLimits{
			maxBytes:            1024,
			allocationRemaining: 1024,
		})
		value, err := decoder.readBytes()
		if err == nil && len(value) > 1024 {
			t.Fatalf("decoded %d bytes with limit 1024", len(value))
		}
		if decoder.offset < 0 || decoder.offset > len(input) {
			t.Fatalf("decoder offset %d outside input length %d", decoder.offset, len(input))
		}
	})
}

func FuzzDecoderVectorHeader(f *testing.F) {
	for _, seed := range [][]byte{
		{},
		{0x15, 0xc4, 0xb5, 0x1c, 0, 0, 0, 0},
		{0x15, 0xc4, 0xb5, 0x1c, 0xff, 0xff, 0xff, 0xff},
		{0, 0, 0, 0, 0, 0, 0, 0},
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		decoder := newDecoder(input, decodeLimits{maxVectorElements: 1024})
		count, err := decoder.readVectorHeader()
		if err == nil && (count < 0 || count > 1024) {
			t.Fatalf("decoded vector count %d outside limit", count)
		}
		if decoder.offset < 0 || decoder.offset > len(input) {
			t.Fatalf("decoder offset %d outside input length %d", decoder.offset, len(input))
		}
	})
}

func decodeAndReencodeFixture(
	t *testing.T,
	fixture primitiveFixture,
	decoder *decoder,
	encoder *encoder,
) {
	t.Helper()

	switch fixture.Operation {
	case "int":
		value, err := decoder.readInt32()
		requireNoError(t, err)
		encoder.putInt32(value)
	case "uint":
		value, err := decoder.readUint32()
		requireNoError(t, err)
		encoder.putUint32(value)
	case "boolean":
		value, err := decoder.readBool()
		requireNoError(t, err)
		encoder.putBool(value)
	case "double":
		value, err := decoder.readFloat64()
		requireNoError(t, err)
		encoder.putFloat64(value)
	case "null":
		requireNoError(t, decoder.readNull())
		encoder.putNull()
	case "bytes":
		value, err := decoder.readBytes()
		requireNoError(t, err)
		requireNoError(t, encoder.putBytes(value))
	case "string":
		value, err := decoder.readString()
		requireNoError(t, err)
		requireNoError(t, encoder.putString(value))
	case "int128":
		value, err := decoder.readInt128()
		requireNoError(t, err)
		encoder.putInt128(value)
	case "int256":
		value, err := decoder.readInt256()
		requireNoError(t, err)
		encoder.putInt256(value)
	case "vector-int", "bare-vector-int":
		count, err := readFixtureVectorHeader(fixture.Operation, decoder)
		requireNoError(t, err)
		requireNoError(t, decoder.reserveAllocationProduct("vector<int>", count, 4))
		values := make([]int32, count)
		requireNoError(t, putFixtureVectorHeader(fixture.Operation, encoder, count))
		for index := range values {
			values[index], err = decoder.readInt32()
			requireNoError(t, err)
			encoder.putInt32(values[index])
		}
	default:
		t.Fatalf("unsupported fixture operation %q", fixture.Operation)
	}
}

func decodeFixture(fixture primitiveFixture, decoder *decoder) error {
	switch fixture.Operation {
	case "int":
		_, err := decoder.readInt32()
		return err
	case "uint":
		_, err := decoder.readUint32()
		return err
	case "boolean":
		_, err := decoder.readBool()
		return err
	case "double":
		_, err := decoder.readFloat64()
		return err
	case "null":
		return decoder.readNull()
	case "bytes":
		_, err := decoder.readBytes()
		return err
	case "string":
		_, err := decoder.readString()
		return err
	case "int128":
		_, err := decoder.readInt128()
		return err
	case "int256":
		_, err := decoder.readInt256()
		return err
	case "vector-int", "bare-vector-int":
		count, err := readFixtureVectorHeader(fixture.Operation, decoder)
		if err != nil {
			return err
		}
		for range count {
			if _, err := decoder.readInt32(); err != nil {
				return err
			}
		}
		return nil
	default:
		panic("unsupported fixture operation " + fixture.Operation)
	}
}

func readFixtureVectorHeader(operation string, decoder *decoder) (int, error) {
	if operation == "vector-int" {
		return decoder.readVectorHeader()
	}
	return decoder.readBareVectorHeader()
}

func putFixtureVectorHeader(
	operation string,
	encoder *encoder,
	count int,
) error {
	if operation == "vector-int" {
		return encoder.putVectorHeader(count)
	}
	return encoder.putBareVectorHeader(count)
}

func loadPrimitiveFixtures(t *testing.T) []primitiveFixture {
	t.Helper()

	data, err := os.ReadFile("../testdata/upstream/tl-primitives/manifest.json")
	if err != nil {
		t.Fatalf("read primitive manifest: %v", err)
	}
	var manifest primitiveManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("decode primitive manifest: %v", err)
	}
	return manifest.Fixtures
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
