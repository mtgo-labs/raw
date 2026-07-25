package tl

import (
	"bytes"
	"compress/gzip"
	"errors"
	"reflect"
	"testing"
)

func TestDecodeGzipPackedObjectAndResult(t *testing.T) {
	t.Parallel()

	limits := DefaultDecodeLimits()
	ping := &MTPPing{PingID: 0x0102030405060708}
	pingInput, err := Encode(ping)
	if err != nil {
		t.Fatalf("Encode ping: %v", err)
	}
	decodedPing, err := Decode(packGzipForTest(t, pingInput), limits)
	if err != nil {
		t.Fatalf("Decode packed ping: %v", err)
	}
	if !reflect.DeepEqual(decodedPing, ping) {
		t.Fatalf("decoded ping = %#v, want %#v", decodedPing, ping)
	}

	nearest := &NearestDC{Country: "IQ", ThisDC: 2, NearestDC: 4}
	nearestInput, err := Encode(nearest)
	if err != nil {
		t.Fatalf("Encode nearest DC: %v", err)
	}
	decodedNearest, err := DecodeResult(
		&HelpGetNearestDCRequest{},
		packGzipForTest(t, nearestInput),
		limits,
	)
	if err != nil {
		t.Fatalf("DecodeResult packed nearest DC: %v", err)
	}
	if !reflect.DeepEqual(decodedNearest, nearest) {
		t.Fatalf("decoded nearest DC = %#v, want %#v", decodedNearest, nearest)
	}
}

func TestDecodeNestedGzipPacked(t *testing.T) {
	t.Parallel()

	input, err := Encode(&MTPPing{PingID: 1})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	once := packGzipForTest(t, input)
	twice := packGzipForTest(t, once)

	limits := DefaultDecodeLimits()
	if _, err := Decode(twice, limits); err != nil {
		t.Fatalf("Decode nested gzip: %v", err)
	}

	limits.MaxDepth = 2
	if _, err := Decode(once, limits); err != nil {
		t.Fatalf("Decode one wrapper at depth 2: %v", err)
	}
	if _, err := Decode(twice, limits); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("nested depth error = %v, want ErrLimitExceeded", err)
	}

	limits = DefaultDecodeLimits()
	limits.MaxDecompressedBytes = len(once) + len(input)
	if _, err := Decode(twice, limits); err != nil {
		t.Fatalf("Decode at cumulative decompression limit: %v", err)
	}

	limits = DefaultDecodeLimits()
	limits.MaxDecompressedBytes = len(once) + len(input) - 1
	if _, err := Decode(twice, limits); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("cumulative decompression error = %v, want ErrLimitExceeded", err)
	}
}

func TestDecodeGzipPackedLimits(t *testing.T) {
	t.Parallel()

	payload, err := Encode(&MTPPing{PingID: 1})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	input := packGzipForTest(t, payload)

	limits := DefaultDecodeLimits()
	limits.MaxDecompressedBytes = len(payload)
	if _, err := Decode(input, limits); err != nil {
		t.Fatalf("Decode at decompression limit: %v", err)
	}

	limits = DefaultDecodeLimits()
	limits.MaxDecompressedBytes = len(payload) - 1
	if _, err := Decode(input, limits); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("decompression limit error = %v, want ErrLimitExceeded", err)
	}

	limits = DefaultDecodeLimits()
	limits.MaxDecompressedBytes = 0
	if _, err := Decode(input, limits); !errors.Is(
		err,
		ErrInvalidDecodeLimits,
	) {
		t.Fatalf("zero decompression limit error = %v", err)
	}

	bomb := packGzipForTest(t, make([]byte, 4096))
	limits = DefaultDecodeLimits()
	limits.MaxDecompressedBytes = 64
	if _, err := Decode(bomb, limits); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("gzip bomb error = %v, want ErrLimitExceeded", err)
	}
}

func TestDecodeGzipPackedRejectsMalformedStreams(t *testing.T) {
	t.Parallel()

	invalid := encodeGzipPackedForTest(t, []byte("not a gzip stream"))
	if _, err := Decode(invalid, DefaultDecodeLimits()); !errors.Is(
		err,
		gzip.ErrHeader,
	) {
		t.Fatalf("invalid header error = %v, want gzip.ErrHeader", err)
	}

	payload, err := Encode(&MTPPing{PingID: 1})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	compressed := gzipForTest(t, payload)
	compressed[len(compressed)-8] ^= 0xff
	if _, err := Decode(
		encodeGzipPackedForTest(t, compressed),
		DefaultDecodeLimits(),
	); !errors.Is(err, gzip.ErrChecksum) {
		t.Fatalf("checksum error = %v, want gzip.ErrChecksum", err)
	}

	concatenated := append(gzipForTest(t, payload), gzipForTest(t, payload)...)
	if _, err := Decode(
		encodeGzipPackedForTest(t, concatenated),
		DefaultDecodeLimits(),
	); !errors.Is(err, ErrTrailingData) {
		t.Fatalf("concatenated stream error = %v, want ErrTrailingData", err)
	}
}

func TestDecodeGzipPackedRejectsTrailingData(t *testing.T) {
	t.Parallel()

	payload, err := Encode(&MTPPing{PingID: 1})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	outerTrailing := append(packGzipForTest(t, payload), 0)
	if _, err := Decode(
		outerTrailing,
		DefaultDecodeLimits(),
	); !errors.Is(err, ErrTrailingData) {
		t.Fatalf("outer trailing error = %v, want ErrTrailingData", err)
	}

	innerTrailing := append(payload, 0)
	if _, err := Decode(
		packGzipForTest(t, innerTrailing),
		DefaultDecodeLimits(),
	); !errors.Is(err, ErrTrailingData) {
		t.Fatalf("inner trailing error = %v, want ErrTrailingData", err)
	}
}

func TestDecodeGzipPackedTruncation(t *testing.T) {
	t.Parallel()

	payload, err := Encode(&MTPPing{PingID: 1})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	input := packGzipForTest(t, payload)
	for end := range len(input) {
		if _, err := Decode(input[:end], DefaultDecodeLimits()); err == nil {
			t.Fatalf("Decode accepted %d/%d bytes", end, len(input))
		}
	}
}

func FuzzDecodeGzipPacked(f *testing.F) {
	payload, err := Encode(&MTPPing{PingID: 1})
	if err != nil {
		f.Fatalf("Encode: %v", err)
	}
	f.Add(gzipForTest(f, payload))
	f.Add([]byte("not a gzip stream"))
	f.Fuzz(func(t *testing.T, packed []byte) {
		if len(packed) > 4096 {
			t.Skip()
		}
		input := encodeGzipPackedForTest(t, packed)
		limits := DecodeLimits{
			MaxBytes:             8192,
			MaxVectorElements:    128,
			MaxDepth:             8,
			MaxAllocation:        16 << 10,
			MaxDecompressedBytes: 4096,
		}
		_, _ = Decode(input, limits)
	})
}

func BenchmarkGzipPackedDecode(b *testing.B) {
	payload, err := Encode(&NearestDC{
		Country:   "IQ",
		ThisDC:    2,
		NearestDC: 4,
	})
	if err != nil {
		b.Fatal(err)
	}
	input := packGzipForTest(b, payload)
	request := &HelpGetNearestDCRequest{}
	limits := DefaultDecodeLimits()

	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	for range b.N {
		benchmarkNearestDC, err = DecodeResult(request, input, limits)
		if err != nil {
			b.Fatal(err)
		}
	}
}

type testFataler interface {
	Helper()
	Fatalf(string, ...any)
}

func packGzipForTest(t testFataler, payload []byte) []byte {
	t.Helper()
	return encodeGzipPackedForTest(t, gzipForTest(t, payload))
}

func gzipForTest(t testFataler, payload []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := gzip.NewWriter(&output)
	if _, err := writer.Write(payload); err != nil {
		t.Fatalf("gzip Write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	return output.Bytes()
}

func encodeGzipPackedForTest(t testFataler, packed []byte) []byte {
	t.Helper()
	output := newEncoder(nil)
	output.putUint32(gzipPackedConstructorID)
	if err := output.putBytes(packed); err != nil {
		t.Fatalf("putBytes: %v", err)
	}
	return output.data()
}
