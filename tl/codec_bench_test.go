package tl

import "testing"

var (
	benchmarkEncoded []byte
	benchmarkInts    []int32
	benchmarkString  string
)

func BenchmarkTLEncodeSmall(b *testing.B) {
	const capacity = 28

	b.Run("Append", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			var encoder encoder
			encodeBenchmarkValue(&encoder)
			benchmarkEncoded = encoder.data()
		}
	})

	b.Run("Preallocated", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			encoder := newEncoder(make([]byte, 0, capacity))
			encodeBenchmarkValue(&encoder)
			benchmarkEncoded = encoder.data()
		}
	})
}

func BenchmarkTLDecodeSmall(b *testing.B) {
	encoder := newEncoder(make([]byte, 0, 28))
	encodeBenchmarkValue(&encoder)
	input := encoder.data()

	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	for range b.N {
		decoder := newDecoder(input, decodeLimits{
			maxBytes:            11,
			allocationRemaining: 11,
		})
		if _, err := decoder.readUint32(); err != nil {
			b.Fatal(err)
		}
		if _, err := decoder.readInt64(); err != nil {
			b.Fatal(err)
		}
		if _, err := decoder.readBool(); err != nil {
			b.Fatal(err)
		}
		value, err := decoder.readString()
		if err != nil {
			b.Fatal(err)
		}
		benchmarkString = value
	}
}

func BenchmarkTLEncodeNested(b *testing.B) {
	const (
		outerCount = 16
		innerCount = 16
		size       = 8 + outerCount*(8+innerCount*4)
	)

	b.ReportAllocs()
	b.SetBytes(size)
	for range b.N {
		encoder := newEncoder(make([]byte, 0, size))
		if err := encoder.putVectorHeader(outerCount); err != nil {
			b.Fatal(err)
		}
		for range outerCount {
			if err := encoder.putVectorHeader(innerCount); err != nil {
				b.Fatal(err)
			}
			for value := range innerCount {
				encoder.putInt32(int32(value))
			}
		}
		benchmarkEncoded = encoder.data()
	}
}

func BenchmarkTLDecodeLargeVector(b *testing.B) {
	const count = 1024

	encoder := newEncoder(make([]byte, 0, 8+count*4))
	if err := encoder.putVectorHeader(count); err != nil {
		b.Fatal(err)
	}
	for value := range count {
		encoder.putInt32(int32(value))
	}
	input := encoder.data()

	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	for range b.N {
		decoder := newDecoder(input, decodeLimits{
			maxVectorElements:   count,
			allocationRemaining: count * 4,
		})
		length, err := decoder.readVectorHeader()
		if err != nil {
			b.Fatal(err)
		}
		if err := decoder.reserveAllocationProduct("vector<int>", length, 4); err != nil {
			b.Fatal(err)
		}
		values := make([]int32, length)
		for index := range values {
			values[index], err = decoder.readInt32()
			if err != nil {
				b.Fatal(err)
			}
		}
		benchmarkInts = values
	}
}

func encodeBenchmarkValue(encoder *encoder) {
	encoder.putUint32(0x12345678)
	encoder.putInt64(0x1234567890abcdef)
	encoder.putBool(true)
	if err := encoder.putString("mtcute 🐈"); err != nil {
		panic(err)
	}
}
