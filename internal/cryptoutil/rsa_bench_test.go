package cryptoutil

import "testing"

var benchmarkRSACiphertext [rsaOutputSize]byte

func BenchmarkEncryptRSAPadded(b *testing.B) {
	publicKey := loadTelegramRSAPublicKey(b)
	for _, size := range []int{64, rsaMaxDataSize} {
		b.Run(benchmarkSizeNameRSA(size), func(b *testing.B) {
			data := sequentialBytes(size, 0x20)
			random := &benchmarkRandomReader{state: 1}

			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				var err error
				benchmarkRSACiphertext, err = EncryptRSAPadded(
					random,
					publicKey,
					data,
				)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

type benchmarkRandomReader struct {
	state uint64
}

func (r *benchmarkRandomReader) Read(output []byte) (int, error) {
	for index := range output {
		r.state ^= r.state << 13
		r.state ^= r.state >> 7
		r.state ^= r.state << 17
		output[index] = byte(r.state >> 56)
	}
	return len(output), nil
}

func benchmarkSizeNameRSA(size int) string {
	switch size {
	case 64:
		return "64B"
	case rsaMaxDataSize:
		return "144B"
	default:
		panic("unknown benchmark size")
	}
}
