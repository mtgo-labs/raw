package cryptoutil

import "testing"

var (
	benchmarkP uint64
	benchmarkQ uint64
)

func BenchmarkFactorPQ(b *testing.B) {
	for _, pq := range []uint64{
		2090522174869285481,
		1470626929934143021,
		2804275833720261793,
		18446743979220271189,
	} {
		b.Run(benchmarkPQName(pq), func(b *testing.B) {
			encodedPQ := encodeUint64(pq)
			random := &testRandomReader{state: pq}

			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				var err error
				benchmarkP, benchmarkQ, err = FactorPQ(random, encodedPQ)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func benchmarkPQName(pq uint64) string {
	switch pq {
	case 2090522174869285481:
		return "vector_1"
	case 1470626929934143021:
		return "vector_2"
	case 2804275833720261793:
		return "vector_3"
	case 18446743979220271189:
		return "64_bit"
	default:
		panic("unknown pq benchmark")
	}
}
