package tl

import "testing"

func BenchmarkGeneratedEncodeStrategy(b *testing.B) {
	salts := make([]MTPFutureSalt, 128)
	for index := range salts {
		salts[index] = MTPFutureSalt{
			ValidSince: int32(index),
			ValidUntil: int32(index + 60),
			Salt:       int64(index),
		}
	}
	cases := []struct {
		name      string
		value     Object
		heuristic int
	}{
		{
			name:      "SmallFixed",
			value:     &MTPPing{PingID: 1},
			heuristic: 64,
		},
		{
			name: "MediumBytes",
			value: &MTPServerDHInnerData{
				DHPrime: make([]byte, 1024),
				GA:      make([]byte, 1024),
			},
			heuristic: 2304,
		},
		{
			name: "BareObjectVector",
			value: &MTPFutureSalts{
				Salts: salts,
			},
			heuristic: 2080,
		},
	}
	for _, test := range cases {
		size, err := test.value.encodedSize()
		if err != nil {
			b.Fatalf("%s encodedSize: %v", test.name, err)
		}
		b.Run(test.name, func(b *testing.B) {
			b.SetBytes(int64(size))
			b.Run("Exact", func(b *testing.B) {
				b.ReportAllocs()
				for range b.N {
					encoded, err := Encode(test.value)
					if err != nil {
						b.Fatal(err)
					}
					benchmarkEncoded = encoded
				}
			})
			b.Run("Append", func(b *testing.B) {
				b.ReportAllocs()
				for range b.N {
					encoded, err := Append(nil, test.value)
					if err != nil {
						b.Fatal(err)
					}
					benchmarkEncoded = encoded
				}
			})
			b.Run("Heuristic", func(b *testing.B) {
				b.ReportAllocs()
				for range b.N {
					encoded, err := Append(
						make([]byte, 0, test.heuristic),
						test.value,
					)
					if err != nil {
						b.Fatal(err)
					}
					benchmarkEncoded = encoded
				}
			})
			b.Run("Reuse", func(b *testing.B) {
				output := make([]byte, 0, test.heuristic)
				b.ReportAllocs()
				for range b.N {
					encoded, err := Append(output[:0], test.value)
					if err != nil {
						b.Fatal(err)
					}
					benchmarkEncoded = encoded
				}
			})
		})
	}
}

func BenchmarkMessageContainerEncode(b *testing.B) {
	messages := make([]MTPMessage, 32)
	for index := range messages {
		messages[index] = MTPMessage{
			MessageID: int64(index + 1),
			Seqno:     int32(index*2 + 1),
			Bytes:     12,
			Body:      &MTPPing{PingID: int64(index)},
		}
	}
	value := &MTPMessageContainer{Messages: messages}
	b.ReportAllocs()
	for range b.N {
		encoded, err := Encode(value)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkEncoded = encoded
	}
}
