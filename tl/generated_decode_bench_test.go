package tl

import "testing"

var (
	benchmarkDispatchResult bool
	benchmarkDecodedObject  Object
	benchmarkNearestDC      *NearestDC
	benchmarkBoolResult     bool
)

func BenchmarkConstructorDispatch(b *testing.B) {
	table := make(map[uint32]func() bool, len(benchmarkConstructorIDs))
	for _, constructor := range benchmarkConstructorIDs {
		table[constructor] = benchmarkConstructorFound
	}
	var inputs [1024]uint32
	for index := range inputs {
		inputs[index] = benchmarkConstructorIDs[(index*1597)%len(benchmarkConstructorIDs)]
	}

	b.Run("Switch", func(b *testing.B) {
		b.ReportAllocs()
		for index := range b.N {
			benchmarkDispatchResult = benchmarkConstructorSwitch(
				inputs[index&(len(inputs)-1)],
			)
		}
	})
	b.Run("FunctionTable", func(b *testing.B) {
		b.ReportAllocs()
		for index := range b.N {
			found := table[inputs[index&(len(inputs)-1)]]
			benchmarkDispatchResult = found()
		}
	})
	b.Run("SplitSwitch", func(b *testing.B) {
		b.ReportAllocs()
		for index := range b.N {
			benchmarkDispatchResult = benchmarkConstructorSplit(
				inputs[index&(len(inputs)-1)],
			)
		}
	})
}

func BenchmarkGeneratedDecode(b *testing.B) {
	limits := DefaultDecodeLimits()

	b.Run("ObjectSmall", func(b *testing.B) {
		input, err := Encode(&MTPPing{PingID: 1})
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.SetBytes(int64(len(input)))
		b.ResetTimer()
		for range b.N {
			benchmarkDecodedObject, err = Decode(input, limits)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("TypedConcrete", func(b *testing.B) {
		request := &HelpGetNearestDCRequest{}
		input, err := Encode(&NearestDC{
			Country:   "IQ",
			ThisDC:    2,
			NearestDC: 4,
		})
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.SetBytes(int64(len(input)))
		b.ResetTimer()
		for range b.N {
			benchmarkNearestDC, err = DecodeResult(request, input, limits)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("TypedBool", func(b *testing.B) {
		request := &ContactsDeleteByPhonesRequest{}
		encoder := newEncoder(nil)
		encoder.putBool(true)
		input := encoder.data()
		var err error
		b.ReportAllocs()
		b.SetBytes(int64(len(input)))
		b.ResetTimer()
		for range b.N {
			benchmarkBoolResult, err = DecodeResult(request, input, limits)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkMessageContainerDecode(b *testing.B) {
	messages := make([]MTPMessage, 32)
	for index := range messages {
		messages[index] = MTPMessage{
			MessageID: int64(index + 1),
			Seqno:     int32(index*2 + 1),
			Bytes:     12,
			Body:      &MTPPing{PingID: int64(index)},
		}
	}
	input, err := Encode(&MTPMessageContainer{Messages: messages})
	if err != nil {
		b.Fatal(err)
	}
	limits := DefaultDecodeLimits()
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	for range b.N {
		benchmarkDecodedObject, err = Decode(input, limits)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkConstructorFound() bool {
	return true
}
