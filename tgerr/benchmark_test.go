package tgerr

import (
	"fmt"
	"testing"
)

var (
	benchmarkError *Error
	benchmarkMatch bool
)

func BenchmarkNew(b *testing.B) {
	b.Run("Exact", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			benchmarkError = New(CodeBadRequest, ErrAuthKeyUnregistered)
		}
	})
	b.Run("Parameterized", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			benchmarkError = New(CodeFlood, "FLOOD_WAIT_60")
		}
	})
	b.Run("ParameterizedSuffix", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			benchmarkError = New(
				CodeBadRequest,
				"FILE_REFERENCE_12_EXPIRED",
			)
		}
	})
}

func BenchmarkMatch(b *testing.B) {
	rpcError := New(CodeFlood, "FLOOD_WAIT_60")
	b.Run("Direct", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			benchmarkMatch = IsFloodWait(rpcError)
		}
	})
	wrapped := fmt.Errorf("invoke: %w", rpcError)
	b.Run("Wrapped", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			benchmarkMatch = IsFloodWait(wrapped)
		}
	})
	b.Run("Miss", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			benchmarkMatch = IsAuthKeyUnregistered(rpcError)
		}
	})
}
