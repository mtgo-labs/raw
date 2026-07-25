package cryptoutil

import "testing"

var (
	benchmarkMessageKey [16]byte
	benchmarkMessageIV  [32]byte
	benchmarkNonceKey   [32]byte
)

func BenchmarkComputeMessageKey(b *testing.B) {
	authKey := repeatedBytes(mtcuteAuthKeyChunk, 8)
	for _, size := range []int{32, 1024, 1 << 20} {
		b.Run(benchmarkSizeName(size), func(b *testing.B) {
			plaintext := sequentialBytes(size, 0x20)

			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for range b.N {
				var err error
				benchmarkMessageKey, err = ComputeMessageKey(
					authKey,
					plaintext,
					ClientToServer,
				)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDeriveMessageAESKeyIV(b *testing.B) {
	authKey := repeatedBytes(mtcuteAuthKeyChunk, 8)
	messageKey := [16]byte{}
	var key [32]byte

	b.ReportAllocs()
	for b.Loop() {
		var err error
		key, benchmarkMessageIV, err = deriveMessageAESKeyIV(
			authKey,
			messageKey,
			ClientToServer,
		)
		if err != nil {
			b.Fatal(err)
		}
	}
	benchmarkNonceKey = key
}

func BenchmarkNewMessageAES256(b *testing.B) {
	authKey := repeatedBytes(mtcuteAuthKeyChunk, 8)
	messageKey := [16]byte{}

	b.ReportAllocs()
	for b.Loop() {
		var err error
		benchmarkIGEBlock, benchmarkMessageIV, err = NewMessageAES256(
			authKey,
			messageKey,
			ClientToServer,
		)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDeriveNonceAESKeyIV(b *testing.B) {
	serverNonce := [16]byte{}
	newNonce := [32]byte{}

	b.ReportAllocs()
	for b.Loop() {
		benchmarkNonceKey, benchmarkMessageIV = DeriveNonceAESKeyIV(
			serverNonce,
			newNonce,
		)
	}
}
