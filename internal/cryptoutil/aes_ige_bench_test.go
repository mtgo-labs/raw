package cryptoutil

import "testing"

var benchmarkIGEByte byte
var benchmarkIGEBlock AES256

func BenchmarkAESIGEEncrypt(b *testing.B) {
	for _, size := range []int{32, 64, 256, 1024, 1 << 20} {
		b.Run(benchmarkSizeName(size), func(b *testing.B) {
			key := sequentialBytes(32, 0x20)
			iv := sequentialBytes(32, 0x40)
			src := sequentialBytes(size, 0x60)
			dst := make([]byte, size)
			block, err := NewAES256(key)
			if err != nil {
				b.Fatal(err)
			}

			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for range b.N {
				if err := EncryptIGE(dst, src, block, iv); err != nil {
					b.Fatal(err)
				}
			}
			benchmarkIGEByte = dst[0]
		})
	}
}

func BenchmarkAESIGEDecrypt(b *testing.B) {
	for _, size := range []int{32, 64, 256, 1024, 1 << 20} {
		b.Run(benchmarkSizeName(size), func(b *testing.B) {
			key := sequentialBytes(32, 0x20)
			iv := sequentialBytes(32, 0x40)
			plaintext := sequentialBytes(size, 0x60)
			src := make([]byte, size)
			block, err := NewAES256(key)
			if err != nil {
				b.Fatal(err)
			}
			if err := EncryptIGE(src, plaintext, block, iv); err != nil {
				b.Fatal(err)
			}
			dst := make([]byte, size)

			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for range b.N {
				if err := DecryptIGE(dst, src, block, iv); err != nil {
					b.Fatal(err)
				}
			}
			benchmarkIGEByte = dst[0]
		})
	}
}

func BenchmarkAESIGEEncryptWithKeySetup(b *testing.B) {
	for _, size := range []int{32, 64, 256, 1024, 1 << 20} {
		b.Run(benchmarkSizeName(size), func(b *testing.B) {
			key := sequentialBytes(32, 0x20)
			iv := sequentialBytes(32, 0x40)
			src := sequentialBytes(size, 0x60)
			dst := make([]byte, size)

			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for range b.N {
				block, err := NewAES256(key)
				if err != nil {
					b.Fatal(err)
				}
				if err := EncryptIGE(dst, src, block, iv); err != nil {
					b.Fatal(err)
				}
			}
			benchmarkIGEByte = dst[0]
		})
	}
}

func BenchmarkAESIGEDecryptWithKeySetup(b *testing.B) {
	for _, size := range []int{32, 64, 256, 1024, 1 << 20} {
		b.Run(benchmarkSizeName(size), func(b *testing.B) {
			key := sequentialBytes(32, 0x20)
			iv := sequentialBytes(32, 0x40)
			src := sequentialBytes(size, 0x60)
			dst := make([]byte, size)

			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for range b.N {
				block, err := NewAES256(key)
				if err != nil {
					b.Fatal(err)
				}
				if err := DecryptIGE(dst, src, block, iv); err != nil {
					b.Fatal(err)
				}
			}
			benchmarkIGEByte = dst[0]
		})
	}
}

func BenchmarkAES256Setup(b *testing.B) {
	key := sequentialBytes(32, 0x20)

	b.ReportAllocs()
	for range b.N {
		block, err := NewAES256(key)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkIGEBlock = block
	}
}

func benchmarkSizeName(size int) string {
	switch size {
	case 32:
		return "32B"
	case 64:
		return "64B"
	case 256:
		return "256B"
	case 1024:
		return "1KiB"
	case 1 << 20:
		return "1MiB"
	default:
		panic("unknown benchmark size")
	}
}
