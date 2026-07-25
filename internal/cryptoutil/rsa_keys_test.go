package cryptoutil

import (
	"testing"
)

func TestTelegramRSAKeyRegistry(t *testing.T) {
	if len(telegramRSAKeys) != 10 {
		t.Fatalf("registry length = %d, want 10", len(telegramRSAKeys))
	}
	newCount := 0
	oldCount := 0
	seen := make(map[uint64]struct{}, len(telegramRSAKeys))
	for _, key := range telegramRSAKeys {
		if _, ok := seen[key.fingerprint]; ok {
			t.Fatalf("duplicate fingerprint 0x%016x", key.fingerprint)
		}
		seen[key.fingerprint] = struct{}{}
		if key.old {
			oldCount++
		} else {
			newCount++
		}
		if key.exponent != [3]byte{0x01, 0x00, 0x01} {
			t.Fatalf("fingerprint 0x%016x has unexpected exponent", key.fingerprint)
		}
	}
	if newCount != 2 || oldCount != 8 {
		t.Fatalf("key generations = %d new, %d old; want 2 new, 8 old", newCount, oldCount)
	}

	newFingerprint := telegramRSAKeys[0].fingerprint
	oldFingerprint := telegramRSAKeys[2].fingerprint
	key, fingerprint, ok := FindTelegramRSAKey([]uint64{oldFingerprint, newFingerprint}, false)
	if !ok || fingerprint != newFingerprint || key == nil || key.E != 65537 {
		t.Fatalf("new-key lookup = (%v, 0x%016x, %v)", key, fingerprint, ok)
	}
	key.N.SetInt64(1)
	key, fingerprint, ok = FindTelegramRSAKey([]uint64{oldFingerprint}, false)
	if !ok || fingerprint != oldFingerprint || key == nil || key.N.BitLen() != 2048 {
		t.Fatalf("old-key fallback = (%v, 0x%016x, %v)", key, fingerprint, ok)
	}
	if _, _, ok := FindTelegramRSAKey([]uint64{0}, true); ok {
		t.Fatal("unknown fingerprint unexpectedly matched")
	}
}

func TestTelegramRSAKeyFingerprint(t *testing.T) {
	if telegramRSAKeys[0].fingerprint != 0xb25898df208d2603 {
		t.Fatalf("first fingerprint = 0x%016x", telegramRSAKeys[0].fingerprint)
	}
	if telegramRSAKeys[1].fingerprint != 0xd09d1d85de64fd85 {
		t.Fatalf("second fingerprint = 0x%016x", telegramRSAKeys[1].fingerprint)
	}
}

func BenchmarkFindTelegramRSAKey(b *testing.B) {
	fingerprints := make([]uint64, len(telegramRSAKeys))
	for index, key := range telegramRSAKeys {
		fingerprints[index] = key.fingerprint
	}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		key, _, ok := FindTelegramRSAKey(fingerprints, false)
		if !ok || key == nil {
			b.Fatal("RSA key lookup failed")
		}
	}
}
