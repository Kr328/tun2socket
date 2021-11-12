package tcpip

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"golang.org/x/sys/cpu"
)

func Test_SumAVX2(t *testing.T) {
	if !cpu.X86.HasAVX2 {
		t.Skipf("AVX2 unavailable")

		return
	}

	bytes := make([]byte, chunkSize)

	for i := 0; i < 10000; i++ {
		_, err := rand.Reader.Read(bytes)
		if err != nil {
			t.Skipf("Rand read failed: %v", err)

			return
		}

		compat := sumCompat(bytes)
		avx := sumAVX2(bytes)

		if compat != avx {
			t.Errorf("Sum of %s mismatched: %d != %d", hex.EncodeToString(bytes), compat, avx)

			return
		}
	}
}

func Benchmark_SumAVX2(b *testing.B) {
	if !cpu.X86.HasAVX2 {
		b.Skipf("AVX2 unavailable")

		return
	}

	bytes := make([]byte, chunkSize)

	_, err := rand.Reader.Read(bytes)
	if err != nil {
		b.Skipf("Rand read failed: %v", err)

		return
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sumAVX2(bytes)
	}
}
