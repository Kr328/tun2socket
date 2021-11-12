package tcpip

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"golang.org/x/sys/cpu"
)

func Test_SumNeon(t *testing.T) {
	if !cpu.ARM64.HasASIMD {
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
		avx := sumNeon(bytes)

		if compat != avx {
			t.Errorf("Sum of %s mismatched: %d != %d", hex.EncodeToString(bytes), compat, avx)

			return
		}
	}
}

func Benchmark_SumNeon(b *testing.B) {
	if !cpu.ARM64.HasASIMD {
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
		sumNeon(bytes)
	}
}
