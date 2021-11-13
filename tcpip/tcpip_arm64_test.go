package tcpip

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"golang.org/x/sys/cpu"
)

func Test_SumNeon(t *testing.T) {
	if !cpu.ARM64.HasASIMD {
		t.Skipf("Neon unavailable")

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
		neon := sumNeon(bytes)

		if compat != neon {
			t.Errorf("Sum of %s mismatched: %d != %d", hex.EncodeToString(bytes), compat, neon)

			return
		}
	}
}

func Test_SumNeon1393(t *testing.T) {
	if !cpu.ARM64.HasASIMD {
		t.Skipf("Neon unavailable")

		return
	}

	bytes := make([]byte, 1393)

	for i := 0; i < 10000; i++ {
		_, err := rand.Reader.Read(bytes)
		if err != nil {
			t.Skipf("Rand read failed: %v", err)

			return
		}

		compat := sumCompat(bytes)
		neon := sumNeon(bytes)

		if compat != neon {
			t.Errorf("Sum of %s mismatched: %d != %d", hex.EncodeToString(bytes), compat, neon)

			return
		}
	}
}

func Benchmark_SumNeon(b *testing.B) {
	if !cpu.ARM64.HasASIMD {
		b.Skipf("Neon unavailable")

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
