package tcpip

import (
	"crypto/rand"
	"testing"
)

const chunkSize = 9631

func Benchmark_SumCompat(b *testing.B) {
	bytes := make([]byte, chunkSize)

	_, err := rand.Reader.Read(bytes)
	if err != nil {
		b.Skipf("Rand read failed: %v", err)

		return
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sumCompat(bytes)
	}
}
