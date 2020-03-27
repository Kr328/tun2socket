package redirect

import "sync"

type bufferProvider struct {
	mtu          int
	fragmentPool sync.Pool
	mergedPool   sync.Pool
}

func newBufferProvider(mtu int) *bufferProvider {
	return &bufferProvider{
		mtu: mtu,
		fragmentPool: sync.Pool{New: func() interface{} {
			return make([]byte, mtu)
		}},
		mergedPool: sync.Pool{New: func() interface{} {
			return make([]byte, 65535)
		}},
	}
}

func (b *bufferProvider) Obtain(length int) []byte {
	if length <= b.mtu {
		return b.fragmentPool.Get().([]byte)[:length]
	} else if length <= 65535 {
		return b.mergedPool.Get().([]byte)[:length]
	} else {
		return make([]byte, length)
	}
}

func (b *bufferProvider) Recycle(buffer []byte) {
	buffer = buffer[:cap(buffer)]
	if len(buffer) == b.mtu {
		b.fragmentPool.Put(buffer)
	} else if len(buffer) == 65535 {
		b.mergedPool.Put(buffer)
	}
}
