package buf

import (
	"github.com/kr328/tun2socket/tcpip/packet"
	"sync"
)

type PacketBufferProvider struct {
	mtu       int
	mtuPool   sync.Pool
	largePool sync.Pool
}

func NewPacketBufferProvider(mtu int) *PacketBufferProvider {
	return &PacketBufferProvider{
		mtu: mtu,
		mtuPool: sync.Pool{New: func() interface{} {
			return make([]byte, mtu)
		}},
		largePool: sync.Pool{New: func() interface{} {
			return make([]byte, packet.IPPacketMaxLength)
		}},
	}
}

func (p *PacketBufferProvider) Obtain(length int) []byte {
	if length <= p.mtu {
		return p.mtuPool.Get().([]byte)[:length]
	} else if length <= packet.IPPacketMaxLength {
		return p.largePool.Get().([]byte)[:length]
	}

	return make([]byte, length)
}

func (p *PacketBufferProvider) Recycle(buffer []byte) {
	c := cap(buffer)

	if c == p.mtu {
		p.mtuPool.Put(buffer[:c])
	} else if c == packet.IPPacketMaxLength {
		p.largePool.Put(buffer[:c])
	}
}
