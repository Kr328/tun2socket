package io

import (
	"github.com/kr328/tun2socket/tcpip/buf"
	"github.com/kr328/tun2socket/tcpip/fragment"
	"github.com/kr328/tun2socket/tcpip/packet"
	"sync"
)

type PacketEncoder struct {
	device   TunDevice
	mtu      int
	provider buf.BufferProvider
	mutex    sync.Mutex
}

func NewPacketEncoder(device TunDevice, mtu int, provider buf.BufferProvider) *PacketEncoder {
	return &PacketEncoder{
		device:   device,
		mtu:      mtu,
		provider: provider,
	}
}

func (encoder *PacketEncoder) Encode(pkt packet.IPPacket) error {
	fragmented := fragment.IPPacketFragment(pkt, encoder.mtu, encoder.provider)
	defer encoder.provider.Recycle(pkt.BaseDataBlock())

	for _, f := range fragmented {
		encoder.mutex.Lock()
		_, err := encoder.device.Write(f.BaseDataBlock())
		encoder.mutex.Unlock()
		encoder.provider.Recycle(f.BaseDataBlock())
		if err != nil {
			return err
		}
	}

	return nil
}
