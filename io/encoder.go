package io

import (
	"github.com/kr328/tun2socket/tcpip/buf"
	"github.com/kr328/tun2socket/tcpip/fragment"
	"github.com/kr328/tun2socket/tcpip/packet"
)

type PacketEncoder struct {
	device   TunDevice
	mtu      int
	provider buf.BufferProvider
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

	for _, f := range fragmented {
		_, err := encoder.device.Write(f.BaseDataBlock())
		if err != nil {
			return err
		}
	}

	return nil
}
