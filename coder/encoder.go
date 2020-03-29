package coder

import (
	"github.com/kr328/tun2socket/tcpip/buf"
	"github.com/kr328/tun2socket/tcpip/fragment"
	"github.com/kr328/tun2socket/tcpip/packet"
)

type PacketEncoder struct {
	mtu      int
	provider buf.BufferProvider
}

func NewPacketEncoder(mtu int, provider buf.BufferProvider) *PacketEncoder {
	return &PacketEncoder{
		mtu:      mtu,
		provider: provider,
	}
}

func (encoder *PacketEncoder) Encode(pkt packet.IPPacket) [][]byte {
	fragmented := fragment.IPPacketFragment(pkt, encoder.mtu, encoder.provider)
	result := make([][]byte, len(fragmented))

	for i, f := range fragmented {
		result[i] = f.BaseDataBlock()
	}

	return result
}
