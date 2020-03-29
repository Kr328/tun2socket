package io

import (
	"github.com/kr328/tun2socket/tcpip/buf"
	"github.com/kr328/tun2socket/tcpip/fragment"
)

func startTransportEncoder(input chan PacketContext, output chan []byte, mtu int, provider buf.BufferProvider, done *completable) {
	go func() {
		for {
			select {
			case ctx := <-input:
				ctx.TransportPkt.ResetChecksum(ctx.IPPkt.SourceAddress(), ctx.IPPkt.TargetAddress())
				fargments := fragment.IPPacketFragment(ctx.IPPkt, mtu, provider)
				for _, p := range fargments {
					select {
					case output <- p.BaseDataBlock():
					default:
					}
				}
			case <-done.waiter():
				return
			}
		}
	}()
}
