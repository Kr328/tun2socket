package io

import (
	"github.com/kr328/tun2socket/tcpip/buf"
	"github.com/kr328/tun2socket/tcpip/fragment"
	"github.com/kr328/tun2socket/tcpip/packet"
)

func startIPDecoder(input chan []byte, fragmentOutput chan packet.IPPacket, output chan packet.IPPacket, provider buf.BufferProvider, done *completable) {
	go func() {
		for {
			select {
			case buffer := <-input:
				switch packet.DetectPacketVersion(buffer) {
				case packet.IPv4:
					pkt := packet.IPv4Packet(buffer)
					if err := pkt.Verify(); err != nil {
						provider.Recycle(buffer)
						continue
					}
					if pkt.FragmentOffset() != 0 || pkt.Flags()&packet.IPv4MoreFragment != 0 {
						select {
						case fragmentOutput <- pkt:
						default:
						}
					} else {
						select {
						case output <- pkt:
						default:
						}
					}
				}
			case <-done.waiter():
				return
			}
		}
	}()
}

func startReassemble(input chan packet.IPPacket, output chan packet.IPPacket, provider buf.BufferProvider, done *completable) {
	go func() {
		reassemble := fragment.NewReassemble(provider)

		for {
			select {
			case pkt := <-input:
				pkt, err := reassemble.InjectPacket(pkt)
				if err != nil {
					continue
				}
				if pkt != nil {
					output <- pkt
				}
			case <-done.waiter():
				return
			}
		}
	}()
}

func startTransportDecoder(input chan packet.IPPacket, output chan PacketContext, provider buf.BufferProvider, done *completable) {
	go func() {
		for {
			select {
			case ipPkt := <-input:
				var tPkt packet.TransportPacket
				switch ipPkt.Protocol() {
				case packet.UDP:
					tPkt = packet.UDPPacket(ipPkt.Payload())
				case packet.TCP:
					tPkt = packet.TCPPacket(ipPkt.Payload())
				case packet.ICMP:
					tPkt = packet.ICMPPacket(ipPkt.Payload())
				}
				if tPkt.Verify(ipPkt.SourceAddress(), ipPkt.TargetAddress()) != nil {
					provider.Recycle(ipPkt.BaseDataBlock())
					continue
				}
				output <- PacketContext{
					IPPkt:        ipPkt,
					TransportPkt: tPkt,
				}
			case <-done.waiter():
				return
			}
		}
	}()
}
