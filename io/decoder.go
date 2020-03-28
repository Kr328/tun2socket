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

func startReassembler(input chan packet.IPPacket, output chan packet.IPPacket, provider buf.BufferProvider, done *completable) {
	go func() {
		reassembler := fragment.NewReassemble(provider)

		for {
			select {
			case pkt := <-input:
				pkt, err := reassembler.InjectPacket(pkt)
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
				switch ipPkt.Protocol() {
				case packet.UDP:
					udpPkt := packet.UDPPacket(ipPkt.Payload())
					if udpPkt.Verify(ipPkt.SourceAddress(), ipPkt.TargetAddress()) != nil {
						provider.Recycle(ipPkt.BaseDataBlock())
						continue
					}
					output <- PacketContext{
						IPPkt:        ipPkt,
						TransportPkt: udpPkt,
					}
				case packet.TCP:
					tcpPkt := packet.TCPPacket(ipPkt.Payload())
					if tcpPkt.Verify(ipPkt.SourceAddress(), ipPkt.TargetAddress()) != nil {
						provider.Recycle(ipPkt.BaseDataBlock())
						continue
					}
					output <- PacketContext{
						IPPkt:        ipPkt,
						TransportPkt: tcpPkt,
					}
				case packet.ICMP:
					icmpPkt := packet.ICMPPacket(ipPkt.Payload())
					if icmpPkt.Verify(ipPkt.SourceAddress(), ipPkt.TargetAddress()) != nil {
						provider.Recycle(ipPkt.BaseDataBlock())
						continue
					}
					output <- PacketContext{
						IPPkt:        ipPkt,
						TransportPkt: icmpPkt,
					}
				}
			case <-done.waiter():
				return
			}
		}
	}()
}
