package packet

func Decode(data []byte) (IPPacket, TransportPacket) {
	var pkt IPPacket

	switch DetectPacketVersion(data) {
	case IPv4:
		v4 := IPv4Packet(data)
		if v4.Flags()&IPv4MoreFragment != 0 || v4.FragmentOffset() != 0 {
			return nil, nil
		}
		pkt = v4
	default:
		return nil, nil
	}

	if err := pkt.Verify(); err != nil {
		return nil, nil
	}

	var tPkt TransportPacket
	switch pkt.Protocol() {
	case TCP:
		tPkt = TCPPacket(pkt.Payload())
	case UDP:
		tPkt = UDPPacket(pkt.Payload())
	case ICMP:
		tPkt = ICMPPacket(pkt.Payload())
	default:
		return nil, nil
	}

	//if err := tPkt.Verify(pkt.SourceAddress(), pkt.TargetAddress()); err != nil {
	//	decoder.provider.Recycle(pkt.BaseDataBlock())
	//	return nil, nil
	//}

	return pkt, tPkt
}
