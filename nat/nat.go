package nat

import (
	"io"
	"net"
	"net/netip"

	"github.com/Kr328/tun2socket/tcpip"
)

func Start(
	device io.ReadWriter,
	network netip.Prefix,
	portal netip.Addr,
) (*TCP, *UDP, error) {
	if !portal.Is4() || !network.Addr().Is4() {
		return nil, nil, net.InvalidAddrError("only ipv4 supported")
	}

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, nil, err
	}

	tab := newTable()
	udp := &UDP{
		device: device,
		buf:    [65535]byte{},
	}
	tcp := &TCP{
		listener: listener,
		portal:   portal,
		table:    tab,
	}

	broadcast := tcpip.BroadcastAddr(network)

	gateway := network.Addr()
	gatewayPort := uint16(listener.Addr().(*net.TCPAddr).Port)

	go func() {
		defer func() {
			_ = tcp.Close()
			_ = udp.Close()
		}()

		buf := make([]byte, 65535)

		for {
			n, err := device.Read(buf)
			if err != nil {
				return
			}

			raw := buf[:n]

			if !tcpip.IsIPv4(raw) {
				continue
			}

			ip := tcpip.IPv4Packet(raw)
			if !ip.Valid() {
				continue
			}

			if ip.Flags()&tcpip.FlagMoreFragment != 0 {
				continue
			}

			if ip.FragmentOffset() != 0 {
				continue
			}

			if !ip.DestinationIP().IsGlobalUnicast() || ip.DestinationIP() == broadcast {
				continue
			}

			switch ip.Protocol() {
			case tcpip.TCP:
				t := tcpip.TCPPacket(ip.Payload())
				if !t.Valid() {
					continue
				}

				if ip.DestinationIP() == portal {
					if ip.SourceIP() == gateway && t.SourcePort() == gatewayPort {
						tup := tab.findTupleByPort(t.DestinationPort())
						if tup == zeroTuple {
							continue
						}

						ip.SetSourceIP(tup.to.Addr())
						t.SetSourcePort(tup.to.Port())
						ip.SetDestinationIP(tup.from.Addr())
						t.SetDestinationPort(tup.from.Port())

						ip.ResetChecksum()
						t.ResetChecksum(ip.PseudoSum())

						_, _ = device.Write(raw)
					}
				} else {
					tup := tuple{
						from: netip.AddrPortFrom(ip.SourceIP(), t.SourcePort()),
						to:   netip.AddrPortFrom(ip.DestinationIP(), t.DestinationPort()),
					}

					port := tab.findPortByTuple(tup)
					if port == 0 {
						if t.Flags() != tcpip.TCPSyn {
							continue
						}

						port = tab.newConn(tup)
					}

					ip.SetSourceIP(portal)
					ip.SetDestinationIP(gateway)
					t.SetSourcePort(port)
					t.SetDestinationPort(gatewayPort)

					ip.ResetChecksum()
					t.ResetChecksum(ip.PseudoSum())

					_, _ = device.Write(raw)
				}
			case tcpip.UDP:
				u := tcpip.UDPPacket(ip.Payload())
				if !u.Valid() {
					continue
				}

				udp.handleUDPPacket(ip, u)
			case tcpip.ICMP:
				i := tcpip.ICMPPacket(ip.Payload())

				if i.Type() != tcpip.ICMPTypePingRequest || i.Code() != 0 {
					continue
				}

				i.SetType(tcpip.ICMPTypePingResponse)

				source := ip.SourceIP()
				destination := ip.DestinationIP()
				ip.SetSourceIP(destination)
				ip.SetDestinationIP(source)

				ip.ResetChecksum()
				i.ResetChecksum()

				_, _ = device.Write(raw)
			}
		}
	}()

	return tcp, udp, nil
}
