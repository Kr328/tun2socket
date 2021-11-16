package nat

import (
	"io"
	"math/rand"
	"net"
	"sync"

	"github.com/Kr328/tun2socket/tcpip"
)

type call struct {
	cond        *sync.Cond
	buf         []byte
	n           int
	source      net.Addr
	destination net.Addr
}

type UDP struct {
	closed  bool
	lock    sync.Mutex
	calls   map[*call]struct{}
	device  io.Writer
	bufLock sync.Mutex
	buf     [65535]byte
}

func (u *UDP) ReadFrom(buf []byte) (int, net.Addr, net.Addr, error) {
	u.lock.Lock()
	defer u.lock.Unlock()

	for !u.closed {
		c := &call{
			cond:        sync.NewCond(&u.lock),
			buf:         buf,
			n:           -1,
			source:      nil,
			destination: nil,
		}

		u.calls[c] = struct{}{}

		c.cond.Wait()

		if c.n >= 0 {
			return c.n, c.source, c.destination, nil
		}
	}

	return -1, nil, nil, net.ErrClosed
}

func (u *UDP) WriteTo(buf []byte, local net.Addr, remote net.Addr) (int, error) {
	u.bufLock.Lock()
	defer u.bufLock.Unlock()

	if len(buf) > 0xffff {
		return 0, net.InvalidAddrError("invalid ip version")
	}

	srcAddr, srcOk := local.(*net.UDPAddr)
	dstAddr, dstOk := remote.(*net.UDPAddr)
	if !srcOk || !dstOk {
		return 0, net.InvalidAddrError("invalid addr")
	}

	srcIP := srcAddr.IP.To4()
	dstIP := dstAddr.IP.To4()
	if srcIP == nil || dstIP == nil {
		return 0, net.InvalidAddrError("invalid ip version")
	}

	ip := tcpip.IPv4Packet(u.buf[:])
	tcpip.SetIPv4(ip)
	ip.SetHeaderLen(tcpip.IPv4HeaderSize)
	ip.SetTotalLength(tcpip.IPv4HeaderSize + tcpip.UDPHeaderSize + uint16(len(buf)))
	ip.SetTypeOfService(0)
	ip.SetIdentification(uint16(rand.Uint32()))
	ip.SetFragmentOffset(0)
	ip.SetTimeToLive(64)
	ip.SetProtocol(tcpip.UDP)
	ip.SetSourceIP(srcIP)
	ip.SetDestinationIP(dstIP)

	udp := tcpip.UDPPacket(ip.Payload())
	udp.SetLength(tcpip.UDPHeaderSize + uint16(len(buf)))
	udp.SetSourcePort(uint16(srcAddr.Port))
	udp.SetDestinationPort(uint16(dstAddr.Port))
	copy(udp.Payload(), buf)

	ip.ResetChecksum()
	udp.ResetChecksum(ip.PseudoSum())

	return u.device.Write(u.buf[:ip.TotalLen()])
}

func (u *UDP) Close() error {
	u.lock.Lock()
	defer u.lock.Unlock()

	u.closed = true

	for c := range u.calls {
		c.cond.Signal()
	}

	return nil
}

func (u *UDP) handleUDPPacket(ip tcpip.IPv4Packet, pkt tcpip.UDPPacket) {
	var c *call

	u.lock.Lock()

	for c = range u.calls {
		delete(u.calls, c)
		break
	}

	u.lock.Unlock()

	if c != nil {
		c.source = &net.UDPAddr{
			IP:   append(net.IP{}, ip.SourceIP()...),
			Port: int(pkt.SourcePort()),
		}
		c.destination = &net.UDPAddr{
			IP:   append(net.IP{}, ip.DestinationIP()...),
			Port: int(pkt.DestinationPort()),
		}
		c.n = copy(c.buf, pkt.Payload())
		c.cond.Signal()
	}
}
