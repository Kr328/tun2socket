package redirect

import (
	"net"
)

type TCPRedirect struct {
	gateway  net.IP
	mirror   net.IP
	listener *net.TCPListener
}

func NewTCPRedirect(gateway, mirror net.IP) *TCPRedirect {
	return &TCPRedirect{
		gateway: gateway,
		mirror:  mirror,
	}
}

func (t *TCPRedirect) Listen() (int, error) {
	if t := t.listener; t != nil {
		_ = t.Close()
	}

	tcpAddr := &net.TCPAddr{
		IP:   t.gateway,
		Port: 0,
		Zone: "",
	}
	tcp, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return 0, err
	}
	tcpAddr = tcp.Addr().(*net.TCPAddr)
	t.listener = tcp

	return tcpAddr.Port, nil
}

func (t *TCPRedirect) Accept() (*net.TCPConn, *net.TCPAddr, error) {
	conn, err := t.listener.AcceptTCP()
	if err != nil {
		return nil, nil, err
	}

	addr := conn.RemoteAddr().(*net.TCPAddr)

	return conn, addr, nil
}

func (t *TCPRedirect) Close() {
	if l := t.listener; l != nil {
		_ = l.Close()
	}
}
