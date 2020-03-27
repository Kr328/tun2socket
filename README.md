# Tun2Socket

A utilize that use system tcpip stack to forward packet from tun device.

### Feature

- IPv4
- IP Fragment/Reassemble
- TCP/UDP
- Ping Echo

### Usage

```go
tun := openTunDevice()      // Open tun device by your self
mtu := tun.getMtu()         // mtu of tun device
gateway := tun.getAddress() // address of tun device
mirror := gateway.getSingleFreeAddress() // a free ip in tun address range

tun2socket := tun2socket2.NewTun2Socket(tun, mtu, gateway, mirror)
tun2socket.SetTCPHandler(func(conn net.Conn, endpoint *binding.Endpoint) {
    // fmt.Println("[TCP] " + endpoint.Source.IP.String() + " -> " + endpoint.Target.IP.String())

    // handle new tcp connection here
    // start a new goroutine if need
})
tun2socket.SetUDPHandler(func(payload []byte, endpoint *binding.Endpoint, sender redirect.UDPSender) {
    // fmt.Println("[UDP] " + endpoint.Source.IP.String() + " -> " + endpoint.Target.IP.String())

    // handle udp packet here
    // start a new goroutine if need 
})

tun2socket.Start() // start now
```

### TODO

- [ ] IPv6 Supoort