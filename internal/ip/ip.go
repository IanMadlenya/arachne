// Copyright (c) 2016 Uber Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package ip

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/net/bpf"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/uber/arachne/defines"
	"github.com/uber/arachne/internal/log"

	"go.uber.org/zap"
)

// Conn represents a raw socket connection for sending IP packets
type Conn struct {
	SrcAddr net.IP
	AF      int
	sendFD  int
	recvFD  int
}

// CloseRecv operates on a Conn file descriptor and mirrors the Close syscall
func (c *Conn) CloseRecv() error {
	return syscall.Close(c.recvFD)
}

// CloseSend operates on a Conn file descriptor and mirrors the Close syscall
func (c *Conn) CloseSend() error {
	return syscall.Close(c.sendFD)
}

// Recvfrom operates on a Conn file descriptor and mirrors the Recvfrom syscall
func (c *Conn) Recvfrom(b []byte) (int, syscall.Sockaddr, error) {
	return syscall.Recvfrom(c.recvFD, b, 0)
}

// Sendto operates on a Conn file descriptor and mirrors the Sendto syscall
func (c *Conn) Sendto(b []byte, to net.IP) error {
	sockAddr, err := ipToSockaddr(c.AF, to, 0)
	if err != nil {
		return err
	}

	return syscall.Sendto(c.sendFD, b, 0, sockAddr)

}

// getFilter will attach a BPF filter to a raw connections recv socket
func getBPFFilter(listenPort uint32) []bpf.RawInstruction {
	// Our recv socket is of type IP_PROTOTCP, so offset 0 is the start of the ethernet payload (ip header)
	filter, _ := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 0, Size: 1},                                           // Load first byte into Register A
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xf0},                              // Register A AND 0xf0 to obtain high-nibble
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6, SkipTrue: 2},                      // If IPv6, skip, else continue
		bpf.LoadAbsolute{Off: 22, Size: 2},                                          // Load TCP dst port starting from IPv4 header
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: listenPort, SkipFalse: 3, SkipTrue: 2}, // Check if equal to desired port
		bpf.LoadAbsolute{Off: 42, Size: 2},                                          // Load TCP dst port starting from IPv6 header
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: listenPort, SkipFalse: 1},              // Check if equal to desired port
		bpf.RetConstant{Val: 4096},                                                  // Return max 4096 bytes from packet
		bpf.RetConstant{Val: 0},                                                     // Drop packet
	})

	return filter
}

func getSendSocket(af int) (int, error) {
	fd, err := syscall.Socket(af, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return 0, err
	}

	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		return 0, err
	}

	return fd, nil
}

func getRecvSocket(af int, intf string) (int, error) {
	fd, err := syscall.Socket(af, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return 0, err
	}

	if err = bindToDevice(fd, intf); err != nil {
		return 0, err
	}

	return fd, nil
}

// NewConn returns a raw socket connection to send and receive packets
func NewConn(af int, listenPort uint32, intf string, srcAddr net.IP, logger *log.Logger) *Conn {
	fds, err := getSendSocket(af)
	if err != nil {
		logger.Fatal("Error creating send socket", zap.Int("address_family", af), zap.Error(err))
	}

	fdr, err := getRecvSocket(af, intf)
	if err != nil {
		logger.Fatal("Error creating recv socket", zap.Int("address_family", af), zap.Error(err))
	}

	connection := &Conn{
		SrcAddr: srcAddr,
		AF:      af,
		sendFD:  fds,
		recvFD:  fdr,
	}

	filter := getBPFFilter(uint32(listenPort))
	// Golang syscall.SO_ATTACH_FILTER is available only in linux
	err = connection.attachBPF(filter)
	if err != nil {
		logger.Fatal("Error attaching BPF filter to recv Socket", zap.Error(err))
	}

	return connection
}

func getIPHeaderLayerV6(tos uint8, tcpLen int, srcIP, dstIP net.IP) (*layers.IPv6, error) {
	return &layers.IPv6{
		Version:      6,
		TrafficClass: tos,
		Length:       uint16(tcpLen),
		NextHeader:   layers.IPProtocolTCP,
		SrcIP:        srcIP,
		DstIP:        dstIP,
	}, nil
}

// GetIPHeaderLayer returns the appriately versioned gopacket IP layer
func GetIPHeaderLayer(af int, tos uint8, tcpLen int, srcIP, dstIP net.IP) (gopacket.NetworkLayer, error) {
	switch af {
	case defines.AfInet:
		return getIPHeaderLayerV4(tos, tcpLen, srcIP, dstIP)
	case defines.AfInet6:
		return getIPHeaderLayerV6(tos, tcpLen, srcIP, dstIP)
	}

	return nil, fmt.Errorf("invalid address family")
}

func ipToSockaddr(family int, ip net.IP, port int) (syscall.Sockaddr, error) {
	switch family {
	case syscall.AF_INET:
		if len(ip) == 0 {
			ip = net.IPv4zero
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, &net.AddrError{Err: "non-IPv4 address", Addr: ip.String()}
		}
		sa := &syscall.SockaddrInet4{Port: port}
		copy(sa.Addr[:], ip4)
		return sa, nil
	case syscall.AF_INET6:
		if len(ip) == 0 || ip.Equal(net.IPv4zero) {
			ip = net.IPv6zero
		}
		ip6 := ip.To16()
		if ip6 == nil {
			return nil, &net.AddrError{Err: "non-IPv6 address", Addr: ip.String()}
		}
		sa := &syscall.SockaddrInet6{Port: port}
		copy(sa.Addr[:], ip6)
		return sa, nil
	}
	return nil, &net.AddrError{Err: "invalid address family", Addr: ip.String()}
}
