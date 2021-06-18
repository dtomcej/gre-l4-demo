package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

var (
	remoteIP          = net.IPv4(192, 168, 1, 125)
	remotePort        = layers.TCPPort(32000)
	serverIP          = net.IPv4(127, 0, 0, 1)
	serverPort        = layers.TCPPort(9090)
	proxyExternalIP   = net.IPv4(192, 168, 1, 114)
	proxyExternalPort = layers.TCPPort(9000)
	proxyInternalIP   = net.IPv4(127, 0, 0, 1)
	proxyInternalPort = layers.TCPPort(10000)
)

func main() {
	if handle, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("tcp and port 9000 or 9090"); err != nil { // optional
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for srcPacket := range packetSource.Packets() {

			packet := gopacket.NewPacket(srcPacket.Data(), layers.LayerTypeEthernet, gopacket.Default)
			options := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}

			var (
				destIP   net.IP
				srcIP    net.IP
				proto    layers.IPProtocol
				destPort layers.TCPPort
				srcPort  layers.TCPPort
				seq      uint32
			)

			// Check if the packet is IPv4.
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer != nil {
				// Packet is an IP Packet.
				ip, _ := ipLayer.(*layers.IPv4)

				// Check if the packet is TCP.
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer != nil {
					tcp, _ := tcpLayer.(*layers.TCP)
					if !shouldProcess(ip, tcp) {
						continue
					}
					fmt.Println("IPv4 layer detected.")
					fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
					fmt.Println("Protocol: ", ip.Protocol)
					fmt.Println()
					fmt.Println("TCP layer detected.")
					fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
					fmt.Println("Sequence number: ", tcp.Seq)
					fmt.Println()

					fmt.Println("Hex dump of real IP packet taken as input:")
					fmt.Println(hex.Dump(srcPacket.Data()))

					fmt.Println("SHA1 of real IP packet taken as input:")
					h := sha1.New()
					h.Write(srcPacket.Data())
					fmt.Println(base64.URLEncoding.EncodeToString(h.Sum(nil)))

					rewriteSourceDest(ip, tcp)

					// Save New IP content for reporting.
					destIP = ip.DstIP
					srcIP = ip.SrcIP
					proto = ip.Protocol

					// Ssave new TCP content for reporting.
					destPort = tcp.DstPort
					srcPort = tcp.SrcPort
					seq = tcp.Seq
					err = tcp.SetNetworkLayerForChecksum(ip)
					if err != nil {
						panic(err)
					}

					fmt.Println()
					fmt.Println()
					fmt.Println("-------")
					fmt.Println()
					fmt.Println()
					fmt.Println("IPv4 layer built.")
					fmt.Printf("From %s to %s\n", srcIP, destIP)
					fmt.Println("Protocol: ", proto)
					fmt.Println()
					fmt.Println("TCP layer built.")
					fmt.Printf("From port %d to %d\n", srcPort, destPort)
					fmt.Println("Sequence number: ", seq)
					fmt.Println()

					buffer := gopacket.NewSerializeBuffer()
					err = gopacket.SerializePacket(buffer, options, packet)
					if err != nil {
						panic(err)
					}
					outgoingPacket := buffer.Bytes()
					fmt.Println("Hex dump of new packet:")
					fmt.Println(hex.Dump(outgoingPacket))
					fmt.Println()
					fmt.Println()
					fmt.Println("-------")

					fmt.Println()
					fmt.Println()
					fmt.Println("Writing to socket")
					fmt.Println()
					fmt.Println()
					// If destination is remote, use external socket.
					if net.IP.Equal(destIP, remoteIP) {
						// _, err = io.WriteString(externalSocket, string(outgoingPacket))
						// if err != nil {
						// 	panic(err)
						// }
						fd, err := unix.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
						if err != nil {
							panic(err)
						}
						defer unix.Close(fd)

						addr := unix.SockaddrInet4{Port: int(proxyExternalPort)}
						copy(addr.Addr[:], proxyExternalIP)
						err = unix.Sendto(fd, outgoingPacket, 0, &addr)
						if err != nil {
							panic(err)
						}
					} else {
						// Use internal socket.
						fmt.Println("Using internal socket")
						fmt.Println()
						fmt.Println()
						// _, err = io.WriteString(internalSocket, string(outgoingPacket))
						// if err != nil {
						// 	panic(err)
						// }

						// fd, _ := unix.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
						// addr := unix.SockaddrInet4{Port: int(proxyInternalPort)}
						// copy(addr.Addr[:], proxyInternalIP)
						// err = unix.Sendto(fd, outgoingIPPacket, 0, &addr)
						// if err != nil {
						// 	panic(err)
						// }

						NewPacket := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
						NewIpLayer := NewPacket.Layer(layers.LayerTypeIPv4)
						if NewIpLayer != nil {
							// Packet is an IP Packet.
							newip, _ := NewIpLayer.(*layers.IPv4)
							fmt.Println("NewPacket is an IP Packet")
							fmt.Println()
							fmt.Println()

							newtcpLayer := NewPacket.Layer(layers.LayerTypeTCP)
							if newtcpLayer != nil {
								newtcp, _ := newtcpLayer.(*layers.TCP)
								fmt.Println("NewPacket has TCP")
								fmt.Println()
								fmt.Println()

								ipHeaderBuf := gopacket.NewSerializeBuffer()
								err := newip.SerializeTo(ipHeaderBuf, options)
								if err != nil {
									panic(err)
								}
								ipHeader, err := ipv4.ParseHeader(ipHeaderBuf.Bytes())
								if err != nil {
									panic(err)
								}
								tcpPayloadBuf := gopacket.NewSerializeBuffer()
								err = gopacket.SerializeLayers(tcpPayloadBuf, options, newtcp)
								if err != nil {
									panic(err)
								}
								tcpPayload := tcpPayloadBuf.Bytes()
								fmt.Println("Hex dump of new IP datagram:")
								rawHeader, err := ipHeader.Marshal()
								if err != nil {
									panic(err)
								}
								newDatagram := append(rawHeader, tcpPayload...)
								fmt.Println(hex.Dump(newDatagram))
								fmt.Println()
								fmt.Println()
								fmt.Println("-------")
								// XXX end of packet creation

								// XXX send packet
								var packetConn net.PacketConn
								var rawConn *ipv4.RawConn
								packetConn, err = net.ListenPacket("ip4:tcp", srcIP.String())
								if err != nil {
									panic(err)
								}
								rawConn, err = ipv4.NewRawConn(packetConn)
								if err != nil {
									panic(err)
								}

								err = rawConn.WriteTo(ipHeader, tcpPayloadBuf.Bytes(), nil)
								if err != nil {
									panic(err)
								}
								log.Printf("packet of length %d sent!\n", (len(ipHeader.String()) + len(tcpPayloadBuf.Bytes())))
							}
						}

					}

					fmt.Println()
					fmt.Println()
					fmt.Println("------------------")

				}
			}
		}
	}
}

func rewriteSourceDest(ip *layers.IPv4, tcp *layers.TCP) {
	// If the Source is the remote, rewrite destination to server.
	if net.IP.Equal(ip.SrcIP, remoteIP) {
		// Destination.
		ip.DstIP = serverIP
		tcp.DstPort = serverPort

		// Source.
		ip.SrcIP = proxyInternalIP
		tcp.SrcPort = proxyInternalPort
		return
	}
	// If the source port is the server, rewrite the destination to the remote.
	if tcp.SrcPort == serverPort {
		// Destination.
		ip.DstIP = remoteIP
		tcp.DstPort = remotePort

		// Source.
		ip.SrcIP = proxyExternalIP
		tcp.SrcPort = proxyExternalPort
	}

}

func shouldProcess(ip *layers.IPv4, tcp *layers.TCP) bool {
	// If the Source is the remote, and destination is proxy.
	if net.IP.Equal(ip.SrcIP, remoteIP) && tcp.SrcPort == remotePort && net.IP.Equal(ip.DstIP, proxyExternalIP) && tcp.DstPort == proxyExternalPort {
		return true
	}

	// If the Source is the server, and destination is proxy.
	if net.IP.Equal(ip.SrcIP, serverIP) && tcp.SrcPort == serverPort && net.IP.Equal(ip.DstIP, proxyInternalIP) && tcp.DstPort == proxyInternalPort {
		return true
	}

	fmt.Println("Skipping packet")
	fmt.Println()
	fmt.Println()
	return false
}

// netSocket is a file descriptor for a system socket.
type netSocket struct {
	// System file descriptor.
	fd int
}

func (ns netSocket) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n, err := syscall.Read(ns.fd, p)
	if err != nil {
		n = 0
	}
	return n, err
}

func (ns netSocket) Write(p []byte) (int, error) {
	n, err := syscall.Write(ns.fd, p)
	if err != nil {
		n = 0
	}
	return n, err
}

// Creates a new netSocket for the next pending connection request.
func (ns *netSocket) Accept() (*netSocket, error) {
	// syscall.ForkLock doc states lock not needed for blocking accept.
	nfd, _, err := syscall.Accept(ns.fd)
	if err == nil {
		syscall.CloseOnExec(nfd)
	}
	if err != nil {
		return nil, err
	}
	return &netSocket{nfd}, nil
}

func (ns *netSocket) Close() error {
	return syscall.Close(ns.fd)
}

// Creates a new socket file descriptor, binds it and listens on it.
func newNetSocket(ip net.IP, port int) (*netSocket, error) {
	// ForkLock docs state that socket syscall requires the lock.
	syscall.ForkLock.Lock()
	// AF_INET = Address Family for IPv4
	// SOCK_STREAM = virtual circuit service
	// 0: the protocol for SOCK_STREAM, there's only 1.
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	fmt.Println("FD: ", fd)
	syscall.ForkLock.Unlock()

	// Allow reuse of recently-used addresses.
	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		syscall.Close(fd)
		return nil, os.NewSyscallError("setsockopt", err)
	}

	// Bind the socket to a port
	sa := &syscall.SockaddrInet4{Port: port}
	copy(sa.Addr[:], ip)
	if err = syscall.Bind(fd, sa); err != nil {
		return nil, os.NewSyscallError("bind", err)
	}

	// Listen for incoming connections.
	if err = syscall.Listen(fd, syscall.SOMAXCONN); err != nil {
		return nil, os.NewSyscallError("listen", err)
	}

	return &netSocket{fd: fd}, nil
}
