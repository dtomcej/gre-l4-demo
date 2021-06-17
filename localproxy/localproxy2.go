package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/ipv4"
)

func main() {
	if handle, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("tcp and dst port 9000"); err != nil { // optional
		// } else if err := handle.SetBPFFilter("tcp and dst port 9000"); err != nil { // optional
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		x := 1
		for packet := range packetSource.Packets() {
			fmt.Printf("Loop :%d\n", x)
			x++
			options := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}

			var (
				NewEthernetLayer layers.Ethernet
				NewIPLayer       layers.IPv4
				NewTcpLayer      layers.TCP
				NewPacketPayload gopacket.Payload
			)

			// Check if the packet is Ethernet.
			ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethernetLayer != nil {
				// Packet is an Ethernet Packet.
				ethernet, _ := ethernetLayer.(*layers.Ethernet)
				fmt.Println("Ethernet layer detected.")
				fmt.Println("Source MAC: ", ethernet.SrcMAC)
				fmt.Println("Destination MAC: ", ethernet.DstMAC)
				fmt.Println("Ethernet type: ", ethernet.EthernetType)
				fmt.Println()
				NewEthernetLayer = layers.Ethernet{
					SrcMAC: ethernet.SrcMAC,
					DstMAC: ethernet.DstMAC,
				}
			}

			// Check if the packet is IPv4.
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer != nil {
				// Packet is an IP Packet.
				ip, _ := ipLayer.(*layers.IPv4)
				fmt.Println("IPv4 layer detected.")
				fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
				fmt.Println("Protocol: ", ip.Protocol)
				fmt.Println()
				NewIPLayer = layers.IPv4{
					SrcIP:    ip.SrcIP,
					DstIP:    ip.DstIP,
					Version:  ip.Version,
					TTL:      ip.TTL,
					Protocol: ip.Protocol,
				}
			}

			// Check if the packet is TCP.
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				fmt.Println("TCP layer detected.")
				fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
				fmt.Println("Sequence number: ", tcp.Seq)
				fmt.Println()
				NewTcpLayer = layers.TCP{
					SrcPort: tcp.SrcPort,
					DstPort: layers.TCPPort(9090),
					Window:  tcp.Window,
					Urgent:  tcp.Urgent,
					Seq:     tcp.Seq,
					Ack:     tcp.Ack,
					ACK:     tcp.ACK,
					SYN:     tcp.SYN,
					FIN:     tcp.FIN,
					RST:     tcp.RST,
					URG:     tcp.URG,
					ECE:     tcp.ECE,
					CWR:     tcp.CWR,
					NS:      tcp.NS,
					PSH:     tcp.PSH,
				}
				_ = NewTcpLayer.SetNetworkLayerForChecksum(&NewIPLayer)
			}

			applicationLayer := packet.ApplicationLayer()
			if applicationLayer != nil {
				fmt.Println("Application layer/Payload found.")
				fmt.Printf("%s\n", applicationLayer.Payload())
				NewPacketPayload = gopacket.Payload(applicationLayer.Payload())
			}

			// And create the packet with the layers
			ipHeaderBuffer := gopacket.NewSerializeBuffer()
			err := NewIPLayer.SerializeTo(ipHeaderBuffer, options)
			if err != nil {
				panic(err)
			}

			ipHeader, err := ipv4.ParseHeader(ipHeaderBuffer.Bytes())
			if err != nil {
				panic(err)
			}

			ipHeaderBytes, err := ipHeader.Marshal()
			if err != nil {
				panic(err)
			}

			tcpPayloadBuffer := gopacket.NewSerializeBuffer()
			err = gopacket.SerializeLayers(tcpPayloadBuffer, options, &NewTcpLayer, NewPacketPayload)
			if err != nil {
				panic(err)
			}
			buffer := gopacket.NewSerializeBuffer()
			_ = gopacket.SerializeLayers(buffer, options,
				&NewEthernetLayer,
				&NewIPLayer,
				&NewTcpLayer,
				&NewPacketPayload)
			outgoingPacket := buffer.Bytes()

			NewPacketData := append(ipHeaderBytes, tcpPayloadBuffer.Bytes()...)
			NewPacket := gopacket.NewPacket(NewPacketData, layers.LayerTypeEthernet, gopacket.Default)
			fmt.Println("Hex dump of real IP packet taken as input:")
			fmt.Println(hex.Dump(packet.Data()))
			fmt.Println("SHA1 of real IP packet taken as input:")
			h := sha1.New()
			h.Write(packet.Data())
			fmt.Println(base64.URLEncoding.EncodeToString(h.Sum(nil)))
			fmt.Println("Hex dump of go packet serialization output:")
			fmt.Println(hex.Dump(NewPacket.Data()))
			fmt.Println("Hex dump of full go packet serialization output:")
			fmt.Println(hex.Dump(outgoingPacket))
		}
	}
}
