package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	remoteIP      = net.IPv4(192, 168, 1, 125)
	remotePort    = layers.TCPPort(32000)
	serverIP      = net.IPv4(172, 217, 13, 238)
	serverPort    = layers.TCPPort(80)
	proxyIP       = net.IPv4(192, 168, 1, 114)
	proxyPort     = layers.TCPPort(9000)
	gatewayIP     = net.IPv4(192, 168, 1, 1)
	interfaceName = "en0"
)

func main() {

	// Get specified network interface.
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		panic(err)
	}

	// // Create a TCP listener to capture traffic.
	// go createListenter(proxyIP.String(), proxyPort)

	// Open up a pcap handle for packet reads/writes.
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter("tcp and port 9000")
	if err != nil {
		panic(err)
	}

	err = processPackets(handle, iface)
	if err != nil {
		panic(err)
	}
}

// func createListenter(host string, port layers.TCPPort) {
// 	address := fmt.Sprintf("%s:%d", host, port)
// 	fmt.Println("Opening listener on: ", address)
// 	_, err := net.Listen("tcp", address)
// 	if err != nil {
// 		panic(err)
// 	}
// 	for {
// 		time.Sleep(2 * time.Second)
// 	}
// }

func processPackets(handle *pcap.Handle, iface *net.Interface) error {
	packetSource := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	for srcPacket := range packetSource.Packets() {

		packet, err := buildNewPacket(handle, iface, srcPacket)
		if err != nil {
			return err
		}
		if packet == nil {
			continue
		}

		err = handle.WritePacketData(packet)
		if err != nil {
			fmt.Println("packet data writing failed")
			return err
		}
		fmt.Println("packet sent successfully")

	}

	return nil
}

func buildNewPacket(handle *pcap.Handle, iface *net.Interface, srcPacket gopacket.Packet) ([]byte, error) {
	fmt.Println("------------------")
	fmt.Println()
	fmt.Println("Hex dump of real IP packet taken as input:")
	fmt.Println(hex.Dump(srcPacket.Data()))

	fmt.Println("SHA1 of real IP packet taken as input:")
	h := sha1.New()
	h.Write(srcPacket.Data())
	fmt.Println(base64.URLEncoding.EncodeToString(h.Sum(nil)))
	fmt.Println()

	// Get the packet Ethernet layer.
	eth, err := getEthernetLayer(srcPacket)
	if err != nil {
		return nil, err
	}
	// Get the packet IPv4 layer.
	ip, err := getIPLayer(srcPacket)
	if err != nil {
		return nil, err
	}

	// Get the packet TCP layer.
	tcp, err := getTCPLayer(srcPacket)
	if err != nil {
		return nil, err
	}

	if !shouldProcess(ip, tcp) {
		return nil, nil
	}

	rewritePacketLayers(eth, ip, tcp, iface)
	printPacketData(eth, ip, tcp)

	err = tcp.SetNetworkLayerForChecksum(ip)
	if err != nil {
		return nil, err
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err = gopacket.SerializeLayers(buffer, options, eth, ip, tcp)
	if err != nil {
		panic(err)
	}
	outgoingPacket := buffer.Bytes()
	fmt.Println("Hex dump of new packet:")
	fmt.Println(hex.Dump(outgoingPacket))

	fmt.Println("------------------")

	return outgoingPacket, nil
}

func getEthernetLayer(packet gopacket.Packet) (*layers.Ethernet, error) {
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil {
		return nil, fmt.Errorf("no Ethernet layer found in packet")
	}

	ethernet, _ := ethernetLayer.(*layers.Ethernet)
	fmt.Println("Ethernet layer detected.")
	fmt.Println("Source MAC: ", ethernet.SrcMAC)
	fmt.Println("Destination MAC: ", ethernet.DstMAC)
	fmt.Println("Ethernet type: ", ethernet.EthernetType)
	fmt.Println()

	eth := layers.Ethernet{
		SrcMAC:       ethernet.SrcMAC,
		DstMAC:       ethernet.DstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	return &eth, nil

}

func getIPLayer(packet gopacket.Packet) (*layers.IPv4, error) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil, fmt.Errorf("no IPv4 layer found in packet")
	}

	ipv4, _ := ipLayer.(*layers.IPv4)
	fmt.Println("IPv4 layer detected.")
	fmt.Printf("From %s to %s\n", ipv4.SrcIP, ipv4.DstIP)
	fmt.Println("Protocol: ", ipv4.Protocol)
	fmt.Println()

	ip := layers.IPv4{
		Version:    ipv4.Version,
		IHL:        ipv4.IHL,
		TOS:        ipv4.TOS,
		Length:     ipv4.Length,
		Id:         ipv4.Id,
		Flags:      ipv4.Flags,
		FragOffset: ipv4.FragOffset,
		TTL:        ipv4.TTL,
		Protocol:   ipv4.Protocol,
		Checksum:   ipv4.Checksum,
		SrcIP:      ipv4.SrcIP,
		DstIP:      ipv4.DstIP,
	}
	return &ip, nil

}

func getTCPLayer(packet gopacket.Packet) (*layers.TCP, error) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil, fmt.Errorf("no TCP layer found in packet")
	}

	tcp, _ := tcpLayer.(*layers.TCP)
	fmt.Println("TCP layer detected.")
	fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
	fmt.Println("Sequence number: ", tcp.Seq)
	fmt.Println()

	t := layers.TCP{
		SrcPort:    tcp.SrcPort,
		DstPort:    tcp.DstPort,
		Seq:        tcp.Seq,
		Ack:        tcp.Ack,
		DataOffset: tcp.DataOffset,
		FIN:        tcp.FIN,
		SYN:        tcp.SYN,
		RST:        tcp.RST,
		PSH:        tcp.PSH,
		ACK:        tcp.ACK,
		URG:        tcp.URG,
		ECE:        tcp.ECE,
		CWR:        tcp.CWR,
		NS:         tcp.NS,
		Window:     tcp.Window,
		Checksum:   tcp.Checksum,
		Urgent:     tcp.Urgent,
		Options:    tcp.Options,
		Padding:    tcp.Padding,
	}
	return &t, nil

}

func rewritePacketLayers(eth *layers.Ethernet, ip *layers.IPv4, tcp *layers.TCP, iface *net.Interface) {
	// If the Source is the remote, rewrite destination to server.
	if net.IP.Equal(ip.SrcIP, remoteIP) && tcp.SrcPort == remotePort {
		// Get destination hardware address.
		hwAddr := arpLookup(gatewayIP)
		if hwAddr == nil {
			panic("EMPTY MAC FROM ARP")
		}
		// Set destination.
		eth.DstMAC = hwAddr
		ip.DstIP = serverIP
		tcp.DstPort = serverPort

		// Set source.
		eth.SrcMAC = iface.HardwareAddr
		ip.SrcIP = proxyIP
		tcp.SrcPort = proxyPort
		return
	}
	// If the source port is the server, rewrite the destination to the remote.
	if net.IP.Equal(ip.SrcIP, serverIP) && tcp.SrcPort == serverPort {
		// Get destination hardware address.
		hwAddr := arpLookup(gatewayIP)
		if hwAddr == nil {
			panic("EMPTY MAC FROM ARP")
		}

		// Set destination.
		eth.DstMAC = hwAddr
		ip.DstIP = remoteIP
		tcp.DstPort = remotePort

		// Set source.
		eth.SrcMAC = iface.HardwareAddr
		ip.SrcIP = proxyIP
		tcp.SrcPort = proxyPort
	}

}

func shouldProcess(ip *layers.IPv4, tcp *layers.TCP) bool {
	// If the Source is the remote, and destination is proxy.
	if net.IP.Equal(ip.SrcIP, remoteIP) && tcp.SrcPort == remotePort && net.IP.Equal(ip.DstIP, proxyIP) && tcp.DstPort == proxyPort {
		return true
	}

	// If the Source is the server, and destination is proxy.
	if net.IP.Equal(ip.SrcIP, serverIP) && tcp.SrcPort == serverPort && net.IP.Equal(ip.DstIP, proxyIP) && tcp.DstPort == proxyPort {
		return true
	}

	fmt.Println("Skipping packet")
	fmt.Println()
	fmt.Println()
	return false
}

func arpLookup(ip net.IP) net.HardwareAddr {
	data, err := exec.Command("arp", "-l", ip.String()).Output()
	if err != nil {
		panic(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		fmt.Println("FIELD 3: ", fields[3])
		fmt.Println("Padded Mac: ", padMAC(fields[3]))
		hw, err := net.ParseMAC(padMAC(fields[3]))
		if err != nil {
			panic(err)
		}
		return hw
	}
	return nil
}

func padMAC(mac string) string {
	newMacSlice := []string{}
	pieces := strings.Split(mac, ":")
	for _, piece := range pieces {
		if len(piece) < 2 {
			piece = "0" + piece
		}

		newMacSlice = append(newMacSlice, piece)
	}

	return strings.Join(newMacSlice, ":")
}

func printPacketData(eth *layers.Ethernet, ip *layers.IPv4, tcp *layers.TCP) {
	fmt.Println("New packet details:")
	fmt.Println()
	fmt.Println("Source MAC: ", eth.SrcMAC)
	fmt.Println("Destination MAC: ", eth.DstMAC)
	fmt.Println("Ethernet type: ", eth.EthernetType)
	fmt.Println()
	fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
	fmt.Println("Protocol: ", ip.Protocol)
	fmt.Println()
	fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
	fmt.Println("Sequence number: ", tcp.Seq)
	fmt.Println()

}
