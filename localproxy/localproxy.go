package main

// Simple, single-threaded server using system calls instead of the net library.
//
// Omitted features from the go net package:
//
// - TLS
// - Most error checking
// - Only supports bodies that close, no persistent or chunked connections
// - Redirects
// - Deadlines and cancellation
// - Non-blocking sockets

import (
	"bufio"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"syscall"
)

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

func parseTCPData(c *netSocket) ([]byte, error) {
	b := bufio.NewReader(*c)

	rawData, _, err := b.ReadLine()
	if err != nil {
		return nil, err
	}

	return rawData, nil
}

func test() {
	ipFlag := flag.String("ip_addr", "127.0.0.1", "The IP address to use")
	portFlag := flag.Int("port", 9000, "The port to use.")
	flag.Parse()

	ip := net.ParseIP(*ipFlag)
	port := *portFlag
	socket, err := newNetSocket(ip, port)
	if err != nil {
		panic(err)
	}
	defer socket.Close()

	log.Print("===============")
	log.Print("Local Proxy Started!")
	log.Print("===============")
	log.Print()
	log.Printf("addr: http://%s:%d", ip, port)

	for {
		// Block until incoming connection
		rw, e := socket.Accept()
		log.Print()
		log.Print()
		log.Printf("Incoming connection")
		if e != nil {
			panic(e)
		}

		// Read request
		log.Print("Reading request")
		data, err := parseTCPData(rw)
		log.Print("request: ", string(data))
		if err != nil {
			panic(err)
		}

		// Write response
		log.Print("Writing response")
		io.WriteString(rw, "HTTP/1.1 200 OK\r\n"+
			"Content-Type: text/html; charset=utf-8\r\n"+
			"Content-Length: 20\r\n"+
			"\r\n"+
			"<h1>hello world</h1>")
		if err != nil {
			log.Print(err.Error())
			continue
		}

	}
}
