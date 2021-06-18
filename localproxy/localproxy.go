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
)

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
