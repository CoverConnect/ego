package dap

import (
	"log"
	"net"
)

type Server struct {
	listener net.Listener
}

func NewServer() *Server {

	tcpListen, err := tcpListen()
	if err != nil {
		log.Fatalf("can't listen tcp connect")
		return nil
	}

	return &Server{listener: tcpListen}
}

func tcpListen() (net.Listener, error) {
	return net.Listen("tcp", ":8888")
}
