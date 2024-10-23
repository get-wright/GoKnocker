package windows

import (
	"bytes"
	"net"
	"time"
)

type RPCService struct {
	timeout time.Duration
}

func NewRPCService(timeout time.Duration) *RPCService {
	return &RPCService{timeout: timeout}
}

func (s *RPCService) Probe(host string, port uint16) (string, string) {
	conn, err := net.DialTimeout("tcp", formatAddress(host, port), s.timeout)
	if err != nil {
		return "", ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(s.timeout))

	probe := buildRPCProbe(port)
	if _, err := conn.Write(probe); err != nil {
		return "", ""
	}

	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return "", ""
	}

	switch port {
	case 135:
		return "MSRPC", "Microsoft Windows RPC"
	case 593:
		if bytes.Contains(response[:n], []byte("ncacn_http")) {
			return "MSRPC-HTTP", "Microsoft Windows RPC over HTTP 1.0"
		}
		return "MSRPC-HTTP", "Microsoft Windows RPC over HTTP"
	}

	return "", ""
}

func buildRPCProbe(port uint16) []byte {
	if port == 593 {
		return []byte("RPC_CONNECT\r\n")
	}

	// Standard DCE/RPC bind request
	return []byte{
		0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
		0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}
