package windows

import (
	"bytes"
	"net"
	"time"
)

type SMBService struct {
	timeout time.Duration
}

func NewSMBService(timeout time.Duration) *SMBService {
	return &SMBService{timeout: timeout}
}

func (s *SMBService) Probe(host string, port uint16) (string, string) {
	conn, err := net.DialTimeout("tcp", formatAddress(host, port), s.timeout)
	if err != nil {
		return "", ""
	}
	defer conn.Close()

	var probe []byte
	var serviceName string

	switch port {
	case 445:
		probe = buildSMBProbe()
		serviceName = "SMB"
	case 139:
		probe = buildNetBIOSProbe()
		serviceName = "NetBIOS"
	default:
		return "", ""
	}

	conn.SetDeadline(time.Now().Add(s.timeout))
	if _, err := conn.Write(probe); err != nil {
		return serviceName, "Microsoft Windows " + serviceName
	}

	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil || n < 4 {
		return serviceName, "Microsoft Windows " + serviceName
	}

	if port == 445 {
		version := extractSMBVersion(response[:n])
		return "SMB", "Microsoft Windows " + version
	}
	return "NetBIOS", "Microsoft Windows NetBIOS-SSN"
}

func buildSMBProbe() []byte {
	return []byte{
		0x00, 0x00, 0x00, 0x85, // NetBIOS Session
		0xff, 0x53, 0x4d, 0x42, // SMB Header
		0x72,                   // Command: Negotiate
		0x00, 0x00, 0x00, 0x00, // Status
		0x18,       // Flags
		0x53, 0xc8, // Flags2
		0x00, 0x00, // Process ID High
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
		0x00, 0x00, // Reserved
		0x00, 0x00, // Tree ID
		0x00, 0x00, // Process ID
		0x00, 0x00, // User ID
		0x00, 0x00, // Multiplex ID
	}
}

func buildNetBIOSProbe() []byte {
	return []byte{
		0x81, 0x00, 0x00, 0x44, // Session Request
		0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x00,
	}
}

func extractSMBVersion(response []byte) string {
	if len(response) < 40 {
		return "SMB"
	}

	if bytes.HasPrefix(response[4:], []byte{0xfe, 0x53, 0x4d, 0x42}) {
		return "SMB2"
	}

	if bytes.HasPrefix(response[4:], []byte{0xff, 0x53, 0x4d, 0x42}) {
		return "SMB1"
	}

	return "SMB"
}
